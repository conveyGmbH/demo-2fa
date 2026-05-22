const express = require("express");
const { v4: uuidv4 } = require("uuid");
const databaseManager = require("../../config/database");
const {
  log, verifyCredentialsForEndpoint, getTwoFactorUser,
  formatProcedureResult, detectDeviceFromUserAgent,
} = require("../../services/totpService");
const authenticateSession = require("../../middleware/authenticateSession");

const router = express.Router();

router.post("/check-credentials", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, message: "Username and password required" });
    }
    log("INFO", `Checking credentials for user: ${username}`);
    const credentialsCheck = await verifyCredentialsForEndpoint(username, password);
    if (credentialsCheck.success) {
      log("INFO", `Credentials valid for user: ${username}`);
      return res.json({
        success: true, message: "Credentials valid",
        resultCode: credentialsCheck.resultCode,
        resultMessage: credentialsCheck.message,
        odataLocation: credentialsCheck.odataLocation,
        inactiveFlag: credentialsCheck.inactiveFlag,
      });
    } else {
      log("WARN", `Invalid credentials for user: ${username}`, {
        resultCode: credentialsCheck.resultCode,
        resultMessage: credentialsCheck.message,
      });
      return res.status(401).json({
        success: false,
        message: credentialsCheck.message || "Invalid credentials",
        resultCode: credentialsCheck.resultCode,
      });
    }
  } catch (error) {
    log("ERROR", "Credentials check error", { username: req.body.username, error: error.message });
    res.status(500).json({ success: false, message: "Internal server error", error: error.message });
  }
});

router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, message: "Username and password required" });
    }
    log("INFO", `Login attempt for user: ${username}`);
    const credentialsCheck = await verifyCredentialsForEndpoint(username, password);
    if (!credentialsCheck.success) {
      log("WARN", `Invalid credentials for user: ${username}`, { resultCode: credentialsCheck.resultCode, message: credentialsCheck.message });
      return res.status(401).json({
        success: false,
        message: credentialsCheck.message || "Invalid credentials",
        resultCode: credentialsCheck.resultCode,
      });
    }

    const userQuery = await databaseManager.query(
      "SELECT TwoFactorUserID, Disable2FA FROM appblddbo.TwoFactorUser WHERE LoginName = ?",
      [username]
    );
    const has2FARecord = userQuery.length > 0;

    if (has2FARecord) {
      const userIdInt = parseInt(userQuery[0].TwoFactorUserID);
      if (isNaN(userIdInt)) throw new Error(`Invalid TwoFactorUserID: ${userQuery[0].TwoFactorUserID}`);

      const deviceQuery = await databaseManager.query(
        "SELECT COUNT(*) as count FROM appblddbo.TwoFactorDevice WHERE Inactive IS NULL AND TwoFactorUserID = ?",
        [userIdInt]
      );
      const activeDeviceCount = deviceQuery[0].count;
      const is2FAEnabled = !userQuery[0].Disable2FA && activeDeviceCount > 0;

      if (!userQuery[0].Disable2FA && activeDeviceCount === 0) {
        log("INFO", `Auto-disabling 2FA for user ${username} - no active devices`, { username, userIdInt, activeDeviceCount });
        await databaseManager.query(
          "UPDATE appblddbo.TwoFactorUser SET Disable2FA = 1 WHERE TwoFactorUserID = ?",
          [userIdInt]
        );
      }

      log("INFO", `User 2FA status - HasRecord: ${has2FARecord}, Enabled: ${is2FAEnabled}, ActiveDevices: ${activeDeviceCount}`);

      if (is2FAEnabled) {
        const deviceInfo = detectDeviceFromUserAgent(req.get("User-Agent"), "Web Browser");
        const sessionToken = uuidv4();
        const sessionData = {
          username, userId: userIdInt, originalPassword: password,
          loginTime: new Date().toISOString(), requires2FA: true,
          ipAddress: req.ip, userAgent: req.get("User-Agent"),
          deviceInfo, deviceId: null, sessionType: "pending_2fa",
        };
        await databaseManager.query(
          "INSERT INTO appblddbo.TwoFactorSession (SessionToken, UserLogin, LastUsedTS, SessionInfo) VALUES (?,?,CURRENT_TIMESTAMP,?)",
          [sessionToken, username, JSON.stringify(sessionData)]
        );
        return res.json({
          success: true, message: "User has 2FA enabled - verification required",
          sessionToken,
          user: { username, id: userIdInt, requires2FA: true },
          nextStep: "verify_2fa",
          d: {
            ODataLocation: credentialsCheck.odataLocation || "odata_online",
            requires2FA: true, HasTwoFactor: true,
            sessionToken, SessionToken: sessionToken,
            InactiveFlag: credentialsCheck.inactiveFlag || false,
          },
        });
      } else {
        log("INFO", `User has 2FA disabled or no active devices: ${username}`);
        const sessionToken = uuidv4();
        const sessionData = {
          username, userId: userIdInt, originalPassword: password,
          loginTime: new Date().toISOString(), requires2FA: false,
          ipAddress: req.ip, userAgent: req.get("User-Agent"),
          deviceInfo: detectDeviceFromUserAgent(req.get("User-Agent"), "Web Browser"),
          deviceId: null, sessionType: "authenticated", authenticated2FA: true,
        };
        await databaseManager.query(
          "INSERT INTO appblddbo.TwoFactorSession (SessionToken, UserLogin, LastUsedTS, SessionInfo) VALUES (?,?,CURRENT_TIMESTAMP,?)",
          [sessionToken, username, JSON.stringify(sessionData)]
        );
        return res.json({
          success: true, message: "User has 2FA disabled - use standard login",
          sessionToken,
          d: {
            ODataLocation: credentialsCheck.odataLocation || "odata_online",
            requires2FA: false, HasTwoFactor: false,
            InactiveFlag: credentialsCheck.inactiveFlag || false, sessionToken,
          },
        });
      }
    } else {
      log("INFO", `User not in 2FA system: ${username}`);
      const sessionToken = uuidv4();
      const sessionData = {
        username, originalPassword: password,
        loginTime: new Date().toISOString(), requires2FA: false,
        ipAddress: req.ip, userAgent: req.get("User-Agent"),
        deviceInfo: detectDeviceFromUserAgent(req.get("User-Agent"), "Web Browser"),
        deviceId: null, sessionType: "authenticated", authenticated2FA: true,
      };
      await databaseManager.query(
        "INSERT INTO appblddbo.TwoFactorSession (SessionToken, UserLogin, LastUsedTS, SessionInfo) VALUES (?,?,CURRENT_TIMESTAMP,?)",
        [sessionToken, username, JSON.stringify(sessionData)]
      );
      return res.json({
        success: true, message: "Login successful - 2FA not configured",
        sessionToken,
        d: {
          ODataLocation: credentialsCheck.odataLocation || "odata_online",
          requires2FA: false, HasTwoFactor: false,
          InactiveFlag: credentialsCheck.inactiveFlag || false,
        },
      });
    }
  } catch (error) {
    log("ERROR", "Login error", { username: req.body.username, error: error.message });
    res.status(500).json({ success: false, message: "Internal server error", error: error.message });
  }
});

router.post("/status", authenticateSession, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username) {
      return res.status(400).json({ success: false, message: "Username required" });
    }
    if (password) {
      const credentialsCheck = await verifyCredentialsForEndpoint(username, password, 0);
      if (!credentialsCheck.success) {
        return res.status(401).json({ success: false, message: credentialsCheck.message, resultCode: credentialsCheck.resultCode });
      }
    }

    const userQuery = await databaseManager.query(
      "SELECT * FROM appblddbo.TwoFactorUser WHERE LoginName = ?", [username]
    );
    if (userQuery.length === 0) {
      return res.json({ success: true, message: "User status retrieved", username, exists: false, is2FAEnabled: false });
    }

    const user = userQuery[0];
    const userIdInt = parseInt(user.TwoFactorUserID);
    if (isNaN(userIdInt)) throw new Error(`Invalid TwoFactorUserID: ${user.TwoFactorUserID}`);

    const deviceQuery = await databaseManager.query(
      "SELECT COUNT(*) as count FROM appblddbo.TwoFactorDevice WHERE Inactive IS NULL AND TwoFactorUserID = ?", [userIdInt]
    );
    const sessionQuery = await databaseManager.query(
      "SELECT COUNT(*) as count FROM appblddbo.TwoFactorSession WHERE UserLogin = ?", [username]
    );

    const activeDeviceCount = deviceQuery[0].count;
    const is2FAEnabled = !user.Disable2FA && activeDeviceCount > 0;

    if (!user.Disable2FA && activeDeviceCount === 0) {
      log("INFO", `Auto-disabling 2FA for user ${username} - no active devices`, { username, userIdInt, activeDeviceCount });
      await databaseManager.query(
        "UPDATE appblddbo.TwoFactorUser SET Disable2FA = 1 WHERE TwoFactorUserID = ?", [userIdInt]
      );
    }

    res.json({
      success: true, message: "User status retrieved", username,
      exists: true, id: userIdInt, is2FAEnabled,
      totalDevices: activeDeviceCount, activeDevices: activeDeviceCount,
      activeSessions: sessionQuery[0].count,
      hasDBPassword: !!user.DBPassword, credentialsValid: true,
    });
  } catch (error) {
    log("ERROR", "Status check error", { username: req.body.username, error: error.message });
    res.status(500).json({ success: false, message: "Internal server error", error: error.message });
  }
});

router.post("/disable-2fa", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, message: "Username and password required" });
    }

    const credentialsCheck = await verifyCredentialsForEndpoint(username, password, false);
    if (!credentialsCheck.success) {
      return res.status(401).json({
        success: false, message: "Access denied - valid 2FA session required",
        resultCode: credentialsCheck.resultCode,
      });
    }

    const userQuery = await databaseManager.query(
      "SELECT TwoFactorUserID, Disable2FA FROM appblddbo.TwoFactorUser WHERE LoginName = ?", [username]
    );
    if (userQuery.length === 0 || userQuery[0].Disable2FA === 1) {
      return res.json({ success: true, message: "2FA already disabled or not configured", originalPassword: password, note: "No changes needed" });
    }

    const activeDevices = await databaseManager.query(
      `SELECT d.TwoFactorDeviceID FROM appblddbo.TwoFactorDevice d
       JOIN appblddbo.TwoFactorUser u ON d.TwoFactorUserID = u.TwoFactorUserID
       WHERE u.LoginName = ? AND d.Inactive IS NULL ORDER BY d.TwoFactorDeviceID ASC`,
      [username]
    );
    if (activeDevices.length === 0) {
      return res.status(404).json({ success: false, message: "No active devices found - 2FA may already be disabled" });
    }

    const firstDeviceId = activeDevices[0].TwoFactorDeviceID;
    log("INFO", `Disabling 2FA using PRC_Disable2FADevice for user: ${username}`);

    const procedureResult = await databaseManager.query(
      "SELECT * FROM appblddbo.PRC_Disable2FADevice(?, ?, ?, ?)",
      [firstDeviceId, password, username, 1]
    );
    const result = formatProcedureResult(procedureResult, "PRC_Disable2FADevice");
    if (!result.success) {
      return res.status(400).json({ success: false, message: result.message, error: "PRC_Disable2FADevice failed" });
    }

    const originalPassword = result.data.DBPassword || password;
    await databaseManager.query("DELETE FROM appblddbo.TwoFactorSession WHERE UserLogin = ?", [username]);
    log("INFO", `2FA disabled successfully: ${username}`);

    res.json({
      success: true, message: "2FA disabled successfully",
      user: { username, is2FAEnabled: false },
      originalPassword, procedureResult: result.message,
      note: "2FA disabled - use original password for future logins",
    });
  } catch (error) {
    log("ERROR", "Error disabling 2FA", { username: req.body.username, error: error.message });
    res.status(500).json({ success: false, message: "Internal server error", error: error.message });
  }
});

router.post("/get-current-password", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, message: "Username and password required" });
    }
    const credentialsCheck = await verifyCredentialsForEndpoint(username, password);
    if (credentialsCheck.success) {
      return res.json({
        success: true, currentPassword: password,
        message: "Current password retrieved", resultCode: credentialsCheck.resultCode,
      });
    } else {
      return res.status(401).json({ success: false, message: credentialsCheck.message, resultCode: credentialsCheck.resultCode });
    }
  } catch (error) {
    log("ERROR", "Get current password error", { error: error.message });
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

module.exports = router;
