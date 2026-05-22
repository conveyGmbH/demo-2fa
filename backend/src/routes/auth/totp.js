const express = require("express");
const { v4: uuidv4 } = require("uuid");
const databaseManager = require("../../config/database");
const {
  log, verifyCredentialsForEndpoint, getTwoFactorUser,
  addTwoFactorDevice, formatProcedureResult, detectDeviceFromUserAgent,
  totpService,
} = require("../../services/totpService");

const router = express.Router();

router.post("/setup-2fa", async (req, res) => {
  try {
    const { username, password, deviceInfo = "Web Browser" } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, message: "Username and password required" });
    }

    await databaseManager.query("BEGIN TRANSACTION");
    try {
      const userCheck = await databaseManager.query(
        "SELECT TwoFactorUserID, Disable2FA FROM appblddbo.TwoFactorUser WHERE LoginName = ?", [username]
      );
      const has2FAActive = userCheck.length > 0 && !userCheck[0].Disable2FA;
      const credentialsCheck = await verifyCredentialsForEndpoint(username, password, has2FAActive);
      if (!credentialsCheck.success) {
        await databaseManager.query("ROLLBACK TRANSACTION");
        return res.status(401).json({
          success: false,
          message: has2FAActive ? "Access denied - valid 2FA session required" : credentialsCheck.message,
          resultCode: credentialsCheck.resultCode,
          requiresStrictAuth: has2FAActive,
        });
      }

      let user = await getTwoFactorUser(username);
      if (!user) {
        await databaseManager.query(
          `INSERT INTO appblddbo.TwoFactorUser (LoginName, LoginPassword, DBPassword, ValidUntilUTC, TokenLifetime, Disable2FA)
          VALUES (?, appblddbo.FCT_HashPassword(?), NULL, NULL, NULL, NULL)`,
          [username, password]
        );
        user = await getTwoFactorUser(username);
        if (!user) {
          await databaseManager.query("ROLLBACK TRANSACTION");
          return res.status(500).json({ success: false, message: "Failed to create 2FA user record" });
        }
        log("INFO", `TwoFactorUser created for first setup`, { username, twoFactorUserID: user.TwoFactorUserID });
      }

      await databaseManager.query("COMMIT TRANSACTION");
    } catch (innerError) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      throw innerError;
    }

    const totpData = await totpService.generateTOTP(username);
    const enhancedDeviceInfo = detectDeviceFromUserAgent(req.get("User-Agent"), deviceInfo);
    const sessionToken = uuidv4();

    totpService.storePendingSetup(sessionToken, {
      username, password, deviceInfo: enhancedDeviceInfo,
      totpSecret: totpData.secret, ipAddress: req.ip, userAgent: req.get("User-Agent"),
    });

    log("INFO", `2FA setup initiated with credential verification`, { username, deviceInfo: enhancedDeviceInfo });

    res.status(200).json({
      success: true, message: "2FA setup initiated - scan QR code and verify",
      sessionToken,
      totpSetup: {
        secret: totpData.secret,
        qrCodeDataURL: totpData.qrCode,
        manualEntryKey: totpData.manualEntryKey,
        qrCodeData: totpData.uri,
      },
      instructions: [
        "1. Open your authenticator app (Google Authenticator, Microsoft Authenticator, etc.)",
        "2. Scan the QR code or enter the secret manually",
        "3. Enter the 6-digit code below to verify",
        "4. Device will be added to your account only after successful verification",
      ],
      note: "No database changes made yet - verification required",
    });
  } catch (error) {
    if (databaseManager.isConnected()) {
      try { await databaseManager.query("ROLLBACK TRANSACTION"); } catch {}
    }
    log("ERROR", "2FA setup error", { username: req.body.username, error: error.message });
    res.status(500).json({ success: false, message: "Internal server error", error: error.message });
  }
});

router.post("/verify-2fa", async (req, res) => {
  try {
    const { sessionToken, totpCode, username } = req.body;
    if (!totpCode) {
      return res.status(400).json({ success: false, message: "TOTP code required" });
    }
    if (!username) {
      return res.status(400).json({ success: false, message: "Username required for verification" });
    }

    const pendingSetup = sessionToken ? totpService.getPendingSetup(sessionToken) : null;

    if (pendingSetup) {
      log("INFO", "Processing 2FA setup verification", { username: pendingSetup.username });

      const { deviceName } = req.body;
      if (deviceName) {
        const trimmedDeviceName = deviceName.trim();
        if (trimmedDeviceName.length < 3 || trimmedDeviceName.length > 50) {
          return res.status(400).json({ success: false, message: "Device name must be between 3 and 50 characters" });
        }
        pendingSetup.deviceInfo = trimmedDeviceName;
      }

      const verification = await totpService.verifyTOTPWithSecret(pendingSetup.totpSecret, totpCode);
      if (!verification.success) {
        return res.status(401).json({ success: false, message: verification.error || "Invalid TOTP code" });
      }

      await databaseManager.query("BEGIN TRANSACTION");
      try {
        let user = await getTwoFactorUser(pendingSetup.username);
        if (!user) {
          await databaseManager.query(
            `INSERT INTO appblddbo.TwoFactorUser (LoginName, LoginPassword, DBPassword, ValidUntilUTC, TokenLifetime, Disable2FA)
            VALUES (?, appblddbo.FCT_HashPassword(?), NULL, NULL, NULL, NULL)`,
            [pendingSetup.username, pendingSetup.password]
          );
          user = await getTwoFactorUser(pendingSetup.username);
          if (!user) {
            await databaseManager.query("ROLLBACK TRANSACTION");
            return res.status(500).json({ success: false, message: "Failed to create 2FA user record during verification" });
          }
        }

        const userIdInt = parseInt(user.TwoFactorUserID);
        if (isNaN(userIdInt)) throw new Error(`Invalid TwoFactorUserID: ${user.TwoFactorUserID}`);

        const existingDevices = await databaseManager.query(
          "SELECT COUNT(*) as count FROM appblddbo.TwoFactorDevice WHERE Inactive IS NULL AND TwoFactorUserID = ?", [userIdInt]
        );
        const isFirstSetup = existingDevices[0].count === 0;

        if (isFirstSetup) {
          await databaseManager.query("DELETE FROM appblddbo.TwoFactorDevice WHERE TwoFactorUserID = ?", [userIdInt]);
        }

        const deviceId = await addTwoFactorDevice(userIdInt, pendingSetup.deviceInfo, pendingSetup.totpSecret);

        log("INFO", `Calling PRC_ActivateTwoFactor for user: ${pendingSetup.username}`);
        const activationResult = await databaseManager.query(
          "SELECT * FROM appblddbo.PRC_ActivateTwoFactor(?)", [pendingSetup.username]
        );
        const result = formatProcedureResult(activationResult, "PRC_ActivateTwoFactor");
        if (!result.success) {
          await databaseManager.query("ROLLBACK TRANSACTION");
          return res.status(400).json({ success: false, message: result.message, error: "PRC_ActivateTwoFactor failed" });
        }

        const dbPassword = result.data.DBPassword;
        const newSessionToken = uuidv4();
        const sessionData = {
          username: pendingSetup.username, userId: userIdInt,
          loginTime: new Date().toISOString(), requires2FA: true, authenticated2FA: true,
          ipAddress: pendingSetup.ipAddress, userAgent: pendingSetup.userAgent,
          deviceInfo: pendingSetup.deviceInfo, deviceId,
        };
        await databaseManager.query(
          "INSERT INTO appblddbo.TwoFactorSession (SessionToken, UserLogin, LastUsedTS, SessionInfo) VALUES (?,?,CURRENT_TIMESTAMP,?)",
          [newSessionToken, pendingSetup.username, JSON.stringify(sessionData)]
        );

        await databaseManager.query("COMMIT TRANSACTION");
        totpService.removePendingSetup(sessionToken);

        log("INFO", `2FA setup completed using ONLY PRC_ActivateTwoFactor`, {
          username: pendingSetup.username, deviceId, isFirstSetup, dbPasswordGenerated: !!dbPassword,
        });

        return res.json({
          success: true, message: "2FA setup completed successfully",
          sessionToken: newSessionToken,
          user: { username: pendingSetup.username, id: userIdInt },
          isFirstSetup, dbPassword,
          note: "Using DBPassword for future API calls",
        });
      } catch (error) {
        await databaseManager.query("ROLLBACK TRANSACTION");
        log("ERROR", "Error during 2FA setup", { username: pendingSetup.username, error: error.message });
        throw error;
      }

    } else {
      // EXISTING 2FA VERIFICATION FOR LOGIN
      log("INFO", "Processing existing 2FA verification for login");

      let sessionTokenToUse = sessionToken;
      if (!sessionTokenToUse && username) {
        const latestSession = await databaseManager.query(
          "SELECT FIRST * FROM appblddbo.TwoFactorSession WHERE UserLogin = ? ORDER BY LastUsedTS DESC", [username]
        );
        if (latestSession.length === 0) {
          return res.status(401).json({ success: false, message: "No active session found for user" });
        }
        sessionTokenToUse = latestSession[0].SessionToken;
        log("INFO", "Found latest session", { sessionToken: sessionTokenToUse.substring(0, 8) + "...", username });
      }

      const sessionQuery = await databaseManager.query(
        "SELECT * FROM appblddbo.TwoFactorSession WHERE SessionToken = ?", [sessionTokenToUse]
      );
      if (sessionQuery.length === 0) {
        return res.status(401).json({ success: false, message: "Invalid or expired session" });
      }

      const sessionData = JSON.parse(sessionQuery[0].SessionInfo);
      const { username: sessionUsername, userId } = sessionData;
      const userIdInt = userId ? parseInt(userId) : null;
      if (!userIdInt) {
        return res.status(400).json({ success: false, message: "Invalid session data" });
      }

      const verificationResult = await totpService.verifyTOTP(userIdInt, totpCode);
      if (!verificationResult.success) {
        return res.status(401).json({ success: false, message: "Invalid TOTP code" });
      }

      const updatedSessionData = {
        ...sessionData,
        authenticated2FA: true,
        authenticationTime: new Date().toISOString(),
        deviceId: verificationResult.deviceId,
        verifiedDeviceInfo: verificationResult.deviceInfo,
      };
      await databaseManager.query(
        "UPDATE appblddbo.TwoFactorSession SET LastUsedTS = CURRENT_TIMESTAMP, SessionInfo = ? WHERE SessionToken = ?",
        [JSON.stringify(updatedSessionData), sessionTokenToUse]
      );

      log("INFO", `Calling PRC_ActivateTwoFactor for user: ${sessionUsername}`);
      const activationResult = await databaseManager.query(
        "SELECT * FROM appblddbo.PRC_ActivateTwoFactor(?)", [sessionUsername]
      );
      const result = formatProcedureResult(activationResult, "PRC_ActivateTwoFactor");
      if (!result.success) {
        return res.status(400).json({ success: false, message: result.message, error: "PRC_ActivateTwoFactor failed" });
      }

      return res.json({
        success: true, message: "2FA verification successful",
        sessionToken: sessionTokenToUse,
        user: { username: sessionUsername, id: userIdInt },
        dbPassword: result.data.DBPassword,
      });
    }
  } catch (error) {
    if (databaseManager.isConnected()) {
      await databaseManager.query("ROLLBACK TRANSACTION");
    }
    log("ERROR", "2FA verification error", { error: error.message });
    res.status(500).json({ success: false, message: "Internal server error", error: error.message });
  }
});

module.exports = router;
