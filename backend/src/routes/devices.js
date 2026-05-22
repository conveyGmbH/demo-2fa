const express = require("express");
const databaseManager = require("../config/database");
const {
  log, verifyCredentialsForEndpoint, addTwoFactorDevice,
  formatProcedureResult, maskSensitiveData, detectDeviceFromUserAgent,
  updateSessionsDeviceInfo, cleanupSessionsForDevice,
  totpService,
} = require("../services/totpService");
const authenticateSession = require("../middleware/authenticateSession");

const router = express.Router();

router.post("/list", authenticateSession, async (req, res) => {
  try {
    const username = req.body.username || req.user?.username;
    if (!username) {
      return res.status(400).json({ success: false, message: "Username required" });
    }

    const { password } = req.body;
    if (password) {
      const credentialsCheck = await verifyCredentialsForEndpoint(username, password, false);
      if (!credentialsCheck.success) {
        return res.status(401).json({ success: false, message: credentialsCheck.message, resultCode: credentialsCheck.resultCode });
      }
    }

    const userQuery = await databaseManager.query(
      "SELECT TwoFactorUserID, Disable2FA FROM appblddbo.TwoFactorUser WHERE LoginName = ?", [username]
    );
    if (userQuery.length === 0) {
      return res.json({ success: true, message: "Devices retrieved", username, deviceCount: 0, activeDevices: 0, devices: [], twoFactorStatus: "never_activated" });
    }

    const user = userQuery[0];
    const userIdInt = parseInt(user.TwoFactorUserID);
    if (isNaN(userIdInt)) throw new Error(`Invalid TwoFactorUserID: ${user.TwoFactorUserID}`);

    if (user.Disable2FA === 1) {
      return res.json({ success: true, message: "Devices retrieved", username, deviceCount: 0, activeDevices: 0, devices: [], twoFactorStatus: "disabled" });
    }

    const devices = await databaseManager.query(
      "SELECT * FROM appblddbo.TwoFactorDevice WHERE TwoFactorUserID = ? AND Inactive IS NULL", [userIdInt]
    );
    const deviceList = devices.map((device) => ({
      deviceId: device.TwoFactorDeviceID,
      authMethod: device.AuthMethod,
      deviceInfo: device.DeviceInfo,
      isActive: !device.Inactive,
      secretData: device.SecretData ? maskSensitiveData(device.SecretData) : null,
    }));

    res.json({
      success: true, message: "Devices retrieved", username,
      deviceCount: deviceList.length,
      activeDevices: deviceList.filter((d) => d.isActive).length,
      devices: deviceList,
      twoFactorStatus: deviceList.length > 0 ? "enabled" : "enabled_no_devices",
    });
  } catch (error) {
    log("ERROR", "List devices error", { username: req.body.username, error: error.message });
    res.status(500).json({ success: false, message: "Internal server error", error: error.message });
  }
});

router.post("/add", async (req, res) => {
  try {
    const { username, password, deviceInfo = "New Device" } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, message: "Username and password required" });
    }

    const userCheck = await databaseManager.query(
      "SELECT TwoFactorUserID, Disable2FA FROM appblddbo.TwoFactorUser WHERE LoginName = ?", [username]
    );
    const has2FAActive = userCheck.length > 0 && !userCheck[0].Disable2FA;
    const credentialsCheck = await verifyCredentialsForEndpoint(username, password, has2FAActive);
    if (!credentialsCheck.success) {
      return res.status(401).json({
        success: false,
        message: has2FAActive ? "Access denied - valid 2FA session required" : credentialsCheck.message,
        resultCode: credentialsCheck.resultCode,
        requiresStrictAuth: has2FAActive,
      });
    }

    await databaseManager.query("BEGIN TRANSACTION");

    const userQuery = await databaseManager.query(
      "SELECT * FROM appblddbo.TwoFactorUser WHERE LoginName = ?", [username]
    );
    if (userQuery.length === 0) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      return res.status(404).json({ success: false, message: "User not found in 2FA system" });
    }

    const user = userQuery[0];
    const userIdInt = parseInt(user.TwoFactorUserID);
    if (isNaN(userIdInt)) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      throw new Error(`Invalid TwoFactorUserID: ${user.TwoFactorUserID}`);
    }

    const enhancedDeviceInfo = detectDeviceFromUserAgent(req.get("User-Agent"), deviceInfo);

    const existingDevices = await databaseManager.query(
      "SELECT * FROM appblddbo.TwoFactorDevice WHERE Inactive IS NULL AND TwoFactorUserID = ? AND DeviceInfo = ?",
      [userIdInt, enhancedDeviceInfo]
    );
    if (existingDevices.length > 0) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      return res.status(409).json({
        success: false,
        message: `A device with name "${enhancedDeviceInfo}" already exists`,
        suggestion: "Try using a different device name or remove the existing device first",
      });
    }

    const totpData = await totpService.generateTOTP(username);
    const deviceId = await addTwoFactorDevice(userIdInt, enhancedDeviceInfo, totpData.secret);
    await databaseManager.query("COMMIT TRANSACTION");

    log("INFO", `New device added with credentials verification`, { username, deviceInfo: enhancedDeviceInfo, deviceId });

    res.status(201).json({
      success: true, message: "Device added successfully",
      device: { deviceId, deviceInfo: enhancedDeviceInfo, authMethod: "TOTP" },
      totpSetup: { secret: totpData.secret, qrCodeDataURL: totpData.qrCode, manualEntryKey: totpData.manualEntryKey },
    });
  } catch (error) {
    await databaseManager.query("ROLLBACK TRANSACTION");
    log("ERROR", "Add device error", { username: req.body.username, error: error.message });
    res.status(500).json({ success: false, message: "Internal server error", error: error.message });
  }
});

router.post("/rename", async (req, res) => {
  try {
    const { deviceId, username, password, newDeviceName } = req.body;
    const deviceIdInt = parseInt(deviceId);
    if (isNaN(deviceIdInt)) {
      return res.status(400).json({ success: false, message: "Invalid device ID - must be numeric" });
    }
    if (!username || !password || !newDeviceName) {
      return res.status(400).json({ success: false, message: "Username, password and new device name required" });
    }

    const userCheck = await databaseManager.query(
      "SELECT TwoFactorUserID, Disable2FA FROM appblddbo.TwoFactorUser WHERE LoginName = ?", [username]
    );
    const has2FAActive = userCheck.length > 0 && !userCheck[0].Disable2FA;
    const credentialsCheck = await verifyCredentialsForEndpoint(username, password, has2FAActive);
    if (!credentialsCheck.success) {
      return res.status(401).json({
        message: has2FAActive ? "Access denied - valid 2FA session required" : credentialsCheck.message,
        resultCode: credentialsCheck.resultCode,
        requiresStrictAuth: has2FAActive,
      });
    }

    if (newDeviceName.trim().length < 1 || newDeviceName.trim().length > 200) {
      return res.status(400).json({ success: false, message: "Device name must be between 1 and 200 characters" });
    }

    await databaseManager.query("BEGIN TRANSACTION");

    const deviceQuery = await databaseManager.query(
      `SELECT d.*, u.LoginName FROM appblddbo.TwoFactorDevice d
       JOIN appblddbo.TwoFactorUser u ON d.TwoFactorUserID = u.TwoFactorUserID
       WHERE d.TwoFactorDeviceID = ? AND u.LoginName = ? AND d.Inactive IS NULL`,
      [deviceIdInt, username]
    );
    if (deviceQuery.length === 0) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      return res.status(404).json({ success: false, message: "Device not found or not owned by user" });
    }

    const oldDeviceName = deviceQuery[0].DeviceInfo;
    await databaseManager.query(
      "UPDATE appblddbo.TwoFactorDevice SET DeviceInfo = ? WHERE TwoFactorDeviceID = ?",
      [newDeviceName.trim(), deviceIdInt]
    );
    const updatedSessions = await updateSessionsDeviceInfo(username, oldDeviceName, newDeviceName.trim());
    await databaseManager.query("COMMIT TRANSACTION");

    log("INFO", `Device renamed`, { deviceId: deviceIdInt, oldName: oldDeviceName, newName: newDeviceName.trim(), sessionsUpdated: updatedSessions });

    res.json({
      success: true, message: "Device renamed successfully",
      device: { deviceId: deviceIdInt, oldName: oldDeviceName, newName: newDeviceName.trim() },
      sessionsUpdated: updatedSessions,
    });
  } catch (error) {
    await databaseManager.query("ROLLBACK TRANSACTION");
    log("ERROR", "Rename device error", { deviceId: parseInt(req.body.deviceId), error: error.message });
    res.status(500).json({ success: false, message: "Internal server error", error: error.message });
  }
});

router.post("/remove", async (req, res) => {
  try {
    const { deviceId, username, password, confirmDelete = false } = req.body;
    const deviceIdInt = parseInt(deviceId);
    if (isNaN(deviceIdInt)) {
      return res.status(400).json({ success: false, message: "Invalid device ID - must be numeric" });
    }
    if (!username || !password) {
      return res.status(400).json({ success: false, message: "Username and password required" });
    }

    const credentialsCheck = await verifyCredentialsForEndpoint(username, password, false);
    if (!credentialsCheck.success) {
      return res.status(401).json({
        success: false, message: "Access denied - valid 2FA session required",
        resultCode: credentialsCheck.resultCode,
        note: "Device removal requires strict authentication",
      });
    }

    await databaseManager.query("BEGIN TRANSACTION");

    const deviceQuery = await databaseManager.query(
      `SELECT d.*, u.LoginName, u.TwoFactorUserID FROM appblddbo.TwoFactorDevice d
       JOIN appblddbo.TwoFactorUser u ON d.TwoFactorUserID = u.TwoFactorUserID
       WHERE d.Inactive IS NULL AND d.TwoFactorDeviceID = ? AND u.LoginName = ?`,
      [deviceIdInt, username]
    );
    if (deviceQuery.length === 0) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      return res.status(404).json({ success: false, message: "Device not found or not owned by user" });
    }

    const userIdInt = parseInt(deviceQuery[0].TwoFactorUserID);
    if (isNaN(userIdInt)) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      throw new Error(`Invalid TwoFactorUserID: ${deviceQuery[0].TwoFactorUserID}`);
    }

    const activeDeviceCount = await databaseManager.query(
      "SELECT COUNT(*) as count FROM appblddbo.TwoFactorDevice WHERE TwoFactorUserID = ? AND Inactive IS NULL",
      [userIdInt]
    );

    if (activeDeviceCount[0].count === 1) {
      if (!confirmDelete) {
        await databaseManager.query("ROLLBACK TRANSACTION");
        return res.status(400).json({
          success: false, message: "This is your last device. Removing it will disable 2FA.",
          requiresConfirmation: true, isLastDevice: true, deviceInfo: deviceQuery[0].DeviceInfo,
        });
      }

      try {
        log("INFO", `Calling PRC_Disable2FADevice for last device: ${deviceIdInt}`);
        const procedureResult = await databaseManager.query(
          "SELECT * FROM appblddbo.PRC_Disable2FADevice(?, ?, ?, ?)",
          [deviceIdInt, password, username, 1]
        );
        const result = formatProcedureResult(procedureResult, "PRC_Disable2FADevice");

        if (result.success) {
          const originalPassword = result.data.DBPassword;
          log("INFO", `PRC_Disable2FADevice returned original password`, {
            username, deviceId: deviceIdInt,
            passwordLength: originalPassword?.length || 0,
            passwordStart: originalPassword?.substring(0, 4) + "***" || "NULL",
          });

          await databaseManager.query("DELETE FROM appblddbo.TwoFactorSession WHERE UserLogin = ?", [username]);
          await databaseManager.query("COMMIT TRANSACTION");

          log("INFO", `Last device removed and 2FA disabled using PRC_Disable2FADevice: ${username}`);
          return res.json({
            success: true, message: "Last device removed and 2FA disabled successfully",
            device: { deviceId: deviceIdInt, deviceInfo: deviceQuery[0].DeviceInfo },
            twoFactorDisabled: true, originalPassword, currentPassword: originalPassword,
            data: { DBPassword: originalPassword, originalPassword },
            procedureResult: result.message, note: "2FA completely disabled - use original password",
          });
        } else {
          await databaseManager.query("ROLLBACK TRANSACTION");
          return res.status(400).json({ success: false, message: result.message, error: "PRC_Disable2FADevice execution failed" });
        }
      } catch (error) {
        await databaseManager.query("ROLLBACK TRANSACTION");
        log("ERROR", "PRC_Disable2FADevice error", { deviceId: deviceIdInt, error: error.message });
        return res.status(500).json({ success: false, message: "Failed to disable 2FA device", error: error.message });
      }
    } else {
      await databaseManager.query(
        "UPDATE appblddbo.TwoFactorDevice SET Inactive = 1 WHERE TwoFactorDeviceID = ?", [deviceIdInt]
      );
      const cleanedSessions = await cleanupSessionsForDevice(username, deviceIdInt);
      await databaseManager.query("COMMIT TRANSACTION");

      log("INFO", `Device removed (marked inactive): ${deviceIdInt}`);
      return res.json({
        success: true, message: "Device removed successfully",
        device: { deviceId: deviceIdInt, deviceInfo: deviceQuery[0].DeviceInfo },
        twoFactorDisabled: false, sessionsCleanedUp: cleanedSessions,
      });
    }
  } catch (error) {
    await databaseManager.query("ROLLBACK TRANSACTION");
    log("ERROR", "Remove device error", { deviceId: parseInt(req.body.deviceId), error: error.message });
    res.status(500).json({ success: false, message: "Internal server error", error: error.message });
  }
});

module.exports = router;
