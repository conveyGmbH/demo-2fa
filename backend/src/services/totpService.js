const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const databaseManager = require('../config/database');

const CONFIG = {
  totp: {
    issuer:       process.env.TOTP_ISSUER    || "convey LeadSuccess",
    serviceName:  process.env.TOTP_LABEL     || "LeadSuccess Portal",
    digits:       Number(process.env.TOTP_DIGITS)  || 6,
    step:         Number(process.env.TOTP_PERIOD)  || 30,
    window:       Number(process.env.TOTP_WINDOW)  || 2,
    algorithm:    process.env.TOTP_ALGORITHM || 'sha1',
    secretLength: Number(process.env.TOTP_SIZE)    || 32,
  },
  session: {
    replayProtectionTTL: 5 * 60 * 1000,
    cleanupInterval: 60000,
  },
  logging: {
    enabled: true,
    sensitive: false,
  },
};

function log(level, message, data = null) {
  if (!CONFIG.logging.enabled) return;
  const timestamp = new Date().toISOString();
  const prefix = { INFO: "", WARN: "⚠️", ERROR: "❌", DEBUG: "🔍" }[level] || "📝";
  const logMessage = `[${timestamp}] ${prefix} ${level}: ${message}`;
  if (data) {
    if (!CONFIG.logging.sensitive && data.password) data = { ...data, password: "***REDACTED***" };
    if (!CONFIG.logging.sensitive && data.secret)   data = { ...data, secret: maskSensitiveData(data.secret) };
    console.log(logMessage, JSON.stringify(data, null, 2));
  } else {
    console.log(logMessage);
  }
}

async function verifyCredentialsForEndpoint(username, password, strict = 0) {
  try {
    if (!username || !password) {
      return { success: false, message: "Username and password required for authentication", resultCode: 400 };
    }
    const result = await databaseManager.query(
      "SELECT ResultCode, ResultMessage, DBPassword, ODataLocation, InactiveFlag FROM appblddbo.PRC_CheckGlobalPassword(?,?,?)",
      [username, password, strict ? 1 : 0]
    );
    if (!result || result.length === 0) {
      return { success: false, message: "No result from database authentication", resultCode: 500 };
    }
    const authResult = result[0];
    if (Number(authResult.ResultCode) === 0 || Number(authResult.ResultCode) === 1330) {
      return {
        success: true, message: "Credentials valid",
        resultCode: authResult.ResultCode,
        odataLocation: authResult.ODataLocation,
        inactiveFlag: authResult.InactiveFlag
      };
    }
    return { success: false, message: authResult.ResultMessage || "Invalid credentials", resultCode: authResult.ResultCode };
  } catch (error) {
    log("ERROR", "Credentials verification failed", { username, error: error.message });
    return { success: false, message: "Authentication service error", resultCode: 401 };
  }
}

class TOTPService {
  constructor() {
    this.recentCodes = new Map();
    this.pendingSetups = new Map();
    this.cleanupInterval = setInterval(() => this.cleanupOldCodes(), CONFIG.session.cleanupInterval);
  }

  async generateTOTP(username) {
    try {
      const secret = speakeasy.generateSecret({
        name: `${CONFIG.totp.issuer}:${username}`,
        issuer: CONFIG.totp.issuer,
        length: CONFIG.totp.secretLength,
      });
      const qrCodeDataURL = await QRCode.toDataURL(secret.otpauth_url, {
        errorCorrectionLevel: "M", type: "image/png", quality: 0.92, margin: 1, width: 256,
        color: { dark: "#000000", light: "#FFFFFF" },
      });
      log("INFO", `TOTP generated for user: ${username}`);
      return { secret: secret.base32, qrCode: qrCodeDataURL, uri: secret.otpauth_url, manualEntryKey: secret.base32 };
    } catch (error) {
      log("ERROR", "Error generating TOTP", { error: error.message });
      throw error;
    }
  }

  storePendingSetup(sessionToken, setupData) {
    this.pendingSetups.set(sessionToken, { ...setupData, timestamp: Date.now() });
    log("INFO", "Pending setup stored", { sessionToken: sessionToken.substring(0, 8) + "..." });
  }

  getPendingSetup(sessionToken) {
    const setup = this.pendingSetups.get(sessionToken);
    if (setup) {
      log("INFO", "Pending setup retrieved", { sessionToken: sessionToken.substring(0, 8) + "..." });
      return setup;
    }
    return null;
  }

  removePendingSetup(sessionToken) {
    if (this.pendingSetups.delete(sessionToken)) {
      log("INFO", "Pending setup removed after successful verification", { sessionToken: sessionToken.substring(0, 8) + "..." });
      return true;
    }
    return false;
  }

  async verifyTOTPWithSecret(secret, token, userId = null) {
    try {
      if (!/^\d{6}$/.test(token)) return { success: false, error: "Invalid code format" };
      if (userId && this.recentCodes.has(`${userId}:${token}`)) return { success: false, error: "Code already used" };
      const verified = speakeasy.totp.verify({
        secret, encoding: "base32", token,
        window: CONFIG.totp.window, algorithm: CONFIG.totp.algorithm,
        digits: CONFIG.totp.digits, step: CONFIG.totp.step,
      });
      if (verified) {
        if (userId) this.recentCodes.set(`${userId}:${token}`, Date.now());
        return { success: true };
      }
      return { success: false, error: "Invalid code" };
    } catch (error) {
      log("ERROR", "Error verifying TOTP with secret", { userId, error: error.message });
      return { success: false, error: "Verification failed" };
    }
  }

  async verifyTOTP(userId, token) {
    try {
      const userIdInt = parseInt(userId);
      if (isNaN(userIdInt) || !/^\d{6}$/.test(token)) return { success: false, deviceId: null };
      const codeKey = `${userIdInt}:${token}`;
      if (this.recentCodes.has(codeKey)) return { success: false, deviceId: null };
      const devices = await databaseManager.query(
        "SELECT TwoFactorDeviceID, SecretData, DeviceInfo FROM appblddbo.TwoFactorDevice WHERE TwoFactorUserID = ? AND Inactive IS NULL",
        [userIdInt]
      );
      if (devices.length === 0) return { success: false, deviceId: null };
      for (const device of devices) {
        const verified = speakeasy.totp.verify({
          secret: device.SecretData, encoding: "base32", token,
          window: CONFIG.totp.window, algorithm: CONFIG.totp.algorithm,
          digits: CONFIG.totp.digits, step: CONFIG.totp.step,
        });
        if (verified) {
          this.recentCodes.set(codeKey, Date.now());
          return { success: true, deviceId: device.TwoFactorDeviceID, deviceInfo: device.DeviceInfo };
        }
      }
      return { success: false, deviceId: null };
    } catch (error) {
      log("ERROR", "Error verifying TOTP", { userId: parseInt(userId), error: error.message });
      return { success: false, deviceId: null };
    }
  }

  cleanupOldCodes() {
    const now = Date.now();
    for (const [key, ts] of this.recentCodes) {
      if (now - ts > CONFIG.session.replayProtectionTTL) this.recentCodes.delete(key);
    }
    for (const [token, setup] of this.pendingSetups) {
      if (now - setup.timestamp > 10 * 60 * 1000) this.pendingSetups.delete(token);
    }
  }
}

const totpService = new TOTPService();

async function getTwoFactorUser(username) {
  try {
    const rows = await databaseManager.query("SELECT * FROM appblddbo.TwoFactorUser WHERE LoginName = ?", [username]);
    if (rows.length > 0) { log("INFO", `Existing 2FA user found: ${username}`); return rows[0]; }
    log("INFO", `User not found in 2FA system: ${username}`);
    return null;
  } catch (error) {
    log("ERROR", "Error getting 2FA user", { username, error: error.message });
    throw error;
  }
}

async function addTwoFactorDevice(userId, deviceInfo, secret) {
  try {
    const userIdInt = parseInt(userId);
    if (isNaN(userIdInt)) throw new Error(`Invalid userId: ${userId} is not a number`);
    await databaseManager.query(
      "INSERT INTO appblddbo.TwoFactorDevice (TwoFactorUserID, AuthMethod, DeviceInfo, SecretData, Inactive) VALUES (?, ?, ?, ?, ?)",
      [userIdInt, "TOTP", deviceInfo, secret, null]
    );
    const deviceQuery = await databaseManager.query(
      "SELECT TwoFactorDeviceID FROM appblddbo.TwoFactorDevice WHERE TwoFactorUserID = ? AND SecretData = ?",
      [userIdInt, secret]
    );
    if (deviceQuery.length > 0) {
      log("INFO", `New device created with ID: ${deviceQuery[0].TwoFactorDeviceID}`, { deviceInfo, userId: userIdInt });
      return deviceQuery[0].TwoFactorDeviceID;
    }
    throw new Error("Device creation failed");
  } catch (error) {
    log("ERROR", "Error adding device", { userId: parseInt(userId), deviceInfo, error: error.message });
    throw error;
  }
}

function formatProcedureResult(result, procedureName) {
  if (!result || result.length === 0) return { success: false, message: `No result from ${procedureName}`, resultCode: -1 };
  const data = result[0];
  return { success: data.ResultCode === 0, resultCode: data.ResultCode, message: data.ResultMessage || "Unknown result", data };
}

function maskSensitiveData(data) {
  if (!data || data.length < 8) return "***MASKED***";
  return data.substring(0, 4) + "***" + data.substring(data.length - 4);
}

function detectDeviceFromUserAgent(userAgent, fallback = "Unknown Device") {
  if (!userAgent) return fallback;
  const ua = userAgent.toLowerCase();
  const browserVersionMatch = ua.match(/(chrome|firefox|safari|edge|opera)[\/\s]([\d.]+)/i);
  const osMatch = ua.match(/(windows nt|mac os x|linux|android|ios) ([^;)]+)/i);
  const browserName = ua.includes("chrome") ? "Chrome" : ua.includes("firefox") ? "Firefox"
    : ua.includes("safari") ? "Safari" : ua.includes("edge") ? "Edge" : "Browser";
  const osName = ua.includes("windows") ? "Windows" : ua.includes("mac") ? "macOS"
    : ua.includes("linux") ? "Linux" : ua.includes("android") ? "Android"
    : ua.includes("ios") ? "iOS" : "Unknown OS";
  const uniqueId = Math.random().toString(36).substring(2, 6).toUpperCase();
  return `${browserName} ${browserVersionMatch?.[2] || ""} on ${osName} ${osMatch?.[2] || ""} (${uniqueId})`;
}

async function updateSessionsDeviceInfo(username, oldDeviceInfo, newDeviceInfo) {
  try {
    const sessions = await databaseManager.query(
      "SELECT SessionToken, SessionInfo FROM appblddbo.TwoFactorSession WHERE UserLogin = ?", [username]
    );
    let updatedCount = 0;
    for (const session of sessions) {
      try {
        const sessionData = JSON.parse(session.SessionInfo);
        if (sessionData.deviceInfo === oldDeviceInfo) {
          sessionData.deviceInfo = newDeviceInfo;
          await databaseManager.query(
            "UPDATE appblddbo.TwoFactorSession SET SessionInfo = ? WHERE SessionToken = ?",
            [JSON.stringify(sessionData), session.SessionToken]
          );
          updatedCount++;
        }
      } catch (e) {
        log("WARN", `Could not parse session info for token: ${session.SessionToken.substring(0, 8)}...`);
      }
    }
    log("INFO", `Updated device info in ${updatedCount} sessions`, { username, oldDeviceInfo, newDeviceInfo });
    return updatedCount;
  } catch (error) {
    log("ERROR", "Error updating sessions device info", { username, error: error.message });
    throw error;
  }
}

async function cleanupSessionsForDevice(username, deviceId) {
  try {
    const deviceIdInt = parseInt(deviceId);
    if (isNaN(deviceIdInt)) return 0;
    const sessions = await databaseManager.query(
      "SELECT SessionToken, SessionInfo FROM appblddbo.TwoFactorSession WHERE UserLogin = ?", [username]
    );
    let cleanedCount = 0;
    for (const session of sessions) {
      try {
        const sessionData = JSON.parse(session.SessionInfo);
        if (parseInt(sessionData.deviceId) === deviceIdInt) {
          await databaseManager.query("DELETE FROM appblddbo.TwoFactorSession WHERE SessionToken = ?", [session.SessionToken]);
          cleanedCount++;
        }
      } catch (e) {
        log("WARN", `Could not parse session info for cleanup: ${session.SessionToken.substring(0, 8)}...`);
      }
    }
    log("INFO", `Cleaned ${cleanedCount} sessions for device ${deviceIdInt}`);
    return cleanedCount;
  } catch (error) {
    log("ERROR", "Error cleaning sessions for device", { username, deviceId: parseInt(deviceId), error: error.message });
    throw error;
  }
}

module.exports = {
  CONFIG, log, verifyCredentialsForEndpoint, totpService,
  getTwoFactorUser, addTwoFactorDevice, formatProcedureResult,
  maskSensitiveData, detectDeviceFromUserAgent,
  updateSessionsDeviceInfo, cleanupSessionsForDevice,
};
