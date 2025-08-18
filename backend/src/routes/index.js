const express = require("express");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const { v4: uuidv4 } = require("uuid");
const databaseManager = require("../config/database");

// Load environment variables from .env file
//require('dotenv').config();

const router = express.Router();

// CONFIGURATION
const CONFIG = {
  totp: {
    issuer: (process.env.TOTP_ISSUER ? process.env.TOTP_ISSUER : "convey LeadSuccess"),
    serviceName: (process.env.TOTP_LABEL ? process.env.TOTP_LABEL : "LeadSuccess Portal"),
    digits: Number(process.env.TOTP_DIGITS) ? Number(process.env.TOTP_DIGITS) : 6,
    step: Number(process.env.TOTP_PERIOD) ? Number(process.env.TOTP_PERIOD) : 30,
    window: Number(process.env.TOTP_WINDOW) ? Number(process.env.TOTP_WINDOW) : 2,
    algorithm: (process.env.TOTP_ALGORITHM ? process.env.TOTP_ALGORITHM : 'sha1'),
    secretLength: Number(process.env.TOTP_SIZE) ? Number(process.env.TOTP_SIZE) : 32,
//    issuer: "convey LeadSuccess",
/*    serviceName: "LeadSuccess Portal",
    digits: 6,
    step: 30,
    window: 2,
    algorithm: 'sha1',
    secretLength: 32,*/
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


// only for developemnt
function log(level, message, data = null) {
  if (!CONFIG.logging.enabled) return;

  const timestamp = new Date().toISOString();
  const prefix = {
      INFO: "",
      WARN: "⚠️",
      ERROR: "❌",
      DEBUG: "🔍",
    }[level] || "📝";

  const logMessage = `[${timestamp}] ${prefix} ${level}: ${message}`;

  if (data) {
    if (!CONFIG.logging.sensitive && data.password) {
      data = { ...data, password: "***REDACTED***" };
    }
    if (!CONFIG.logging.sensitive && data.secret) {
      data = { ...data, secret: maskSensitiveData(data.secret) };
    }
    console.log(logMessage, JSON.stringify(data, null, 2));
  } else {
    console.log(logMessage);
  }
}

// SECURITY VERIFICATION FUNCTION

// fallback vers authentification par credentials
async function authenticateSession(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    const sessionToken = authHeader && authHeader.startsWith('Bearer ') 
      ? authHeader.slice(7) 
      : req.body.sessionToken;

    if (sessionToken) {
      // check if the session token is valid
      const sessionQuery = await databaseManager.query(
        "SELECT * FROM appblddbo.TwoFactorSession WHERE SessionToken = ? AND LastUsedTS > DATEADD(hour, -24, CURRENT_TIMESTAMP)",
        [sessionToken]
      );

      if (sessionQuery.length > 0) {
        const sessionData = JSON.parse(sessionQuery[0].SessionInfo);
        
        if (sessionData.authenticated2FA) {
          req.user = {
            username: sessionData.username,
            userId: sessionData.userId,
            sessionToken: sessionToken
          };

          await databaseManager.query(
            "UPDATE appblddbo.TwoFactorSession SET LastUsedTS = CURRENT_TIMESTAMP WHERE SessionToken = ?",
            [sessionToken]
          );
          return next();
        }
      }
    }

    // fallback vers authentification par credentials
    const { username, password } = req.body;
    if (username && password) {
      const credentialsCheck = await verifyCredentialsForEndpoint(username, password);
      if (credentialsCheck.success) {
        req.user = {
          username: username,
          password: password 
        };
        return next();
      }
    }

    return res.status(401).json({
      success: false,
      message: "Authentication required"
    });

  } catch (error) {
    log("ERROR", "Authentication middleware error", { error: error.message });
    return res.status(500).json({
      success: false,
      message: "Authentication error"
    });
  }
}

// check credentials for every endpoint using PRC_CheckGlobalPassword
async function verifyCredentialsForEndpoint(username, password, strict = 0) {
  try {
    if (!username || !password) {
      return {
        success: false,
        message: "Username and password required for authentication",
        resultCode: 400
      };
    }

    // PRC_CheckGlobalPassword handles all password logic internally
    const result = await databaseManager.query(
      "SELECT ResultCode, ResultMessage, DBPassword, ODataLocation, InactiveFlag FROM appblddbo.PRC_CheckGlobalPassword(?,?,?)",
      [username, password, strict ? 1 : 0]
    );


      if (!result || result.length === 0) {
      return {
        success: false,
        message: "No result from database authentication",
        resultCode: 500
      };
    }

    const authResult = result[0];
    
    if (authResult.ResultCode === 0 || authResult.ResultCode === 1330)  {
      return {
        success: true,
        message: "Credentials valid",
        resultCode: authResult.ResultCode,
        odataLocation: authResult.ODataLocation,
        inactiveFlag: authResult.InactiveFlag
      };
    } else {
      return {
        success: false,
        message: authResult.ResultMessage || "Invalid credentials",
        resultCode: authResult.ResultCode
      };
    }
  } catch (error) {
    log("ERROR", "Credentials verification failed", { username, error: error.message });
    return {
      success: false,
      message: "Authentication service error",
      resultCode: 401
    };
  }
}

// TOTP SERVICE

class TOTPService {
  constructor() {
    this.recentCodes = new Map();
    this.pendingSetups = new Map();
    this.cleanupInterval = setInterval(
      () => this.cleanupOldCodes(),
      CONFIG.session.cleanupInterval
    );
  }

  async generateTOTP(username) {
    try {
      const secret = speakeasy.generateSecret({
        name: `${CONFIG.totp.issuer}:${username}`,
        issuer: CONFIG.totp.issuer,
        length: CONFIG.totp.secretLength,
      });

      const otpAuthUrl = secret.otpauth_url;
      const qrCodeDataURL = await QRCode.toDataURL(otpAuthUrl, {
        errorCorrectionLevel: "M",
        type: "image/png",
        quality: 0.92,
        margin: 1,
        width: 256,
        color: {
          dark: "#000000",
          light: "#FFFFFF",
        },
      });

      log("INFO", `TOTP generated for user: ${username}`);

      return {
        secret: secret.base32,
        qrCode: qrCodeDataURL,
        uri: otpAuthUrl,
        manualEntryKey: secret.base32,
      };
    } catch (error) {
      log("ERROR", "Error generating TOTP", { error: error.message });
      throw error;
    }
  }

  storePendingSetup(sessionToken, setupData) {
    this.pendingSetups.set(sessionToken, {
      ...setupData,
      timestamp: Date.now(),
    });
    log("INFO", "Pending setup stored", {
      sessionToken: sessionToken.substring(0, 8) + "...",
    });
  }

  getPendingSetup(sessionToken) {
    const setup = this.pendingSetups.get(sessionToken);
    if (setup) {
      log("INFO", "Pending setup retrieved", {
        sessionToken: sessionToken.substring(0, 8) + "...",
      });
      return setup;
    }
    return null;
  }

  removePendingSetup(sessionToken) {
    if (this.pendingSetups.delete(sessionToken)) {
      log("INFO", "Pending setup removed after successful verification", {
        sessionToken: sessionToken.substring(0, 8) + "...",
      });
      return true;
    }
    return false;
  }

  async verifyTOTPWithSecret(secret, token, userId = null) {
    try {
      if (!/^\d{6}$/.test(token)) {
        return { success: false, error: "Invalid code format" };
      }

      if (userId) {
        const codeKey = `${userId}:${token}`;
        if (this.recentCodes.has(codeKey)) {
          return { success: false, error: "Code already used" };
        }
      }

      const verified = speakeasy.totp.verify({
        secret,
        encoding: "base32",
        token,
        window: CONFIG.totp.window,
        algorithm: CONFIG.totp.algorithm,
        digits: CONFIG.totp.digits,
        step: CONFIG.totp.step,
      });

      if (verified) {
        if (userId) {
          const codeKey = `${userId}:${token}`;
          this.recentCodes.set(codeKey, Date.now());
        }
        return { success: true };
      } else {
        return { success: false, error: "Invalid code" };
      }
    } catch (error) {
      log("ERROR", "Error verifying TOTP with secret", {
        userId,
        error: error.message,
      });
      return { success: false, error: "Verification failed" };
    }
  }

  async verifyTOTP(userId, token) {
    try {
      const userIdInt = parseInt(userId);
      if (isNaN(userIdInt)) {
        return { success: false, deviceId: null };
      }

      if (!/^\d{6}$/.test(token)) {
        return { success: false, deviceId: null };
      }

      const codeKey = `${userIdInt}:${token}`;
      if (this.recentCodes.has(codeKey)) {
        return { success: false, deviceId: null };
      }

      const devices = await databaseManager.query(
        `SELECT TwoFactorDeviceID, SecretData, DeviceInfo
        FROM appblddbo.TwoFactorDevice 
        WHERE TwoFactorUserID = ? AND Inactive IS NULL`,
        [userIdInt]
      );

      if (devices.length === 0) {
        return { success: false, deviceId: null };
      }

      for (const device of devices) {
        const verified = speakeasy.totp.verify({
          secret: device.SecretData,
          encoding: "base32",
          token,
          window: CONFIG.totp.window,
          algorithm: CONFIG.totp.algorithm,
          digits: CONFIG.totp.digits,
          step: CONFIG.totp.step,
        });

        if (verified) {
          this.recentCodes.set(codeKey, Date.now());
          return {
            success: true,
            deviceId: device.TwoFactorDeviceID,
            deviceInfo: device.DeviceInfo,
          };
        }
      }

      return { success: false, deviceId: null };
    } catch (error) {
      log("ERROR", "Error verifying TOTP", {
        userId: parseInt(userId),
        error: error.message,
      });
      return { success: false, deviceId: null };
    }
  }

  cleanupOldCodes() {
    const now = Date.now();
    const ttl = CONFIG.session.replayProtectionTTL;
    let cleanedCount = 0;

    for (const [key, timestamp] of this.recentCodes) {
      if (now - timestamp > ttl) {
        this.recentCodes.delete(key);
        cleanedCount++;
      }
    }

    const setupTTL = 10 * 60 * 1000; 
    let expiredSetups = 0;
    for (const [sessionToken, setup] of this.pendingSetups) {
      if (now - setup.timestamp > setupTTL) {
        this.pendingSetups.delete(sessionToken);
        expiredSetups++;
      }
    }

    if (cleanedCount > 0 || expiredSetups > 0) {
      log("DEBUG", `Cleaned up ${cleanedCount} old TOTP codes and ${expiredSetups} expired setups`);
    }
  }
}

const totpService = new TOTPService();

// HELPER FUNCTIONS
async function getTwoFactorUser(username) {
  try {
    const existingUser = await databaseManager.query(
      "SELECT * FROM appblddbo.TwoFactorUser WHERE LoginName = ?",
      [username]
    );

    if (existingUser.length > 0) {
      log("INFO", `Existing 2FA user found: ${username}`);
      return existingUser[0];
    } else {
      log("INFO", `User not found in 2FA system: ${username}`);
      return null;
    }
  } catch (error) {
    log("ERROR", "Error getting 2FA user", {
      username,
      error: error.message,
    });
    throw error;
  }
}

// add 2FA device
async function addTwoFactorDevice(userId, deviceInfo, secret) {
  try {
    const userIdInt = parseInt(userId);
    if (isNaN(userIdInt)) {
      throw new Error(`Invalid userId: ${userId} is not a number`);
    }

    await databaseManager.query(
      "INSERT INTO appblddbo.TwoFactorDevice (TwoFactorUserID, AuthMethod, DeviceInfo, SecretData, Inactive) VALUES (?, ?, ?, ?, ?)",
      [userIdInt, "TOTP", deviceInfo, secret, null]
    );

    const deviceQuery = await databaseManager.query(
      "SELECT TwoFactorDeviceID FROM appblddbo.TwoFactorDevice WHERE TwoFactorUserID = ? AND SecretData = ?",
      [userIdInt, secret]
    );

    if (deviceQuery.length > 0) {
      log("INFO", `New device created with ID: ${deviceQuery[0].TwoFactorDeviceID}`, {
        deviceInfo,
        userId: userIdInt,
      });
      return deviceQuery[0].TwoFactorDeviceID;
    } else {
      throw new Error("Device creation failed");
    }
  } catch (error) {
    log("ERROR", "Error adding device", {
      userId: parseInt(userId),
      deviceInfo,
      error: error.message,
    });
    throw error;
  }
}

function formatProcedureResult(result, procedureName) {
  if (!result || result.length === 0) {
    return {
      success: false,
      message: `No result from ${procedureName}`,
      resultCode: -1,
    };
  }

  const data = result[0];
  return {
    success: data.ResultCode === 0,
    resultCode: data.ResultCode,
    message: data.ResultMessage || "Unknown result",
    data: data,
  };
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

  const browserName = ua.includes("chrome") ? "Chrome"
    : ua.includes("firefox") ? "Firefox"
    : ua.includes("safari") ? "Safari"
    : ua.includes("edge") ? "Edge"
    : "Browser";

  const osName = ua.includes("windows") ? "Windows"
    : ua.includes("mac") ? "macOS"
    : ua.includes("linux") ? "Linux"
    : ua.includes("android") ? "Android"
    : ua.includes("ios") ? "iOS"
    : "Unknown OS";

  const uniqueId = Math.random().toString(36).substring(2, 6).toUpperCase();

  return `${browserName} ${browserVersionMatch?.[2] || ""} on ${osName} ${osMatch?.[2] || ""} (${uniqueId})`;
}

async function updateSessionsDeviceInfo(username, oldDeviceInfo, newDeviceInfo) {
  try {
    const sessions = await databaseManager.query(
      "SELECT SessionToken, SessionInfo FROM appblddbo.TwoFactorSession WHERE UserLogin = ?",
      [username]
    );

    let updatedCount = 0;

    for (const session of sessions) {
      try {
        const sessionData = JSON.parse(session.SessionInfo);

        if (sessionData.deviceInfo === oldDeviceInfo) {
          sessionData.deviceInfo = newDeviceInfo;
          const updatedSessionInfo = JSON.stringify(sessionData);

          await databaseManager.query(
            "UPDATE appblddbo.TwoFactorSession SET SessionInfo = ? WHERE SessionToken = ?",
            [updatedSessionInfo, session.SessionToken]
          );

          updatedCount++;
        }
      } catch (parseError) {
        log("WARN", `Could not parse session info for token: ${session.SessionToken.substring(0, 8)}...`);
      }
    }

    log("INFO", `Updated device info in ${updatedCount} sessions`, {
      username,
      oldDeviceInfo,
      newDeviceInfo,
    });
    return updatedCount;
  } catch (error) {
    log("ERROR", "Error updating sessions device info", {
      username,
      error: error.message,
    });
    throw error;
  }
}

async function cleanupSessionsForDevice(username, deviceId) {
  try {
    const deviceIdInt = parseInt(deviceId);
    if (isNaN(deviceIdInt)) {
      return 0;
    }

    const sessions = await databaseManager.query(
      "SELECT SessionToken, SessionInfo FROM appblddbo.TwoFactorSession WHERE UserLogin = ?",
      [username]
    );

    let cleanedCount = 0;

    for (const session of sessions) {
      try {
        const sessionData = JSON.parse(session.SessionInfo);

        if (parseInt(sessionData.deviceId) === deviceIdInt) {
          await databaseManager.query(
            "DELETE FROM appblddbo.TwoFactorSession WHERE SessionToken = ?",
            [session.SessionToken]
          );
          cleanedCount++;
        }
      } catch (parseError) {
        log("WARN", `Could not parse session info for cleanup: ${session.SessionToken.substring(0, 8)}...`);
      }
    }

    log("INFO", `Cleaned ${cleanedCount} sessions for device ${deviceIdInt}`);
    return cleanedCount;
  } catch (error) {
    log("ERROR", "Error cleaning sessions for device", {
      username,
      deviceId: parseInt(deviceId),
      error: error.message,
    });
    throw error;
  }
}


// API ROUTES - ALL POST WITH CREDENTIAL VERIFICATION

router.use((req, res, next) => {
  next();
});

// API Information
router.get("/", (req, res) => {
  res.json({
    success: true,
    message: "LeadSuccess 2FA API - Final Corrected Version",
    timestamp: new Date().toISOString(),
    architecture: "Client keeps original password, procedures handle DBPassword internally",
    security: "All endpoints secured with PRC_CheckGlobalPassword",
    endpoints: {
      authentication: {
        login: "POST /auth/login",
        checkCredentials: "POST /auth/check-credentials", 
        setup2fa: "POST /auth/setup-2fa",
        verify2fa: "POST /auth/verify-2fa",
        status: "POST /auth/status",
        disable2fa: "POST /auth/disable-2fa",
      },
      devices: {
        list: "POST /devices/list",
        add: "POST /devices/add", 
        rename: "POST /devices/rename",
        remove: "POST /devices/remove",
      },
      sessions: {
        list: "POST /sessions/list",
        logout: "POST /sessions/logout",
        logoutAll: "POST /sessions/logout-all",
      },
    },
  });
});

// System health check
router.get("/health", async (req, res) => {
  try {
    const dbHealthy = await databaseManager.healthCheck();

    res.status(dbHealthy ? 200 : 503).json({
      success: dbHealthy,
      message: dbHealthy ? "Service healthy" : "Database connection failed",
      timestamp: new Date().toISOString(),
      services: {
        database: dbHealthy ? "healthy" : "unhealthy",
        api: "healthy",
        totp: "healthy",
      },
    });
  } catch (error) {
    log("ERROR", "Health check error", { error: error.message });
    res.status(503).json({
      success: false,
      message: "Health check failed",
      error: error.message,
    });
  }
});

// AUTHENTICATION ROUTES

// Check credentials using PRC_CheckGlobalPassword
router.post("/auth/check-credentials", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password required",
      });
    }

    log("INFO", `Checking credentials for user: ${username}`);

    const credentialsCheck = await verifyCredentialsForEndpoint(username, password);
    
    if (credentialsCheck.success) {
      log("INFO", `Credentials valid for user: ${username}`);
      
      return res.json({
        success: true,
        message: "Credentials valid",
        resultCode: credentialsCheck.resultCode,
        resultMessage: credentialsCheck.message,
        odataLocation: credentialsCheck.odataLocation,
        inactiveFlag: credentialsCheck.inactiveFlag,
      });
    } else {
      log("WARN", `Invalid credentials for user: ${username}`, {
        resultCode: credentialsCheck.resultCode,
        resultMessage: credentialsCheck.message
      });

      return res.status(401).json({
        success: false,
        message: credentialsCheck.message || "Invalid credentials",
        resultCode: credentialsCheck.resultCode,
      });
    }

  } catch (error) {
    log("ERROR", "Credentials check error", {
      username: req.body.username,
      error: error.message,
    });
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
});

//login endpoint
router.post("/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password required",
      });
    }

    log("INFO", `Login attempt for user: ${username}`);

    // Verify credentials first using PRC_CheckGlobalPassword
    const credentialsCheck = await verifyCredentialsForEndpoint(username, password);
    
    if (!credentialsCheck.success) {
      log("WARN", `Invalid credentials for user: ${username}`);
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Check 2FA status
    const userQuery = await databaseManager.query(
      "SELECT TwoFactorUserID, Disable2FA FROM appblddbo.TwoFactorUser WHERE LoginName = ?",
      [username]
    );

    const has2FARecord = userQuery.length > 0;

    if (has2FARecord) {
      const userIdInt = parseInt(userQuery[0].TwoFactorUserID);
      if (isNaN(userIdInt)) {
        throw new Error(`Invalid TwoFactorUserID: ${userQuery[0].TwoFactorUserID}`);
      }

      const deviceQuery = await databaseManager.query(
        "SELECT COUNT(*) as count FROM appblddbo.TwoFactorDevice WHERE Inactive IS NULL AND TwoFactorUserID = ?",
        [userIdInt]
      );
      
      const activeDeviceCount = deviceQuery[0].count;
      const is2FAEnabled = !userQuery[0].Disable2FA && activeDeviceCount > 0;
      
      if (!userQuery[0].Disable2FA && activeDeviceCount === 0) {
        log("INFO", `Auto-disabling 2FA for user ${username} - no active devices`, {
          username,
          userIdInt,
          activeDeviceCount
        });
        
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
          username,
          userId: userIdInt,
          originalPassword: password, 
          loginTime: new Date().toISOString(),
          requires2FA: true,
          ipAddress: req.ip,
          userAgent: req.get("User-Agent"),
          deviceInfo: deviceInfo,
          deviceId: null,
          sessionType: "pending_2fa",
        };

        await databaseManager.query(
          "INSERT INTO appblddbo.TwoFactorSession (SessionToken, UserLogin, LastUsedTS, SessionInfo) VALUES (?,?,CURRENT_TIMESTAMP,?)",
          [sessionToken, username, JSON.stringify(sessionData)]
        );

        return res.json({
          success: true,
          message: "User has 2FA enabled - verification required",
          sessionToken,
          user: {
            username,
            id: userIdInt,
            requires2FA: true,
          },
          nextStep: "verify_2fa",
          d: {
            ODataLocation: credentialsCheck.odataLocation || "odata_online",
            requires2FA: true,
            HasTwoFactor: true,
            sessionToken,
            SessionToken: sessionToken,
            InactiveFlag: credentialsCheck.inactiveFlag || false,
          },
        });
      } else {
        // user has 2FA disabled OR no active devices
        log("INFO", `User has 2FA disabled or no active devices: ${username}`);
        return res.json({
          success: true,
          message: "User has 2FA disabled - use standard login",
          d: {
            ODataLocation: credentialsCheck.odataLocation || "odata_online",
            requires2FA: false,
            HasTwoFactor: false,
            InactiveFlag: credentialsCheck.inactiveFlag || false,
          },
        });
      }
    } else {
      // user is not in 2FA system
      log("INFO", `User not in 2FA system: ${username}`);
      return res.json({
        success: false,
        message: "Use standard login endpoint for non-2FA users",
        d: {
          ODataLocation: credentialsCheck.odataLocation || "odata_online",
          requires2FA: false,
          HasTwoFactor: false,
          InactiveFlag: credentialsCheck.inactiveFlag || false,
        },
      });
    }
  } catch (error) {
    log("ERROR", "Login error", {
      username: req.body.username,
      error: error.message,
    });
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
});

// setup 2FA
router.post("/auth/setup-2fa", async (req, res) => {
  try {

    const { username, password, deviceInfo = "Web Browser" } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password required",
      });
    }

    await databaseManager.query("BEGIN TRANSACTION");

    try {
      
    const userCheck = await databaseManager.query(
      "SELECT TwoFactorUserID, Disable2FA FROM appblddbo.TwoFactorUser WHERE LoginName = ?",
      [username]
    );

    const has2FAActive = userCheck.length > 0 && !userCheck[0].Disable2FA;

    // Verify credentials first
    const credentialsCheck = await verifyCredentialsForEndpoint(username, password, has2FAActive);

    if (!credentialsCheck.success) {
      return res.status(401).json({
       success: false,
        message: has2FAActive ? "Access denied - valid 2FA session required" :   credentialsCheck.message,
        resultCode: credentialsCheck.resultCode,
        requiresStrictAuth: has2FAActive
      });
    }

    await databaseManager.query("BEGIN TRANSACTION");

    try {

    // Ensure user exists in TwoFactorUser table for first setup
    let user = await getTwoFactorUser(username);
    if (!user) {
      
      await databaseManager.query(
        `INSERT INTO appblddbo.TwoFactorUser (LoginName, LoginPassword, DBPassword, ValidUntilUTC, TokenLifetime, Disable2FA) 
        VALUES (?, appblddbo.FCT_HashPassword(?), NULL, NULL, NULL, NULL)`,
        [username, password]
      );
      
      user = await getTwoFactorUser(username);

      if (!user) {
        return res.status(500).json({
          success: false,
          message: "Failed to create 2FA user record"
        });
      }
      
      log("INFO", `TwoFactorUser created for first setup`, {
        username,
        twoFactorUserID: user.TwoFactorUserID
      });
    }

    await databaseManager.query("COMMIT TRANSACTION");

    } catch (error) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      throw error;
    }

    // Generate TOTP secret 
    const totpData = await totpService.generateTOTP(username);

    // Enhanced device info detection
    const enhancedDeviceInfo = detectDeviceFromUserAgent(req.get("User-Agent"), deviceInfo);

    // Create temporary session token for this setup
    const sessionToken = uuidv4();

    const setupData = {
      username,
      password, 
      deviceInfo: enhancedDeviceInfo,
      totpSecret: totpData.secret,
      ipAddress: req.ip,
      userAgent: req.get("User-Agent"),
    };

    totpService.storePendingSetup(sessionToken, setupData);

    log("INFO", `2FA setup initiated with credential verification`, {
      username,
      deviceInfo: enhancedDeviceInfo,
    });

    // Return QR code and session token for verification
    res.status(200).json({
      success: true,
      message: "2FA setup initiated - scan QR code and verify",
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

  }
  catch (innerError) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      throw innerError;
    }
  } catch (error) {

    if (databaseManager.isConnected()) {
      try {
        await databaseManager.query("ROLLBACK TRANSACTION");
      } catch (rollbackError) {
        log("ERROR", "Rollback error in setup-2fa", { error: rollbackError.message });
      }
    }
    
    log("ERROR", "2FA setup error", { username: req.body.username, error: error.message });


    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
});

// Verify 2FA 
router.post("/auth/verify-2fa", async (req, res) => {
  try {
    const { sessionToken, totpCode, username } = req.body;

    if (!totpCode) {
      return res.status(400).json({
        success: false,
        message: "TOTP code required",
      });
    }

     if (!username) {
      return res.status(400).json({
        success: false,
        message: "Username required for verification",
      });
    }

    const pendingSetup = sessionToken ? totpService.getPendingSetup(sessionToken) : null;

    if (!pendingSetup && !username) {
      return res.status(400).json({
        success: false,
        message: "Username required for verification",
      });
    }

    if (pendingSetup) {

      // 2FA setup verification
      log("INFO", "Processing 2FA setup verification", {
        username: pendingSetup.username,
      });

      const { deviceName } = req.body;
      if (deviceName) {
        const trimmedDeviceName = deviceName.trim();
        if (trimmedDeviceName.length < 3 || trimmedDeviceName.length > 50) {
          return res.status(400).json({
            success: false,
            message: "Device name must be between 3 and 50 characters",
          });
        }
        pendingSetup.deviceInfo = trimmedDeviceName;
      }

      // verify TOTP code first
      const verification = await totpService.verifyTOTPWithSecret(
        pendingSetup.totpSecret,
        totpCode
      );

      if (!verification.success) {
        return res.status(401).json({
          success: false,
          message: verification.error || "Invalid TOTP code",
        });
      }

      await databaseManager.query("BEGIN TRANSACTION");
      try {

        // get user (must exist in TwoFactorUser)       
        let user = await getTwoFactorUser(pendingSetup.username);
        if (!user) {
          console.log(`🔧 Creating TwoFactorUser during verification for: ${pendingSetup.username}`);

          // User FCT_HashPassword to save Hash Password in TwoFactorUser          
          await databaseManager.query(
            `INSERT INTO appblddbo.TwoFactorUser (LoginName, LoginPassword, DBPassword, ValidUntilUTC, TokenLifetime, Disable2FA) 
            VALUES (?, appblddbo.FCT_HashPassword(?), NULL, NULL, NULL, NULL)`,
            [pendingSetup.username, pendingSetup.password]
          );
          
          user = await getTwoFactorUser(pendingSetup.username);
          if (!user) {
            await databaseManager.query("ROLLBACK TRANSACTION");
            return res.status(500).json({
              success: false,
              message: "Failed to create 2FA user record during verification"
            });
          }
        }

        const userIdInt = parseInt(user.TwoFactorUserID);
        if (isNaN(userIdInt)) {
          throw new Error(`Invalid TwoFactorUserID: ${user.TwoFactorUserID}`);
        }

        // check if first device
        const existingDevices = await databaseManager.query(
          "SELECT COUNT(*) as count FROM appblddbo.TwoFactorDevice WHERE Inactive IS NULL AND TwoFactorUserID = ?",
          [userIdInt]
        );
        const isFirstSetup = existingDevices[0].count === 0;

        // clean up old devices if first setup
        if (isFirstSetup) {
          await databaseManager.query(
            "DELETE FROM appblddbo.TwoFactorDevice WHERE TwoFactorUserID = ?",
            [userIdInt]
          );
        }

        // add the new device BEFORE calling PRC_ActivateTwoFactor
        const deviceId = await addTwoFactorDevice(
          userIdInt,
          pendingSetup.deviceInfo,
          pendingSetup.totpSecret
        );

        // call PRC_ActivateTwoFactor
        log("INFO", `Calling PRC_ActivateTwoFactor for user: ${pendingSetup.username}`);
        const activationResult = await databaseManager.query(
          "SELECT * FROM appblddbo.PRC_ActivateTwoFactor(?)",
          [pendingSetup.username]
        );

        const result = formatProcedureResult(activationResult, "PRC_ActivateTwoFactor");
        
        if (!result.success) {
          await databaseManager.query("ROLLBACK TRANSACTION");
          return res.status(400).json({
            success: false,
            message: result.message,
            error: "PRC_ActivateTwoFactor failed"
          });
        }
  
        const dbPassword = result.data.DBPassword; 

        // create authenticated session
        const newSessionToken = uuidv4();
        const sessionData = {
          username: pendingSetup.username,
          userId: userIdInt,
          loginTime: new Date().toISOString(),
          requires2FA: true,
          authenticated2FA: true,
          ipAddress: pendingSetup.ipAddress,
          userAgent: pendingSetup.userAgent,
          deviceInfo: pendingSetup.deviceInfo,
          deviceId: deviceId,
        };

        await databaseManager.query(
          "INSERT INTO appblddbo.TwoFactorSession (SessionToken, UserLogin, LastUsedTS, SessionInfo) VALUES (?,?,CURRENT_TIMESTAMP,?)",
          [newSessionToken, pendingSetup.username, JSON.stringify(sessionData)]
        );

        await databaseManager.query("COMMIT TRANSACTION");
        totpService.removePendingSetup(sessionToken);

        log("INFO", `2FA setup completed using ONLY PRC_ActivateTwoFactor`, {
          username: pendingSetup.username,
          deviceId,
          isFirstSetup,
          dbPasswordGenerated: !!dbPassword
        });

        return res.json({
          success: true,
          message: "2FA setup completed successfully",
          sessionToken: newSessionToken,
          user: {
            username: pendingSetup.username,
            id: userIdInt,
          },
          isFirstSetup: isFirstSetup,
          dbPassword: dbPassword,
          note: "Using DBPassword for future API calls"
        });

      } catch (error) {
        await databaseManager.query("ROLLBACK TRANSACTION");
        log("ERROR", "Error during 2FA setup", {
          username: pendingSetup.username,
          error: error.message,
        });
        throw error;
      }

    } else {

      // EXISTING 2FA VERIFICATION FOR LOGIN
      
      log("INFO", "Processing existing 2FA verification for login");

      let sessionData = null;
      let sessionTokenToUse = sessionToken;

      if (!sessionTokenToUse && username) {
        // Get latest session using FIRST...ORDER BY DESC pattern
        const latestSession = await databaseManager.query(
          "SELECT FIRST * FROM appblddbo.TwoFactorSession WHERE UserLogin = ? ORDER BY LastUsedTS DESC",
          [username]
        );

        if (latestSession.length === 0) {
          return res.status(401).json({
            success: false,
            message: "No active session found for user",
          });
        }

        sessionTokenToUse = latestSession[0].SessionToken;
        log("INFO", "Found latest session", { 
          sessionToken: sessionTokenToUse.substring(0, 8) + "...",
          username 
        });
      }

      // Get session data
      const sessionQuery = await databaseManager.query(
        "SELECT * FROM appblddbo.TwoFactorSession WHERE SessionToken = ?",
        [sessionTokenToUse]
      );

      if (sessionQuery.length === 0) {
        return res.status(401).json({
          success: false,
          message: "Invalid or expired session",
        });
      }

      sessionData = JSON.parse(sessionQuery[0].SessionInfo);

      const { username: sessionUsername, userId } = sessionData;

      const userIdInt = userId ? parseInt(userId) : null;
      if (!userIdInt) {
        return res.status(400).json({
          success: false,
          message: "Invalid session data",
        });
      }

      // Verify TOTP code
      const verificationResult = await totpService.verifyTOTP(userIdInt, totpCode);
      if (!verificationResult.success) {
        return res.status(401).json({
          success: false,
          message: "Invalid TOTP code",
        });
      }

      // Update session as authenticated
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

        // Get DBPassword from PRC_ActivateTwoFactor using sessionUsername
        log("INFO", `Calling PRC_ActivateTwoFactor for user: ${sessionUsername}`);
        
        const activationResult = await databaseManager.query(
          "SELECT * FROM appblddbo.PRC_ActivateTwoFactor(?)",
          [sessionUsername]
        );

        const result = formatProcedureResult(activationResult, "PRC_ActivateTwoFactor");
        
        if (!result.success) {
          return res.status(400).json({
            success: false,
            message: result.message,
            error: "PRC_ActivateTwoFactor failed"
          });
        }
  
        const dbPassword = result.data.DBPassword; 

      return res.json({
        success: true,
        message: "2FA verification successful",
        sessionToken: sessionTokenToUse,
        user: {
          username: sessionUsername,
          id: userIdInt,
        },
         dbPassword: dbPassword,
      });
    }

  } catch (error) {
    if (databaseManager.isConnected()) {
      await databaseManager.query("ROLLBACK TRANSACTION");
    }

    log("ERROR", "2FA verification error", { error: error.message });
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
});


// Get 2FA status
router.post("/auth/status", authenticateSession, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password required",
      });
    }

    // Verify credentials first
    const credentialsCheck = await verifyCredentialsForEndpoint(username, password, 0);
    if (!credentialsCheck.success) {
      return res.status(401).json({
        success: false,
        message: credentialsCheck.message,
        resultCode: credentialsCheck.resultCode
      });
    }

    // Get 2FA status
    const userQuery = await databaseManager.query(
      "SELECT * FROM appblddbo.TwoFactorUser WHERE LoginName = ?",
      [username]
    );

    if (userQuery.length === 0) {
      return res.json({
        success: true,
        message: "User status retrieved",
        username,
        exists: false,
        is2FAEnabled: false,
      });
    }

    const user = userQuery[0];
    const userIdInt = parseInt(user.TwoFactorUserID);
    
    if (isNaN(userIdInt)) {
      throw new Error(`Invalid TwoFactorUserID: ${user.TwoFactorUserID}`);
    }

    // Get active devices count
    const deviceQuery = await databaseManager.query(
      "SELECT COUNT(*) as count FROM appblddbo.TwoFactorDevice WHERE Inactive IS NULL AND TwoFactorUserID = ?",
      [userIdInt]
    );

    // Get active sessions count  
    const sessionQuery = await databaseManager.query(
      "SELECT COUNT(*) as count FROM appblddbo.TwoFactorSession WHERE UserLogin = ?",
      [username]
    );

    const activeDeviceCount = deviceQuery[0].count;

    const is2FAEnabled = !user.Disable2FA && activeDeviceCount > 0;

    // Optional: Auto-cleanup orphaned 2FA records with no devices
    if (!user.Disable2FA && activeDeviceCount === 0) {
      log("INFO", `Auto-disabling 2FA for user ${username} - no active devices`, {
        username,
        userIdInt,
        activeDeviceCount
      });

      await databaseManager.query(
        "UPDATE appblddbo.TwoFactorUser SET Disable2FA = 1 WHERE TwoFactorUserID = ?",
        [userIdInt]
      );
    }


    res.json({
      success: true,
      message: "User status retrieved",
      username,
      exists: true,
      id: userIdInt,
      is2FAEnabled: is2FAEnabled,
      totalDevices: activeDeviceCount,
      activeDevices: activeDeviceCount,
      activeSessions: sessionQuery[0].count,
      hasDBPassword: !!user.DBPassword,
      credentialsValid: true
    });
  } catch (error) {
    log("ERROR", "Status check error", {
      username: req.body.username,
      error: error.message,
    });
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
});


router.post("/auth/disable-2fa", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password required",
      });
    }

    const credentialsCheck = await verifyCredentialsForEndpoint(username, password, false);
    if (!credentialsCheck.success) {
      return res.status(401).json({
        success: false,
        message: "Access denied - valid 2FA session required",
        resultCode: credentialsCheck.resultCode,
      });
    }

    // Check if user has 2FA enabled
    const userQuery = await databaseManager.query(
      "SELECT TwoFactorUserID, Disable2FA FROM appblddbo.TwoFactorUser WHERE LoginName = ?",
      [username]
    );

    if (userQuery.length === 0 || userQuery[0].Disable2FA === 1) {
      return res.json({
        success: true,
        message: "2FA already disabled or not configured",
        originalPassword: password,
        note: "No changes needed"
      });
    }

    // Get any active device (or use first available device ID)
    const activeDevices = await databaseManager.query(
      `SELECT d.TwoFactorDeviceID 
       FROM appblddbo.TwoFactorDevice d 
       JOIN appblddbo.TwoFactorUser u ON d.TwoFactorUserID = u.TwoFactorUserID 
       WHERE u.LoginName = ? AND d.Inactive IS NULL 
       ORDER BY d.TwoFactorDeviceID ASC`,
      [username]
    );

    if (activeDevices.length === 0) {
      return res.status(404).json({
        success: false,
        message: "No active devices found - 2FA may already be disabled",
      });
    }

    const firstDeviceId = activeDevices[0].TwoFactorDeviceID;
    
    log("INFO", `Disabling 2FA using PRC_Disable2FADevice for user: ${username}`);
    
    const procedureResult = await databaseManager.query(
      "SELECT * FROM appblddbo.PRC_Disable2FADevice(?, ?, ?, ?)",
      [firstDeviceId, password, username, 1] 
    );

    const result = formatProcedureResult(procedureResult, "PRC_Disable2FADevice");
    
    if (!result.success) {
      return res.status(400).json({
        success: false,
        message: result.message,
        error: "PRC_Disable2FADevice failed"
      });
    }

    const originalPassword = result.data.DBPassword || password;

    await databaseManager.query(
      "DELETE FROM appblddbo.TwoFactorSession WHERE UserLogin = ?",
      [username]
    );

    log("INFO", `2FA disabled successfully: ${username}`);

    res.json({
      success: true,
      message: "2FA disabled successfully",
      user: {
        username: username,
        is2FAEnabled: false,
      },
      originalPassword: originalPassword, 
      procedureResult: result.message,
      note: "2FA disabled - use original password for future logins",
    });

  } catch (error) {
    log("ERROR", "Error disabling 2FA", {
      username: req.body.username,
      error: error.message,
    });
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
});


//Endpoint to get the current password to use
router.post("/auth/get-current-password", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password required",
      });
    }

    const credentialsCheck = await verifyCredentialsForEndpoint(username, password);
    
    if (credentialsCheck.success) {

      return res.json({
        success: true,
        currentPassword: password,
        message: "Current password retrieved",
        resultCode: credentialsCheck.resultCode,
      });
    } else {
      return res.status(401).json({
        success: false,
        message: credentialsCheck.message,
        resultCode: credentialsCheck.resultCode
      });
    }

  } catch (error) {
    log("ERROR", "Get current password error", { error: error.message });
    res.status(500).json({
      success: false,
      message: "Internal server error"
    });
  }
});


// DEVICE MANAGEMENT ROUTES

// List user devices
router.post("/devices/list", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password required",
      });
    }

    // STEP 1: Verify credentials first
    const credentialsCheck = await verifyCredentialsForEndpoint(username, password, false);
    if (!credentialsCheck.success) {
      return res.status(401).json({
        success: false,
        message: credentialsCheck.message,
        resultCode: credentialsCheck.resultCode
      });
    }

    // STEP 2: Get user information
    const userQuery = await databaseManager.query(
      "SELECT TwoFactorUserID, Disable2FA FROM appblddbo.TwoFactorUser WHERE LoginName = ?",
      [username]
    );

    if (userQuery.length === 0) {
      return res.json({
        success: true,
        message: "Devices retrieved",
        username,
        deviceCount: 0,
        activeDevices: 0,
        devices: [],
        twoFactorStatus: "never_activated"
      });
    }

    const user = userQuery[0];
    const userIdInt = parseInt(user.TwoFactorUserID);
    
    if (isNaN(userIdInt)) {
      throw new Error(`Invalid TwoFactorUserID: ${user.TwoFactorUserID}`);
    }

    if (user.Disable2FA === 1) {
      return res.json({
        success: true,
        message: "Devices retrieved",
        username,
        deviceCount: 0,
        activeDevices: 0,
        devices: [],
        twoFactorStatus: "disabled"
      });
    }

    // Get active devices
    const devices = await databaseManager.query(
      "SELECT * FROM appblddbo.TwoFactorDevice WHERE TwoFactorUserID = ? AND Inactive IS NULL",
      [userIdInt]
    );

    const deviceList = devices.map((device) => ({
      deviceId: device.TwoFactorDeviceID,
      authMethod: device.AuthMethod,
      deviceInfo: device.DeviceInfo,
      isActive: !device.Inactive,
      secretData: device.SecretData ? maskSensitiveData(device.SecretData) : null,
    }));

    res.json({
      success: true,
      message: "Devices retrieved",
      username,
      deviceCount: deviceList.length,
      activeDevices: deviceList.filter((d) => d.isActive).length,
      devices: deviceList,
      twoFactorStatus: deviceList.length > 0 ? "enabled" : "enabled_no_devices"
    });

  } catch (error) {
    log("ERROR", "List devices error", {
      username: req.body.username,
      error: error.message,
    });
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
});

// Add new device
router.post("/devices/add", async (req, res) => {
  try {
    const { username, password, deviceInfo = "New Device" } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password required",
      });
    }

    // 1. Verify credentials first
    
    const userCheck = await databaseManager.query(
      "SELECT TwoFactorUserID, Disable2FA FROM appblddbo.TwoFactorUser WHERE LoginName = ?",
      [username]
    );
    
    const has2FAActive = userCheck.length > 0 && !userCheck[0].Disable2FA;
    
    const credentialsCheck = await verifyCredentialsForEndpoint(username, password, has2FAActive);

    if (!credentialsCheck.success) {
      return res.status(401).json({
        success: false,
        message: has2FAActive ? 
            "Access denied - valid 2FA session required" : 
            credentialsCheck.message,
          resultCode: credentialsCheck.resultCode,
          requiresStrictAuth: has2FAActive
        });
    }

    await databaseManager.query("BEGIN TRANSACTION");

    // 2. Get user
    const userQuery = await databaseManager.query(
      "SELECT * FROM appblddbo.TwoFactorUser WHERE LoginName = ?",
      [username]
    );

    if (userQuery.length === 0) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      return res.status(404).json({
        success: false,
        message: "User not found in 2FA system",
      });
    }

    const user = userQuery[0];
    const userIdInt = parseInt(user.TwoFactorUserID);
    
    if (isNaN(userIdInt)) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      throw new Error(`Invalid TwoFactorUserID: ${user.TwoFactorUserID}`);
    }

    // 3. Enhanced device info detection
    const enhancedDeviceInfo = detectDeviceFromUserAgent(req.get("User-Agent"), deviceInfo);

    // check if device with same name already exists
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

    // 4. Generate new TOTP secret and add device
    const totpData = await totpService.generateTOTP(username);
    const deviceId = await addTwoFactorDevice(userIdInt, enhancedDeviceInfo, totpData.secret);

    await databaseManager.query("COMMIT TRANSACTION");

    log("INFO", `New device added with credentials verification`, {
      username,
      deviceInfo: enhancedDeviceInfo,
      deviceId,
    });

    res.status(201).json({
      success: true,
      message: "Device added successfully",
      device: {
        deviceId,
        deviceInfo: enhancedDeviceInfo,
        authMethod: "TOTP",
      },
      totpSetup: {
        secret: totpData.secret,
        qrCodeDataURL: totpData.qrCode,
        manualEntryKey: totpData.manualEntryKey,
      },
    });

  } catch (error) {
    await databaseManager.query("ROLLBACK TRANSACTION");
    log("ERROR", "Add device error", {
      username: req.body.username,
      error: error.message,
    });
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
});


// rename device 
router.post("/devices/rename", async (req, res) => {
  try {
    const { deviceId, username, password, newDeviceName } = req.body;

    const deviceIdInt = parseInt(deviceId);
    if (isNaN(deviceIdInt)) {
      return res.status(400).json({
        success: false,
        message: "Invalid device ID - must be numeric",
      });
    }

    if (!username || !password || !newDeviceName) {
      return res.status(400).json({
        success: false,
        message: "Username, password and new device name required",
      });
    }

      const userCheck = await databaseManager.query(
        "SELECT TwoFactorUserID, Disable2FA FROM appblddbo.TwoFactorUser WHERE LoginName = ?",
        [username]
      );

    const has2FAActive = userCheck.length > 0 && !userCheck[0].Disable2FA;

    // STEP 1: Verify credentials first
    const credentialsCheck = await verifyCredentialsForEndpoint(username, password, has2FAActive);
    if (!credentialsCheck.success) {
      return res.status(401).json({
        message: has2FAActive ? "Access denied - valid 2FA session required" :   credentialsCheck.message,
        resultCode: credentialsCheck.resultCode,
        requiresStrictAuth: has2FAActive
      });
    }

    // Validate device name length
    if (newDeviceName.trim().length < 1 || newDeviceName.trim().length > 200) {
      return res.status(400).json({
        success: false,
        message: "Device name must be between 1 and 200 characters",
      });
    }

    await databaseManager.query("BEGIN TRANSACTION");

    // STEP 2: Verify device ownership
    const deviceQuery = await databaseManager.query(
      `SELECT d.*, u.LoginName 
       FROM appblddbo.TwoFactorDevice d 
       JOIN appblddbo.TwoFactorUser u ON d.TwoFactorUserID = u.TwoFactorUserID 
       WHERE d.TwoFactorDeviceID = ? AND u.LoginName = ? AND d.Inactive IS NULL`,
      [deviceIdInt, username]
    );

    if (deviceQuery.length === 0) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      return res.status(404).json({
        success: false,
        message: "Device not found or not owned by user",
      });
    }

    const oldDeviceName = deviceQuery[0].DeviceInfo;

    // STEP 3: Update device name
    await databaseManager.query(
      "UPDATE appblddbo.TwoFactorDevice SET DeviceInfo = ? WHERE TwoFactorDeviceID = ?",
      [newDeviceName.trim(), deviceIdInt]
    );

    // Update sessions with new device info
    const updatedSessions = await updateSessionsDeviceInfo(
      username,
      oldDeviceName,
      newDeviceName.trim()
    );

    await databaseManager.query("COMMIT TRANSACTION");

    log("INFO", `Device renamed`, {
      deviceId: deviceIdInt,
      oldName: oldDeviceName,
      newName: newDeviceName.trim(),
      sessionsUpdated: updatedSessions,
    });

    res.json({
      success: true,
      message: "Device renamed successfully",
      device: {
        deviceId: deviceIdInt,
        oldName: oldDeviceName,
        newName: newDeviceName.trim(),
      },
      sessionsUpdated: updatedSessions,
    });

  } catch (error) {
    await databaseManager.query("ROLLBACK TRANSACTION");
    log("ERROR", "Rename device error", {
      deviceId: parseInt(req.body.deviceId),
      error: error.message,
    });
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
});

// remove device - Uses PRC_Disable2FADevice for last device
router.post("/devices/remove", async (req, res) => {
  try {
    const { deviceId, username, password, confirmDelete = false } = req.body;

    const deviceIdInt = parseInt(deviceId);
    if (isNaN(deviceIdInt)) {
      return res.status(400).json({
        success: false,
        message: "Invalid device ID - must be numeric",
      });
    }

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password required",
      });
    }

    // 1. Verify credentials first
    const credentialsCheck = await verifyCredentialsForEndpoint(username, password, false);
    if (!credentialsCheck.success) {
      return res.status(401).json({
        success: false,
        message: "Access denied - valid 2FA session required",
        resultCode: credentialsCheck.resultCode,
        note: "Device removal requires strict authentication"
      });
    }

    await databaseManager.query("BEGIN TRANSACTION");

    // 2: Get device and verify ownership
    const deviceQuery = await databaseManager.query(
      `SELECT d.*, u.LoginName, u.TwoFactorUserID
       FROM appblddbo.TwoFactorDevice d 
       JOIN appblddbo.TwoFactorUser u ON d.TwoFactorUserID = u.TwoFactorUserID 
       WHERE d.Inactive IS NULL AND d.TwoFactorDeviceID = ? AND u.LoginName = ?`,
      [deviceIdInt, username]
    );

    if (deviceQuery.length === 0) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      return res.status(404).json({
        success: false,
        message: "Device not found or not owned by user",
      });
    }

    const userIdInt = parseInt(deviceQuery[0].TwoFactorUserID);
    if (isNaN(userIdInt)) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      throw new Error(`Invalid TwoFactorUserID: ${deviceQuery[0].TwoFactorUserID}`);
    }

    // 3: Check if this is the last active device
    const activeDeviceCount = await databaseManager.query(
      `SELECT COUNT(*) as count 
       FROM appblddbo.TwoFactorDevice 
       WHERE TwoFactorUserID = ? AND Inactive IS NULL`,
      [userIdInt]
    );

    if (activeDeviceCount[0].count === 1) {
      // This is the last device - requires confirmation
      if (!confirmDelete) {
        await databaseManager.query("ROLLBACK TRANSACTION");
        return res.status(400).json({
          success: false,
          message: "This is your last device. Removing it will disable 2FA.",
          requiresConfirmation: true,
          isLastDevice: true,
          deviceInfo: deviceQuery[0].DeviceInfo,
        });
      }

      // Use PRC_Disable2FADevice to properly handle last device removal
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
                username,
                deviceId: deviceIdInt,
                passwordLength: originalPassword?.length || 0,
                passwordStart: originalPassword?.substring(0, 4) + '***' || 'NULL'
            });

          // Clean up sessions
          await databaseManager.query(
            "DELETE FROM appblddbo.TwoFactorSession WHERE UserLogin = ?",
            [username]
          );

          await databaseManager.query("COMMIT TRANSACTION");

          log("INFO", `Last device removed and 2FA disabled using PRC_Disable2FADevice: ${username}`);

          res.json({
            success: true,
            message: "Last device removed and 2FA disabled successfully",
            device: {
              deviceId: deviceIdInt,
              deviceInfo: deviceQuery[0].DeviceInfo,
            },
            twoFactorDisabled: true,
            originalPassword:originalPassword,
            currentPassword: originalPassword,
              data: {
              DBPassword: originalPassword, 
              originalPassword: originalPassword 
            },
            procedureResult: result.message,
            note: "2FA completely disabled - use original password",
          });
        } else {
          await databaseManager.query("ROLLBACK TRANSACTION");
          res.status(400).json({
            success: false,
            message: result.message,
            error: "PRC_Disable2FADevice execution failed",
          });
        }
      } catch (error) {
        await databaseManager.query("ROLLBACK TRANSACTION");
        log("ERROR", "PRC_Disable2FADevice error", {
          deviceId: deviceIdInt,
          error: error.message,
        });
        res.status(500).json({
          success: false,
          message: "Failed to disable 2FA device",
          error: error.message,
        });
      }
    } else {
      // Not the last device - mark as inactive
      await databaseManager.query(
        "UPDATE appblddbo.TwoFactorDevice SET Inactive = 1 WHERE TwoFactorDeviceID = ?",
        [deviceIdInt]
      );

      const cleanedSessions = await cleanupSessionsForDevice(username, deviceIdInt);

      await databaseManager.query("COMMIT TRANSACTION");

      log("INFO", `Device removed (marked inactive): ${deviceIdInt}`);

      res.json({
        success: true,
        message: "Device removed successfully",
        device: {
          deviceId: deviceIdInt,
          deviceInfo: deviceQuery[0].DeviceInfo,
        },
        twoFactorDisabled: false,
        sessionsCleanedUp: cleanedSessions,
      });
    }

  } catch (error) {
    await databaseManager.query("ROLLBACK TRANSACTION");
    log("ERROR", "Remove device error", {
      deviceId: parseInt(req.body.deviceId),
      error: error.message,
    });
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
});


module.exports = router;