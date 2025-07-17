// Backend/src/routes/index.js 
const express = require("express");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const { v4: uuidv4 } = require("uuid");
const databaseManager = require("../config/database");

const router = express.Router();

// =============================================================================
// CONFIGURATION
// =============================================================================

const CONFIG = {
  totp: {
    issuer: "LeadSuccess",
    serviceName: "LeadSuccess Portal",
    digits: 6,
    step: 30,
    window: 2,
    algorithm: "sha1",
    secretLength: 32
  },
  session: {
    replayProtectionTTL: 5 * 60 * 1000, // 5 minutes
    cleanupInterval: 60000 // 1 minute
  },
  logging: {
    enabled: true,
    sensitive: false // Set to true in production to mask sensitive data
  }
};

// =============================================================================
// LOGGING UTILITY
// =============================================================================

/**
 * Centralized logging with levels and formatting
 * @param {string} level - Log level (INFO, WARN, ERROR, DEBUG)
 * @param {string} message - Log message
 * @param {Object} data - Additional data to log
 */
function log(level, message, data = null) {
  if (!CONFIG.logging.enabled) return;
  
  const timestamp = new Date().toISOString();
  const prefix = {
    'INFO': '✅',
    'WARN': '⚠️',
    'ERROR': '❌',
    'DEBUG': '🔍'
  }[level] || '📝';
  
  const logMessage = `[${timestamp}] ${prefix} ${level}: ${message}`;
  
  if (data) {
    // Mask sensitive data in production
    if (!CONFIG.logging.sensitive && data.password) {
      data = { ...data, password: '***REDACTED***' };
    }
    if (!CONFIG.logging.sensitive && data.secret) {
      data = { ...data, secret: maskSensitiveData(data.secret) };
    }
    console.log(logMessage, JSON.stringify(data, null, 2));
  } else {
    console.log(logMessage);
  }
}

// =============================================================================
// TOTP SERVICE INTEGRATION
// =============================================================================

class TOTPService {
  constructor() {
    this.recentCodes = new Map();
    this.pendingSetups = new Map();
    this.cleanupInterval = setInterval(
      () => this.cleanupOldCodes(),
      CONFIG.session.cleanupInterval
    );
  }

  /**
   * Generate TOTP secret and QR code with UTF-8 support
   * @param {string} username - Username for the account
   * @returns {Object} - Secret, QR code, and URI
   */
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

  /**
   * Store pending 2FA setup temporarily
   * @param {string} sessionToken - Session token as key
   * @param {Object} setupData - Setup data to store
   */
  storePendingSetup(sessionToken, setupData) {
    this.pendingSetups.set(sessionToken, {
      ...setupData,
      timestamp: Date.now(),
    });
    log("INFO", "Pending setup stored", {
      sessionToken: sessionToken.substring(0, 8) + "...",
    });
  }

  /**
   * Retrieve and remove pending setup
   * @param {string} sessionToken - Session token
   * @returns {Object|null} - Setup data or null if not found
   */
  getPendingSetup(sessionToken) {
    const setup = this.pendingSetups.get(sessionToken);
    if (setup) {
      log("INFO", "Pending setup retrieved (not deleted)", {
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

  /**
   * Verify TOTP code with secret
   * @param {string} secret - The TOTP secret
   * @param {string} token - The token to verify
   * @param {string} userId - User ID for replay protection
   * @returns {Object} - Verification result
   */

  async verifyTOTPWithSecret(secret, token, userId = null) {
    try {
      if (!/^\d{6}$/.test(token)) {
        log("WARN", "Invalid TOTP format", {
          userId,
          token: token.substring(0, 2) + "****",
        });
        return { success: false, error: "Invalid code format" };
      }

      // Check replay protection if userId provided
      if (userId) {
        const codeKey = `${userId}:${token}`;
        if (this.recentCodes.has(codeKey)) {
          log("WARN", "TOTP code already used", { userId });
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
        // Mark code as used if userId provided
        if (userId) {
          const codeKey = `${userId}:${token}`;
          this.recentCodes.set(codeKey, Date.now());
        }
        log("INFO", "TOTP verified successfully with secret", { userId });
        return { success: true };
      } else {
        log("WARN", "TOTP verification failed with secret", { userId });
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

  /**
   * Verify TOTP code against active devices
   * @param {string} userId - User ID
   * @param {string} token - The token to verify
   * @returns {Object} - Verification result
   */
  // async verifyTOTP(userId, token) {
  //   try {
  //     if (!/^\d{6}$/.test(token)) {
  //       log("WARN", "Invalid TOTP format", {
  //         userId,
  //         token: token.substring(0, 2) + "****",
  //       });
  //       return { success: false, deviceId: null };
  //     }

  //     const codeKey = `${userId}:${token}`;

  //     if (this.recentCodes.has(codeKey)) {
  //       log("WARN", "TOTP code already used", { userId });
  //       return { success: false, deviceId: null };
  //     }

  //     const devices = await databaseManager.query(
  //       `SELECT TwoFactorDeviceID, SecretData, DeviceInfo
  //        FROM appblddbo.TwoFactorDevice 
  //        WHERE TwoFactorUserID = ? AND Inactive IS NULL`,
  //       [userId]
  //     );

  //     if (devices.length === 0) {
  //       log("WARN", "No active devices found for user", { userId });
  //       return { success: false, deviceId: null };
  //     }

  //     // Track which device verified the token
  //     for (const device of devices) {
  //       const verified = speakeasy.totp.verify({
  //         secret: device.SecretData,
  //         encoding: "base32",
  //         token,
  //         window: CONFIG.totp.window,
  //         algorithm: CONFIG.totp.algorithm,
  //         digits: CONFIG.totp.digits,
  //         step: CONFIG.totp.step,
  //       });

  //       if (verified) {
  //         this.recentCodes.set(codeKey, Date.now());
  //         log("INFO", "TOTP verified successfully", {
  //           userId,
  //           deviceId: device.TwoFactorDeviceID,
  //           deviceInfo: device.DeviceInfo,
  //         });

  //         return {
  //           success: true,
  //           deviceId: device.TwoFactorDeviceID,
  //           deviceInfo: device.DeviceInfo,
  //         };
  //       }
  //     }

  //     log("WARN", "TOTP verification failed for all devices", {
  //       userId,
  //       devicesChecked: devices.length,
  //     });

  //     return { success: false, deviceId: null };
  //   } catch (error) {
  //     log("ERROR", "Error verifying TOTP", { userId, error: error.message });
  //     return { success: false, deviceId: null };
  //   }
  // }

  async verifyTOTP(userId, token) {
  try {
    // ✅ CONVERSION OBLIGATOIRE EN INTEGER
    const userIdInt = parseInt(userId);
    if (isNaN(userIdInt)) {
      log('ERROR', 'Invalid userId - not a number', { 
        userId, 
        type: typeof userId 
      });
      return { success: false, deviceId: null };
    }

    if (!/^\d{6}$/.test(token)) {
      log("WARN", "Invalid TOTP format", {
        userId: userIdInt,
        token: token.substring(0, 2) + "****",
      });
      return { success: false, deviceId: null };
    }

    const codeKey = `${userIdInt}:${token}`;

    if (this.recentCodes.has(codeKey)) {
      log("WARN", "TOTP code already used", { userId: userIdInt });
      return { success: false, deviceId: null };
    }

    // ✅ UTILISER L'INTEGER DANS LA REQUÊTE
    const devices = await databaseManager.query(
      `SELECT TwoFactorDeviceID, SecretData, DeviceInfo
       FROM appblddbo.TwoFactorDevice 
       WHERE TwoFactorUserID = ? AND Inactive IS NULL`,
      [userIdInt] // ← INTEGER au lieu de string
    );

    if (devices.length === 0) {
      log("WARN", "No active devices found for user", { userId: userIdInt });
      return { success: false, deviceId: null };
    }

    // Track which device verified the token
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
        log("INFO", "TOTP verified successfully", {
          userId: userIdInt,
          deviceId: device.TwoFactorDeviceID,
          deviceInfo: device.DeviceInfo,
        });

        return {
          success: true,
          deviceId: device.TwoFactorDeviceID,
          deviceInfo: device.DeviceInfo,
        };
      }
    }

    log("WARN", "TOTP verification failed for all devices", {
      userId: userIdInt,
      devicesChecked: devices.length,
    });

    return { success: false, deviceId: null };
  } catch (error) {
    log("ERROR", "Error verifying TOTP", { 
      userId: parseInt(userId), 
      error: error.message 
    });
    return { success: false, deviceId: null };
  }
}




  /**
   * Verify TOTP code during setup (before DB changes)
   * @param {string} sessionToken - Temporary setup session token
   * @param {string} token - The token to verify
   * @returns {Object} - Verification result
   */
  

  async verifySetupTOTP(sessionToken, token) {
    try {
      // Get pending setup data WITHOUT removing it
      const setup = this.getPendingSetup(sessionToken);
      if (!setup) {
        log("WARN", "No pending setup found for session token");
        return { success: false, error: "Setup session expired or invalid" };
      }

      // Check if setup is too old (optional security measure)
      const setupAge = Date.now() - setup.timestamp;
      const maxAge = 10 * 60 * 1000; // 10 minutes
      if (setupAge > maxAge) {
        this.pendingSetups.delete(sessionToken); // Remove expired setup
        log("WARN", "Setup session expired", { age: setupAge });
        return {
          success: false,
          error: "Setup session expired - please start over",
        };
      }

      // Verify the code with the temporary secret
      const verification = await this.verifyTOTPWithSecret(
        setup.totpSecret,
        token,
        null // No userId for setup verification
      );

      if (!verification.success) {
        return verification;
      }

      // Return setup data along with verification result
      return {
        success: true,
        setupData: setup,
      };
    } catch (error) {
      log("ERROR", "Error verifying setup TOTP", { error: error.message });
      return { success: false, error: "Verification failed" };
    }
  }

  /**
   * Clear user's recent codes
   * @param {string} userId - User ID
   */
  clearUserCodes(userId) {
    const keysToDelete = [];
    for (const key of this.recentCodes.keys()) {
      if (key.startsWith(`${userId}:`)) {
        keysToDelete.push(key);
      }
    }
    keysToDelete.forEach((key) => this.recentCodes.delete(key));
    log("DEBUG", `Cleared ${keysToDelete.length} codes for user`, { userId });
  }


  cleanupOldCodes() {
    const now = Date.now();
    const ttl = CONFIG.session.replayProtectionTTL;
    let cleanedCount = 0;

    // Clean up old TOTP codes
    for (const [key, timestamp] of this.recentCodes) {
      if (now - timestamp > ttl) {
        this.recentCodes.delete(key);
        cleanedCount++;
      }
    }

    // Clean up expired pending setups (older than 10 minutes)
    const setupTTL = 10 * 60 * 1000; // 10 minutes
    let expiredSetups = 0;
    for (const [sessionToken, setup] of this.pendingSetups) {
      if (now - setup.timestamp > setupTTL) {
        this.pendingSetups.delete(sessionToken);
        expiredSetups++;
      }
    }

    if (cleanedCount > 0 || expiredSetups > 0) {
      log(
        "DEBUG",
        `Cleaned up ${cleanedCount} old TOTP codes and ${expiredSetups} expired setups`
      );
    }
  }
}

/**
 * Clean up sessions for a specific device
 * @param {string} username - Username
 * @param {number} deviceId - Device ID to clean sessions for
 * @returns {Promise<number>} - Number of sessions cleaned
 */
// async function cleanupSessionsForDevice(username, deviceId) {
//   try {
//     const sessions = await databaseManager.query(
//       "SELECT SessionToken, SessionInfo FROM appblddbo.TwoFactorSession WHERE UserLogin = ?",
//       [username]
//     );

//     let cleanedCount = 0;

//     for (const session of sessions) {
//       try {
//         const sessionData = JSON.parse(session.SessionInfo);
        
//         if (sessionData.deviceId === deviceId) {
//           await databaseManager.query(
//             "DELETE FROM appblddbo.TwoFactorSession WHERE SessionToken = ?",
//             [session.SessionToken]
//           );
//           cleanedCount++;
//         }
//       } catch (parseError) {
//         log('WARN', `Could not parse session info for cleanup: ${session.SessionToken.substring(0, 8)}...`);
//       }
//     }

//     log('INFO', `Cleaned ${cleanedCount} sessions for device ${deviceId}`);
//     return cleanedCount;
//   } catch (error) {
//     log('ERROR', 'Error cleaning sessions for device', { username, deviceId, error: error.message });
//     throw error;
//   }
// }


// Initialize TOTP service

async function cleanupSessionsForDevice(username, deviceId) {
  try {
    // ✅ CONVERSION EN INTEGER
    const deviceIdInt = parseInt(deviceId);
    if (isNaN(deviceIdInt)) {
      log('ERROR', 'Invalid deviceId for cleanup', { deviceId, type: typeof deviceId });
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
        
        // ✅ COMPARAISON AVEC INTEGER
        if (parseInt(sessionData.deviceId) === deviceIdInt) {
          await databaseManager.query(
            "DELETE FROM appblddbo.TwoFactorSession WHERE SessionToken = ?",
            [session.SessionToken]
          );
          cleanedCount++;
        }
      } catch (parseError) {
        log('WARN', `Could not parse session info for cleanup: ${session.SessionToken.substring(0, 8)}...`);
      }
    }

    log('INFO', `Cleaned ${cleanedCount} sessions for device ${deviceIdInt}`);
    return cleanedCount;
  } catch (error) {
    log('ERROR', 'Error cleaning sessions for device', { 
      username, 
      deviceId: parseInt(deviceId), 
      error: error.message 
    });
    throw error;
  }
}





const totpService = new TOTPService();

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Enhanced password verification with boolean return
 * @param {Object} user - User object with username and password
 * @returns {Promise<Object>} - Authentication result
 */
async function verifyPasswordEnhanced(user) {
  try {
    const result = await databaseManager.query(
      "SELECT ResultCode, ResultMessage, DBPassword, ODataLocation, InactiveFlag FROM appblddbo.PRC_CheckGlobalPassword(?,?)",
      [user.username, user.password]
    );

    const authResult = result[0];
    return {
      success: authResult.ResultCode === 0,
      passwordType: authResult.DBPassword ? "login_password" : "global_password",
      message: authResult.ResultMessage,
      dbPassword: authResult.DBPassword,
    };
  } catch (error) {
    log('ERROR', 'Password verification error', { username: user.username, error: error.message });
    return { success: false, message: "Password verification failed" };
  }
}

/**
 * CRITICAL: Preserve original password before any 2FA operations
 * @param {string} username - The username
 * @returns {Promise<string>} - The original password hash
 */
async function preserveOriginalPassword(username) {
  try {
    const result = await databaseManager.query(
      'SELECT "Password" FROM appblddbo.Mitarbeiter WHERE "Login" = ?',
      [username]
    );

    if (result.length > 0) {
      const originalHash = result[0].Password;
      log('INFO', `Original password preserved for user: ${username}`);
      return originalHash;
    }

    throw new Error("User not found in Mitarbeiter table");
  } catch (error) {
    log('ERROR', 'Error preserving password', { username, error: error.message });
    throw error;
  }
}

/**
 * CRITICAL: Restore original password after 2FA operations
 * @param {string} username - The username
 * @param {string} originalPasswordHash - The original password hash
 * @returns {Promise<boolean>} - True if restore was successful
 */
async function restoreOriginalPassword(username, originalPasswordHash) {
  try {
    await databaseManager.query(
      'UPDATE appblddbo.Mitarbeiter SET "Password" = ? WHERE "Login" = ?',
      [originalPasswordHash, username]
    );

    log('INFO', `Original password restored for user: ${username}`);
    return true;
  } catch (error) {
    log('ERROR', 'Error restoring password', { username, error: error.message });
    return false;
  }
}

/**
 * Create or get TwoFactorUser with proper password handling
 * @param {string} username - Username
 * @param {string} password - Password
 * @returns {Promise<Object>} - User object
 */
async function createOrGetTwoFactorUser(username, password) {
  try {
    // Check if user already exists
    const existingUser = await databaseManager.query(
      "SELECT * FROM appblddbo.TwoFactorUser WHERE LoginName = ?",
      [username]
    );

    if (existingUser.length > 0) {
      log('INFO', `Existing 2FA user found: ${username}`);
      return existingUser[0];
    }

    // Create new user with FCT_HashPassword
    await databaseManager.query(
      "INSERT INTO appblddbo.TwoFactorUser (LoginName, Disable2FA, LoginPassword) SELECT ?, 0, appblddbo.FCT_HashPassword(?)",
      [username, password]
    );

    const newUser = await databaseManager.query(
      "SELECT * FROM appblddbo.TwoFactorUser WHERE LoginName = ?",
      [username]
    );

    if (newUser.length === 1) {
      log('INFO', `New 2FA user created: ${username}`);
      return newUser[0];
    } else {
      throw new Error("User creation unsuccessful");
    }
  } catch (error) {
    log('ERROR', 'Error creating/getting 2FA user', { username, error: error.message });
    throw error;
  }
}

/**
 * Add TOTP Device with proper secret
 * @param {number} userId - User ID
 * @param {string} deviceInfo - Device information
 * @param {string} secret - TOTP secret
 * @returns {Promise<number>} - Device ID
 */
// async function addTwoFactorDevice(userId, deviceInfo, secret) {
//   try {
//     // Use parameterized query to handle UTF-8 characters properly
//     await databaseManager.query(
//       "INSERT INTO appblddbo.TwoFactorDevice (TwoFactorUserID, AuthMethod, DeviceInfo, SecretData, Inactive) VALUES (?, ?, ?, ?, ?)",
//       [userId, "TOTP", deviceInfo, secret, null]
//     );

//     const deviceQuery = await databaseManager.query(
//       "SELECT TwoFactorDeviceID FROM appblddbo.TwoFactorDevice WHERE TwoFactorUserID = ? AND SecretData = ?",
//       [userId, secret]
//     );

//     if (deviceQuery.length > 0) {
//       log('INFO', `New device created with ID: ${deviceQuery[0].TwoFactorDeviceID}`, { deviceInfo });
//       return deviceQuery[0].TwoFactorDeviceID;
//     } else {
//       throw new Error("Device creation failed");
//     }
//   } catch (error) {
//     log('ERROR', 'Error adding device', { userId, deviceInfo, error: error.message });
//     throw error;
//   }
// }

async function addTwoFactorDevice(userId, deviceInfo, secret) {
  try {
    // ✅ CONVERSION EN INTEGER
    const userIdInt = parseInt(userId);
    if (isNaN(userIdInt)) {
      throw new Error(`Invalid userId: ${userId} is not a number`);
    }

    // Use parameterized query to handle UTF-8 characters properly
    await databaseManager.query(
      "INSERT INTO appblddbo.TwoFactorDevice (TwoFactorUserID, AuthMethod, DeviceInfo, SecretData, Inactive) VALUES (?, ?, ?, ?, ?)",
      [userIdInt, "TOTP", deviceInfo, secret, null] // ← INTEGER
    );

    const deviceQuery = await databaseManager.query(
      "SELECT TwoFactorDeviceID FROM appblddbo.TwoFactorDevice WHERE TwoFactorUserID = ? AND SecretData = ?",
      [userIdInt, secret] // ← INTEGER
    );

    if (deviceQuery.length > 0) {
      log('INFO', `New device created with ID: ${deviceQuery[0].TwoFactorDeviceID}`, { 
        deviceInfo,
        userId: userIdInt 
      });
      return deviceQuery[0].TwoFactorDeviceID;
    } else {
      throw new Error("Device creation failed");
    }
  } catch (error) {
    log('ERROR', 'Error adding device', { 
      userId: parseInt(userId), 
      deviceInfo, 
      error: error.message 
    });
    throw error;
  }
}

/**
 * Format stored procedure results
 */
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

/**
 * Mask sensitive data for logging
 */
function maskSensitiveData(data) {
  if (!data || data.length < 8) return "***MASKED***";
  return data.substring(0, 4) + "***" + data.substring(data.length - 4);
}

/**
 * Enhanced device detection with UTF-8 support
 * @param {string} userAgent - User agent string
 * @param {string} fallback - Fallback device name
 * @returns {string} - Detected device name
 */

function detectDeviceFromUserAgent(userAgent, fallback = "Unknown Device") {
  if (!userAgent) return fallback;
  
  const ua = userAgent.toLowerCase();
  
  const browserVersionMatch = ua.match(/(chrome|firefox|safari|edge|opera)[\/\s]([\d.]+)/i);
  const osMatch = ua.match(/(windows nt|mac os x|linux|android|ios) ([^;)]+)/i);
  
  const browserName = 
    ua.includes('chrome') ? 'Chrome' :
    ua.includes('firefox') ? 'Firefox' : 
    ua.includes('safari') ? 'Safari' : 
    ua.includes('edge') ? 'Edge' : 'Browser';
  
  const osName = 
    ua.includes('windows') ? 'Windows' :
    ua.includes('mac') ? 'macOS' :
    ua.includes('linux') ? 'Linux' :
    ua.includes('android') ? 'Android' :
    ua.includes('ios') ? 'iOS' : 'Unknown OS';

  
  const uniqueId = Math.random().toString(36).substring(2, 6).toUpperCase();
  
  return `${browserName} ${browserVersionMatch?.[2] || ''} on ${osName} ${osMatch?.[2] || ''} (${uniqueId})`;
}

/**
 * Update sessions with new device info
 * @param {string} username - Username
 * @param {string} oldDeviceInfo - Old device name
 * @param {string} newDeviceInfo - New device name
 */
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
        log('WARN', `Could not parse session info for token: ${session.SessionToken.substring(0, 8)}...`);
      }
    }

    log('INFO', `Updated device info in ${updatedCount} sessions`, { username, oldDeviceInfo, newDeviceInfo });
    return updatedCount;
  } catch (error) {
    log('ERROR', 'Error updating sessions device info', { username, error: error.message });
    throw error;
  }
}

// =============================================================================
// API ROUTES
// =============================================================================

// API Information
router.get("/", (req, res) => {
  res.json({
    success: true,
    message: "LeadSuccess Enhanced 2FA API v4.2 - Production Ready",
    version: "4.2.0",
    timestamp: new Date().toISOString(),
    features: [
      "Full UTF-8 character support for international users",
      "Enhanced session tracking with device synchronization",
      "Professional logging and error handling",
      "Secure password preservation during 2FA lifecycle",
      "Graceful 2FA deactivation with automatic cleanup",
    ],
    endpoints: {
      system: {
        health: "GET /health",
        tables: "GET /tables",
        testDb: "GET /test-db",
      },
      authentication: {
        login: "POST /auth/login",
        verify2fa: "POST /auth/verify-2fa",
        setup2fa: "POST /auth/setup-2fa",
        status: "POST /auth/status",
        disable2fa: "POST /auth/disable-2fa",
      },
      sessions: {
        list: "GET /sessions/list/:username",
        logout: "POST /sessions/logout",
        logoutAll: "POST /sessions/logout-all",
      },
      devices: {
        list: "GET /devices/list/:username",
        add: "POST /devices/add",
        rename: "PUT /devices/rename/:deviceId",
        remove: "DELETE /devices/remove/:deviceId",
      },
    },
  });
});

// System Health Check
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
    log('ERROR', 'Health check error', { error: error.message });
    res.status(503).json({
      success: false,
      message: "Health check failed",
      error: error.message,
    });
  }
});

// Database Tables Overview
router.get("/tables", async (req, res) => {
  try {
    if (!databaseManager.isConnected()) {
      return res.status(503).json({
        success: false,
        message: "Database not connected",
      });
    }

    const users = await databaseManager.query(
      "SELECT * FROM appblddbo.TwoFactorUser"
    );
    const devices = await databaseManager.query(
      "SELECT * FROM appblddbo.TwoFactorDevice WHERE Inactive IS NULL"
    );
    const sessions = await databaseManager.query(
      "SELECT SessionToken, UserLogin, LastUsedTS FROM appblddbo.TwoFactorSession"
    );

    res.json({
      success: true,
      message: "Database tables overview",
      timestamp: new Date().toISOString(),
      data: {
        users: {
          count: users.length,
          data: users.map((user) => ({
            ...user,
            LoginPassword: user.LoginPassword ? "HASH_STORED" : null,
            DBPassword: user.DBPassword ? maskSensitiveData(user.DBPassword) : null,
          })),
        },
        devices: {
          count: devices.length,
          data: devices,
        },
        sessions: {
          count: sessions.length,
          data: sessions.map((session) => ({
            ...session,
            SessionToken: session.SessionToken ? session.SessionToken.substring(0, 8) + "..." : null,
          })),
        },
      },
    });
  } catch (error) {
    log('ERROR', 'Error getting tables', { error: error.message });
    res.status(500).json({
      success: false,
      message: "Error getting database tables",
      error: error.message,
    });
  }
});

// Database test endpoint
router.get('/test-db', async (req, res) => {
    try {
        console.log('🗃️ Database test requested');
        const result = await databaseManager.query('SELECT 1 as test');
        
        res.json({
            success: true,
            message: 'Database test successful',
            result: result,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('❌ Database test error:', error);
        res.status(500).json({
            success: false,
            message: 'Database test failed',
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// =============================================================================
// AUTHENTICATION ROUTE
// =============================================================================

// User Login - Enhanced with device info in session
// router.post("/auth/login", async (req, res) => {
//   try {
//     const { username, password } = req.body;

//     if (!username || !password) {
//       return res.status(400).json({
//         success: false,
//         message: "Username and password required",
//       });
//     }

//     await databaseManager.query("BEGIN TRANSACTION");

//     // Verify password
//     const isValidPassword = await verifyPasswordEnhanced({ username, password });

//     if (!isValidPassword.success) {
//       await databaseManager.query("ROLLBACK TRANSACTION");
//       return res.status(401).json({
//         success: false,
//         message: "Invalid credentials",
//       });
//     }

//     // Preserve original password BEFORE any operations
//     const originalPasswordHash = await preserveOriginalPassword(username);

//     // Check 2FA status
//     const userQuery = await databaseManager.query(
//       "SELECT * FROM appblddbo.TwoFactorUser WHERE LoginName = ?",
//       [username]
//     );

//     const requires2FA = userQuery.length > 0 && !userQuery[0].Disable2FA;

//     // Detect device info from user agent
//     const deviceInfo = detectDeviceFromUserAgent(req.get("User-Agent"), "Web Browser");

//     // Create session with device info
//     const sessionToken = uuidv4();
//     const sessionData = {
//       username,
//       userId: userQuery[0]?.TwoFactorUserID,
//       originalPassword: password,
//       originalPasswordHash,
//       loginTime: new Date().toISOString(),
//       requires2FA,
//       ipAddress: req.ip,
//       userAgent: req.get("User-Agent"),
//       deviceInfo: deviceInfo,
//       deviceId: null,
//       sessionType: requires2FA ? "pending_2fa" : "authenticated",
//     };

//     await databaseManager.query(
//       "INSERT INTO appblddbo.TwoFactorSession (SessionToken, UserLogin, LastUsedTS, SessionInfo) VALUES (?,?,CURRENT_TIMESTAMP,?)",
//       [sessionToken, username, JSON.stringify(sessionData)]
//     );

//     await databaseManager.query("COMMIT TRANSACTION");

//     log('INFO', `Login successful`, { username, requires2FA, deviceInfo });

//     res.json({
//       success: true,
//       message: "Login successful",
//       sessionToken,
//       user: {
//         username,
//         id: userQuery[0]?.TwoFactorUserID,
//         requires2FA,
//         originalPasswordPreserved: true,
//       },
//       nextStep: requires2FA ? "verify_2fa" : "authenticated",
//     });
//   } catch (error) {
//     await databaseManager.query("ROLLBACK TRANSACTION");
//     log('ERROR', 'Login error', { username: req.body.username, error: error.message });
//     res.status(500).json({
//       success: false,
//       message: "Internal server error",
//       error: error.message,
//     });
//   }
// });

router.post("/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password required",
      });
    }

    await databaseManager.query("BEGIN TRANSACTION");

    // Verify password
    const isValidPassword = await verifyPasswordEnhanced({ username, password });

    if (!isValidPassword.success) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Preserve original password BEFORE any operations
    const originalPasswordHash = await preserveOriginalPassword(username);

    // Check 2FA status
    const userQuery = await databaseManager.query(
      "SELECT * FROM appblddbo.TwoFactorUser WHERE LoginName = ?",
      [username]
    );

    const requires2FA = userQuery.length > 0 && !userQuery[0].Disable2FA;

    // ✅ CONVERSION EN INTEGER SI UTILISATEUR EXISTE
    let userIdInt = null;
    if (userQuery.length > 0) {
      userIdInt = parseInt(userQuery[0].TwoFactorUserID);
      if (isNaN(userIdInt)) {
        await databaseManager.query("ROLLBACK TRANSACTION");
        throw new Error(`Invalid TwoFactorUserID: ${userQuery[0].TwoFactorUserID}`);
      }
    }

    // Detect device info from user agent
    const deviceInfo = detectDeviceFromUserAgent(req.get("User-Agent"), "Web Browser");

    // Create session with device info
    const sessionToken = uuidv4();
    const sessionData = {
      username,
      userId: userIdInt, // ✅ INTEGER OU NULL
      originalPassword: password,
      originalPasswordHash,
      loginTime: new Date().toISOString(),
      requires2FA,
      ipAddress: req.ip,
      userAgent: req.get("User-Agent"),
      deviceInfo: deviceInfo,
      deviceId: null,
      sessionType: requires2FA ? "pending_2fa" : "authenticated",
    };

    await databaseManager.query(
      "INSERT INTO appblddbo.TwoFactorSession (SessionToken, UserLogin, LastUsedTS, SessionInfo) VALUES (?,?,CURRENT_TIMESTAMP,?)",
      [sessionToken, username, JSON.stringify(sessionData)]
    );

    await databaseManager.query("COMMIT TRANSACTION");

    log('INFO', `Login successful`, { username, requires2FA, deviceInfo, userId: userIdInt });

    res.json({
      success: true,
      message: "Login successful",
      sessionToken,
      user: {
        username,
        id: userIdInt,
        requires2FA,
        originalPasswordPreserved: true,
      },
      nextStep: requires2FA ? "verify_2fa" : "authenticated",
    });
  } catch (error) {
    await databaseManager.query("ROLLBACK TRANSACTION");
    log('ERROR', 'Login error', { username: req.body.username, error: error.message });
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
});


// Setup 2FA - Enhanced with proper cleanup
router.post("/auth/setup-2fa", async (req, res) => {
  try {
    const { username, password, deviceInfo = "Web Browser" } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password required",
      });
    }

    // STEP 1: Verify credentials
    const isValidPassword = await verifyPasswordEnhanced({ username, password });
    if (!isValidPassword.success) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // STEP 2: Generate TOTP secret (but don't save to DB yet)
    const totpData = await totpService.generateTOTP(username);

    // STEP 3: Enhanced device info detection
    const enhancedDeviceInfo = detectDeviceFromUserAgent(req.get("User-Agent"), deviceInfo);

    // STEP 4: Create temporary session token for this setup
    const sessionToken = uuidv4();

    // STEP 5: Store the setup data temporarily (NOT in database)
    const setupData = {
      username,
      password,
      deviceInfo: enhancedDeviceInfo,
      totpSecret: totpData.secret,
      ipAddress: req.ip,
      userAgent: req.get("User-Agent"),
    };

    totpService.storePendingSetup(sessionToken, setupData);

    log('INFO', `2FA setup initiated (QR code generated)`, { username, deviceInfo: enhancedDeviceInfo });

    // STEP 6: Return QR code and session token for verification
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
        "1. Open your authenticator app (Google Authenticator, Authy, etc.)",
        "2. Scan the QR code or enter the secret manually",
        "3. Enter the 6-digit code below to verify",
        "4. Device will be added to your account only after successful verification",
      ],
      note: "No database changes made yet - verification required"
    });
  } catch (error) {
    log('ERROR', '2FA setup error', { username: req.body.username, error: error.message });
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
});

// Verify 2FA - Enhanced with device info and session management
// router.post("/auth/verify-2fa", async (req, res) => {
//   try {
//     const { sessionToken, totpCode } = req.body;

//     if (!sessionToken || !totpCode) {
//       return res.status(400).json({
//         success: false,
//         message: "Session token and TOTP code required",
//       });
//     }

//     // CASE 1: Check if this is a new 2FA setup verification
//     const pendingSetup = totpService.getPendingSetup(sessionToken);
    
//     if (pendingSetup) {
//       // This is a NEW 2FA setup verification
//       log('INFO', 'Processing NEW 2FA setup verification', { username: pendingSetup.username });
      
//       // Verify the TOTP code with the temporary secret
//       const verification = await totpService.verifyTOTPWithSecret(
//         pendingSetup.totpSecret,
//         totpCode
//       );

//       if (!verification.success) {
//         // DO NOT remove pending setup on failure - allow retry
//         log('WARN', 'TOTP verification failed for new setup', { 
//           username: pendingSetup.username,
//           error: verification.error 
//         });
        
//         return res.status(401).json({
//           success: false,
//           message: verification.error || "Invalid TOTP code",
//         });
//       }

//       // TOTP code is valid - NOW we can modify the database
//       await databaseManager.query("BEGIN TRANSACTION");

//       try {
//         // Preserve original password before any changes
//         const originalPasswordHash = await preserveOriginalPassword(pendingSetup.username);

//         // Create or get 2FA user (only now, after successful verification)
//         const user = await createOrGetTwoFactorUser(pendingSetup.username, pendingSetup.password);

//         // Check if this is first setup
//         const existingDevices = await databaseManager.query(
//           "SELECT COUNT(*) as count FROM appblddbo.TwoFactorDevice WHERE TwoFactorUserID = ? AND Inactive IS NULL",
//           [user.TwoFactorUserID]
//         );

//         const isFirstSetup = existingDevices[0].count === 0;

//         if (isFirstSetup) {
//           // Clean up old inactive devices
//           await databaseManager.query(
//             "DELETE FROM appblddbo.TwoFactorDevice WHERE TwoFactorUserID = ?",
//             [user.TwoFactorUserID]
//           );
//         }

//         // Create the device (only now, after successful verification)
//         const deviceId = await addTwoFactorDevice(
//           user.TwoFactorUserID,
//           pendingSetup.deviceInfo,
//           pendingSetup.totpSecret
//         );

//         // Enable 2FA
//         await databaseManager.query(
//           "UPDATE appblddbo.TwoFactorUser SET Disable2FA = 0 WHERE TwoFactorUserID = ?",
//           [user.TwoFactorUserID]
//         );

//         // Create authenticated session
//         const newSessionToken = uuidv4();
//         const sessionData = {
//           username: pendingSetup.username,
//           userId: user.TwoFactorUserID,
//           originalPasswordHash,
//           loginTime: new Date().toISOString(),
//           requires2FA: true,
//           authenticated2FA: true,
//           ipAddress: pendingSetup.ipAddress,
//           userAgent: pendingSetup.userAgent,
//           deviceInfo: pendingSetup.deviceInfo,
//           deviceId: deviceId,
//         };

//         await databaseManager.query(
//           "INSERT INTO appblddbo.TwoFactorSession (SessionToken, UserLogin, LastUsedTS, SessionInfo) VALUES (?,?,CURRENT_TIMESTAMP,?)",
//           [newSessionToken, pendingSetup.username, JSON.stringify(sessionData)]
//         );

//         // Activate 2FA and generate DB password
//         const activationResult = await databaseManager.query(
//           "SELECT * FROM appblddbo.PRC_ActivateTwoFactor(?)",
//           [pendingSetup.username]
//         );

//         const activation = formatProcedureResult(activationResult, "PRC_ActivateTwoFactor");
//         const dbPassword = activation.success ? activation.data?.DBPassword : null;

//         // Restore original password
//         await restoreOriginalPassword(pendingSetup.username, originalPasswordHash);

//         await databaseManager.query("COMMIT TRANSACTION");

//         // NOW remove the pending setup after successful completion
//         totpService.removePendingSetup(sessionToken);

//         log("INFO", `2FA setup completed successfully`, {
//           username: pendingSetup.username,
//           deviceId,
//           isFirstSetup,
//         });

//         return res.json({
//           success: true,
//           message: "2FA setup completed successfully",
//           sessionToken: newSessionToken,
//           user: {
//             username: pendingSetup.username,
//             id: user.TwoFactorUserID,
//             originalPasswordPreserved: true,
//           },
//           dbPassword: dbPassword,
//           isFirstSetup: isFirstSetup,
//         });

//       } catch (error) {
//         await databaseManager.query("ROLLBACK TRANSACTION");
//         log("ERROR", "Error during 2FA setup", {
//           error: error.message,
//           stack: error.stack,
//         });
//         throw error;
//       }
//     } else {
//       // CASE 2: Regular 2FA verification for existing user
//       log('INFO', 'Processing EXISTING 2FA verification');
      
//       const sessionQuery = await databaseManager.query(
//         "SELECT * FROM appblddbo.TwoFactorSession WHERE SessionToken = ?",
//         [sessionToken]
//       );

//       if (sessionQuery.length === 0) {
//         return res.status(401).json({
//           success: false,
//           message: "Invalid or expired session",
//         });
//       }

//       const sessionData = JSON.parse(sessionQuery[0].SessionInfo);
//       const { username, originalPasswordHash, userId } = sessionData;

//       const verificationResult = await totpService.verifyTOTP(userId, totpCode);

//       if (!verificationResult.success) {
//         return res.status(401).json({
//           success: false,
//           message: "Invalid TOTP code",
//         });
//       }

//       // Update session as authenticated
//       const updatedSessionData = {
//         ...sessionData,
//         authenticated2FA: true,
//         authenticationTime: new Date().toISOString(),
//         deviceId: verificationResult.deviceId,
//         verifiedDeviceInfo: verificationResult.deviceInfo,
//       };

//       await databaseManager.query(
//         "UPDATE appblddbo.TwoFactorSession SET LastUsedTS = CURRENT_TIMESTAMP, SessionInfo = ? WHERE SessionToken = ?",
//         [JSON.stringify(updatedSessionData), sessionToken]
//       );

//       // Activate 2FA for user
//       const activationResult = await databaseManager.query(
//         "SELECT * FROM appblddbo.PRC_ActivateTwoFactor(?)",
//         [username]
//       );

//       const activation = formatProcedureResult(activationResult, "PRC_ActivateTwoFactor");
//       const dbPassword = activation.success ? activation.data?.DBPassword : null;

//       if (activation.success && originalPasswordHash) {
//         await restoreOriginalPassword(username, originalPasswordHash);
//       }

//       log('INFO', `Existing 2FA verification successful`, { username });

//       return res.json({
//         success: true,
//         message: "2FA verification successful",
//         sessionToken,
//         user: {
//           username,
//           id: userId,
//           originalPasswordPreserved: true,
//         },
//         dbPassword: dbPassword,
//       });
//     }

//   } catch (error) {
//     if (databaseManager.isConnected()) {
//       await databaseManager.query("ROLLBACK TRANSACTION");
//     }
    
//     res.status(500).json({
//       success: false,
//       message: "Internal server error",
//       error: error.message,
//     });
//   }
// });

router.post("/auth/verify-2fa", async (req, res) => {
  try {
    const { sessionToken, totpCode } = req.body;

    if (!sessionToken || !totpCode) {
      return res.status(400).json({
        success: false,
        message: "Session token and TOTP code required",
      });
    }

    // CASE 1: Check if this is a new 2FA setup verification
    const pendingSetup = totpService.getPendingSetup(sessionToken);
    
    if (pendingSetup) {
      // This is a NEW 2FA setup verification
      log('INFO', 'Processing NEW 2FA setup verification', { username: pendingSetup.username });
      
      // Verify the TOTP code with the temporary secret
      const verification = await totpService.verifyTOTPWithSecret(
        pendingSetup.totpSecret,
        totpCode
      );

      if (!verification.success) {
        log('WARN', 'TOTP verification failed for new setup', { 
          username: pendingSetup.username,
          error: verification.error 
        });
        
        return res.status(401).json({
          success: false,
          message: verification.error || "Invalid TOTP code",
        });
      }

      // TOTP code is valid - NOW we can modify the database
      await databaseManager.query("BEGIN TRANSACTION");

      try {
        // Preserve original password before any changes
        const originalPasswordHash = await preserveOriginalPassword(pendingSetup.username);

        // Create or get 2FA user (only now, after successful verification)
        const user = await createOrGetTwoFactorUser(pendingSetup.username, pendingSetup.password);

        // ✅ CONVERSION EN INTEGER
        const userIdInt = parseInt(user.TwoFactorUserID);
        if (isNaN(userIdInt)) {
          throw new Error(`Invalid TwoFactorUserID: ${user.TwoFactorUserID}`);
        }

        // Check if this is first setup
        const existingDevices = await databaseManager.query(
          "SELECT COUNT(*) as count FROM appblddbo.TwoFactorDevice WHERE TwoFactorUserID = ? AND Inactive IS NULL",
          [userIdInt] // ← INTEGER
        );

        const isFirstSetup = existingDevices[0].count === 0;

        if (isFirstSetup) {
          // Clean up old inactive devices
          await databaseManager.query(
            "DELETE FROM appblddbo.TwoFactorDevice WHERE TwoFactorUserID = ?",
            [userIdInt] // ← INTEGER
          );
        }

        // Create the device (only now, after successful verification)
        const deviceId = await addTwoFactorDevice(
          userIdInt, // ← INTEGER
          pendingSetup.deviceInfo,
          pendingSetup.totpSecret
        );

        // Enable 2FA
        await databaseManager.query(
          "UPDATE appblddbo.TwoFactorUser SET Disable2FA = 0 WHERE TwoFactorUserID = ?",
          [userIdInt] // ← INTEGER
        );

        // Create authenticated session
        const newSessionToken = uuidv4();
        const sessionData = {
          username: pendingSetup.username,
          userId: userIdInt, // ← INTEGER
          originalPasswordHash,
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

        // Activate 2FA and generate DB password
        const activationResult = await databaseManager.query(
          "SELECT * FROM appblddbo.PRC_ActivateTwoFactor(?)",
          [pendingSetup.username]
        );

        const activation = formatProcedureResult(activationResult, "PRC_ActivateTwoFactor");
        const dbPassword = activation.success ? activation.data?.DBPassword : null;

        // Restore original password
        await restoreOriginalPassword(pendingSetup.username, originalPasswordHash);

        await databaseManager.query("COMMIT TRANSACTION");

        // NOW remove the pending setup after successful completion
        totpService.removePendingSetup(sessionToken);

        log("INFO", `2FA setup completed successfully`, {
          username: pendingSetup.username,
          deviceId,
          isFirstSetup,
        });

        return res.json({
          success: true,
          message: "2FA setup completed successfully",
          sessionToken: newSessionToken,
          user: {
            username: pendingSetup.username,
            id: userIdInt,
            originalPasswordPreserved: true,
          },
          dbPassword: dbPassword,
          isFirstSetup: isFirstSetup,
        });

      } catch (error) {
        await databaseManager.query("ROLLBACK TRANSACTION");
        log("ERROR", "Error during 2FA setup", {
          error: error.message,
          stack: error.stack,
        });
        throw error;
      }
    } else {
      // CASE 2: Regular 2FA verification for existing user
      log('INFO', 'Processing EXISTING 2FA verification');
      
      const sessionQuery = await databaseManager.query(
        "SELECT * FROM appblddbo.TwoFactorSession WHERE SessionToken = ?",
        [sessionToken]
      );

      if (sessionQuery.length === 0) {
        return res.status(401).json({
          success: false,
          message: "Invalid or expired session",
        });
      }

      const sessionData = JSON.parse(sessionQuery[0].SessionInfo);
      const { username, originalPasswordHash, userId } = sessionData;

      // ✅ VALIDATION ET CONVERSION
      const userIdInt = userId ? parseInt(userId) : null;
      if (userId && isNaN(userIdInt)) {
        log('ERROR', 'Invalid userId in session', { 
          userId, 
          type: typeof userId,
          username 
        });
        return res.status(400).json({
          success: false,
          message: "Invalid session data - userId not numeric"
        });
      }

      if (!userIdInt) {
        return res.status(400).json({
          success: false,
          message: "User does not have 2FA enabled",
        });
      }



      log('DEBUG', 'Session userId validation', {
        originalUserId: userId,
        convertedUserId: userIdInt,
        username: username
      });

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
        userId: userIdInt, // ← Assurer que c'est un INTEGER
        authenticated2FA: true,
        authenticationTime: new Date().toISOString(),
        deviceId: verificationResult.deviceId,
        verifiedDeviceInfo: verificationResult.deviceInfo,
      };

      await databaseManager.query(
        "UPDATE appblddbo.TwoFactorSession SET LastUsedTS = CURRENT_TIMESTAMP, SessionInfo = ? WHERE SessionToken = ?",
        [JSON.stringify(updatedSessionData), sessionToken]
      );

      // Activate 2FA for user
      const activationResult = await databaseManager.query(
        "SELECT * FROM appblddbo.PRC_ActivateTwoFactor(?)",
        [username]
      );

      const activation = formatProcedureResult(activationResult, "PRC_ActivateTwoFactor");
      const dbPassword = activation.success ? activation.data?.DBPassword : null;

      if (activation.success && originalPasswordHash) {
        await restoreOriginalPassword(username, originalPasswordHash);
      }

      log('INFO', `Existing 2FA verification successful`, { username });

      return res.json({
        success: true,
        message: "2FA verification successful",
        sessionToken,
        user: {
          username,
          id: userIdInt,
          originalPasswordPreserved: true,
        },
        dbPassword: dbPassword,
      });
    }

  } catch (error) {
    if (databaseManager.isConnected()) {
      await databaseManager.query("ROLLBACK TRANSACTION");
    }
    
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
});




// Get user status
// router.post("/auth/status", async (req, res) => {
//   try {
//     const { username } = req.body;

//     if (!username) {
//       return res.status(400).json({
//         success: false,
//         message: "Username required",
//       });
//     }

//     const userQuery = await databaseManager.query(
//       "SELECT * FROM appblddbo.TwoFactorUser WHERE LoginName = ?",
//       [username]
//     );

//     if (userQuery.length === 0) {
//       return res.json({
//         success: true,
//         message: "User status retrieved",
//         username,
//         exists: false,
//         is2FAEnabled: false,
//       });
//     }

//     const user = userQuery[0];

//     // Get devices (only active ones)
//     const deviceQuery = await databaseManager.query(
//       "SELECT * FROM appblddbo.TwoFactorDevice WHERE TwoFactorUserID = ? AND Inactive IS NULL",
//       [user.TwoFactorUserID]
//     );

//     // Get sessions
//     const sessionQuery = await databaseManager.query(
//       "SELECT COUNT(*) as count FROM appblddbo.TwoFactorSession WHERE UserLogin = ?",
//       [username]
//     );

//     res.json({
//       success: true,
//       message: "User status retrieved",
//       username,
//       exists: true,
//       id: user.TwoFactorUserID,
//       is2FAEnabled: !user.Disable2FA,
//       totalDevices: deviceQuery.length,
//       activeDevices: deviceQuery.filter((d) => !d.Inactive).length,
//       activeSessions: sessionQuery[0].count,
//       hasDBPassword: !!user.DBPassword,
//       originalPasswordPreserved: true,
//     });
//   } catch (error) {
//     log('ERROR', 'Status check error', { username: req.body.username, error: error.message });
//     res.status(500).json({
//       success: false,
//       message: "Internal server error",
//       error: error.message,
//     });
//   }
// });

router.post("/auth/status", async (req, res) => {
  try {
    const { username } = req.body;

    if (!username) {
      return res.status(400).json({
        success: false,
        message: "Username required",
      });
    }

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

    // ✅ CONVERSION EN INTEGER
    const userIdInt = parseInt(user.TwoFactorUserID);
    if (isNaN(userIdInt)) {
      throw new Error(`Invalid TwoFactorUserID: ${user.TwoFactorUserID}`);
    }

    // Get devices (only active ones)
    const deviceQuery = await databaseManager.query(
      "SELECT * FROM appblddbo.TwoFactorDevice WHERE TwoFactorUserID = ? AND Inactive IS NULL",
      [userIdInt] // ← INTEGER
    );

    // Get sessions
    const sessionQuery = await databaseManager.query(
      "SELECT COUNT(*) as count FROM appblddbo.TwoFactorSession WHERE UserLogin = ?",
      [username]
    );

    res.json({
      success: true,
      message: "User status retrieved",
      username,
      exists: true,
      id: userIdInt,
      is2FAEnabled: !user.Disable2FA,
      totalDevices: deviceQuery.length,
      activeDevices: deviceQuery.filter((d) => !d.Inactive).length,
      activeSessions: sessionQuery[0].count,
      hasDBPassword: !!user.DBPassword,
      originalPasswordPreserved: true,
    });
  } catch (error) {
    log('ERROR', 'Status check error', { username: req.body.username, error: error.message });
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
});






// Disable 2FA for User - Complete cleanup
// router.post("/auth/disable-2fa", async (req, res) => {
//   try {
//     const { username, password } = req.body;

//     if (!username || !password) {
//       return res.status(400).json({
//         success: false,
//         message: "Username and password required",
//       });
//     }

//     await databaseManager.query("BEGIN TRANSACTION");

//     // Verify credentials
//     const isValidPassword = await verifyPasswordEnhanced({ username, password });
//     if (!isValidPassword.success) {
//       await databaseManager.query("ROLLBACK TRANSACTION");
//       return res.status(401).json({
//         success: false,
//         message: "Invalid credentials",
//       });
//     }

//     // Check if user exists in 2FA system
//     const userQuery = await databaseManager.query(
//       "SELECT * FROM appblddbo.TwoFactorUser WHERE LoginName = ?",
//       [username]
//     );

//     if (userQuery.length === 0) {
//       await databaseManager.query("ROLLBACK TRANSACTION");
//       return res.status(404).json({
//         success: false,
//         message: "User not found in 2FA system - 2FA may already be disabled",
//       });
//     }

//     const user = userQuery[0];

//     // Preserve original password before any changes
//     const originalPasswordHash = await preserveOriginalPassword(username);

//     // Disable 2FA completely
//     await databaseManager.query(
//       "UPDATE appblddbo.TwoFactorUser SET Disable2FA = 1, DBPassword = NULL WHERE TwoFactorUserID = ?",
//       [user.TwoFactorUserID]
//     );

//     // Deactivate all devices
//     await databaseManager.query(
//       "UPDATE appblddbo.TwoFactorDevice SET Inactive = 1 WHERE TwoFactorUserID = ?",
//       [user.TwoFactorUserID]
//     );

//     // Clear all sessions
//     await databaseManager.query(
//       "DELETE FROM appblddbo.TwoFactorSession WHERE UserLogin = ?",
//       [username]
//     );

//     // CRITICAL: Restore original password
//     const restored = await restoreOriginalPassword(username, originalPasswordHash);
//     if (!restored) {
//       await databaseManager.query("ROLLBACK TRANSACTION");
//       throw new Error("Failed to restore original password");
//     }

//     // Verify that password works
//     const finalPasswordTest = await verifyPasswordEnhanced({ username, password });

//     await databaseManager.query("COMMIT TRANSACTION");

//     log('INFO', `2FA disabled successfully for: ${username}`);

//     res.json({
//       success: true,
//       message: "2FA disabled successfully",
//       user: {
//         username: username,
//         id: user.TwoFactorUserID,
//         is2FAEnabled: false,
//         originalPasswordPreserved: true,
//         originalPasswordWorking: finalPasswordTest.success,
//       },
//       actions: [
//         "Set Disable2FA to 1",
//         "Cleared DBPassword",
//         "Deactivated all TOTP devices",
//         "Cleared active sessions",
//         "Restored original password",
//       ],
//       note: "User can now login with original password only. Transaction committed successfully.",
//     });
//   } catch (error) {
//     await databaseManager.query("ROLLBACK TRANSACTION");
//     log('ERROR', 'Error disabling 2FA', { username: req.body.username, error: error.message });
//     res.status(500).json({
//       success: false,
//       message: "Internal server error",
//       error: error.message,
//       note: "Transaction rolled back - no changes made",
//     });
//   }
// });


router.post("/auth/disable-2fa", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password required",
      });
    }

    await databaseManager.query("BEGIN TRANSACTION");

    // Verify credentials
    const isValidPassword = await verifyPasswordEnhanced({ username, password });
    if (!isValidPassword.success) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Check if user exists in 2FA system
    const userQuery = await databaseManager.query(
      "SELECT * FROM appblddbo.TwoFactorUser WHERE LoginName = ?",
      [username]
    );

    if (userQuery.length === 0) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      return res.status(404).json({
        success: false,
        message: "User not found in 2FA system - 2FA may already be disabled",
      });
    }

    const user = userQuery[0];

    // ✅ CONVERSION EN INTEGER
    const userIdInt = parseInt(user.TwoFactorUserID);
    if (isNaN(userIdInt)) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      throw new Error(`Invalid TwoFactorUserID: ${user.TwoFactorUserID}`);
    }

    // Preserve original password before any changes
    const originalPasswordHash = await preserveOriginalPassword(username);

    // Disable 2FA completely
    await databaseManager.query(
      "UPDATE appblddbo.TwoFactorUser SET Disable2FA = 1, DBPassword = NULL WHERE TwoFactorUserID = ?",
      [userIdInt] // ← INTEGER
    );

    // Deactivate all devices
    await databaseManager.query(
      "UPDATE appblddbo.TwoFactorDevice SET Inactive = 1 WHERE TwoFactorUserID = ?",
      [userIdInt] // ← INTEGER
    );

    // Clear all sessions
    await databaseManager.query(
      "DELETE FROM appblddbo.TwoFactorSession WHERE UserLogin = ?",
      [username]
    );

    // CRITICAL: Restore original password
    const restored = await restoreOriginalPassword(username, originalPasswordHash);
    if (!restored) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      throw new Error("Failed to restore original password");
    }

    // Verify that password works
    const finalPasswordTest = await verifyPasswordEnhanced({ username, password });

    await databaseManager.query("COMMIT TRANSACTION");

    log('INFO', `2FA disabled successfully for: ${username}`);

    res.json({
      success: true,
      message: "2FA disabled successfully",
      user: {
        username: username,
        id: userIdInt,
        is2FAEnabled: false,
        originalPasswordPreserved: true,
        originalPasswordWorking: finalPasswordTest.success,
      },
      actions: [
        "Set Disable2FA to 1",
        "Cleared DBPassword",
        "Deactivated all TOTP devices",
        "Cleared active sessions",
        "Restored original password",
      ],
      note: "User can now login with original password only. Transaction committed successfully.",
    });
  } catch (error) {
    await databaseManager.query("ROLLBACK TRANSACTION");
    log('ERROR', 'Error disabling 2FA', { username: req.body.username, error: error.message });
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
      note: "Transaction rolled back - no changes made",
    });
  }
});






// =============================================================================
// SESSION MANAGEMENT ROUTES (Enhanced)
// =============================================================================

// List user sessions with device info
// router.get("/sessions/list/:username", async (req, res) => {
//   try {
//     const { username } = req.params;

//     const sessions = await databaseManager.query(
//       "SELECT SessionToken, LastUsedTS, SessionInfo FROM appblddbo.TwoFactorSession WHERE UserLogin = ?",
//       [username]
//     );

//     const sessionList = [];

//     for (const session of sessions) {
//       let sessionData = {};
//       try {
//         sessionData = JSON.parse(session.SessionInfo);
//       } catch (e) {
//         sessionData = {};
//       }

//       // Get current device info if deviceId exists
//       let currentDeviceInfo = sessionData.deviceInfo || "Unknown Device";
//       let deviceStatus = "Unknown";

//       if (sessionData.deviceId) {
//         try {
//           const deviceQuery = await databaseManager.query(
//             "SELECT DeviceInfo, Inactive FROM appblddbo.TwoFactorDevice WHERE TwoFactorDeviceID = ?",
//             [sessionData.deviceId]
//           );

//           if (deviceQuery.length > 0) {
//             currentDeviceInfo = deviceQuery[0].DeviceInfo;
//             deviceStatus = deviceQuery[0].Inactive ? "Inactive" : "Active";
//           } else {
//             deviceStatus = "Deleted";
//             currentDeviceInfo = sessionData.verifiedDeviceInfo || "Deleted Device";
//           }
//         } catch (error) {
//           log('WARN', 'Error fetching device info for session', { 
//             sessionToken: session.SessionToken.substring(0, 8),
//             deviceId: sessionData.deviceId 
//           });
//         }
//       }

//       sessionList.push({
//         sessionToken: session.SessionToken.substring(0, 8) + "...",
//         lastUsed: session.LastUsedTS,
//         loginTime: sessionData.loginTime,
//         ipAddress: sessionData.ipAddress,
//         userAgent: sessionData.userAgent,
//         deviceInfo: currentDeviceInfo,
//         deviceId: sessionData.deviceId || null,
//         deviceStatus: deviceStatus, 
//         authenticated2FA: sessionData.authenticated2FA || false,
//         sessionType: sessionData.sessionType || "legacy"
//       });
//     }

//     res.json({
//       success: true,
//       message: "Sessions retrieved",
//       username,
//       sessionCount: sessionList.length,
//       sessions: sessionList,
//     });
//   } catch (error) {
//     log('ERROR', 'List sessions error', { username: req.params.username, error: error.message });
//     res.status(500).json({
//       success: false,
//       message: "Internal server error",
//       error: error.message,
//     });
//   }
// });


router.get("/sessions/list/:username", async (req, res) => {
  try {
    const { username } = req.params;

    const sessions = await databaseManager.query(
      "SELECT SessionToken, LastUsedTS, SessionInfo FROM appblddbo.TwoFactorSession WHERE UserLogin = ?",
      [username]
    );

    const sessionList = [];

    for (const session of sessions) {
      let sessionData = {};
      try {
        sessionData = JSON.parse(session.SessionInfo);
      } catch (e) {
        sessionData = {};
      }

      // Get current device info if deviceId exists
      let currentDeviceInfo = sessionData.deviceInfo || "Unknown Device";
      let deviceStatus = "Unknown";

      if (sessionData.deviceId) {
        try {
          // ✅ CONVERSION EN INTEGER POUR LA REQUÊTE
          const deviceIdInt = parseInt(sessionData.deviceId);
          if (!isNaN(deviceIdInt)) {
            const deviceQuery = await databaseManager.query(
              "SELECT DeviceInfo, Inactive FROM appblddbo.TwoFactorDevice WHERE TwoFactorDeviceID = ?",
              [deviceIdInt] // ← INTEGER
            );

            if (deviceQuery.length > 0) {
              currentDeviceInfo = deviceQuery[0].DeviceInfo;
              deviceStatus = deviceQuery[0].Inactive ? "Inactive" : "Active";
            } else {
              deviceStatus = "Deleted";
              currentDeviceInfo = sessionData.verifiedDeviceInfo || "Deleted Device";
            }
          }
        } catch (error) {
          log('WARN', 'Error fetching device info for session', { 
            sessionToken: session.SessionToken.substring(0, 8),
            deviceId: sessionData.deviceId 
          });
        }
      }

      sessionList.push({
        sessionToken: session.SessionToken.substring(0, 8) + "...",
        lastUsed: session.LastUsedTS,
        loginTime: sessionData.loginTime,
        ipAddress: sessionData.ipAddress,
        userAgent: sessionData.userAgent,
        deviceInfo: currentDeviceInfo,
        deviceId: sessionData.deviceId ? parseInt(sessionData.deviceId) : null, // ✅ INTEGER
        deviceStatus: deviceStatus, 
        authenticated2FA: sessionData.authenticated2FA || false,
        sessionType: sessionData.sessionType || "legacy"
      });
    }

    res.json({
      success: true,
      message: "Sessions retrieved",
      username,
      sessionCount: sessionList.length,
      sessions: sessionList,
    });
  } catch (error) {
    log('ERROR', 'List sessions error', { username: req.params.username, error: error.message });
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
});

// Logout specific session
router.post("/sessions/logout", async (req, res) => {
  try {
    const { sessionToken } = req.body;

    if (!sessionToken) {
      return res.status(400).json({
        success: false,
        message: "Session token required",
      });
    }

    await databaseManager.query(
      "DELETE FROM appblddbo.TwoFactorSession WHERE SessionToken = ?",
      [sessionToken]
    );

    log('INFO', `Session logged out`, { sessionToken: sessionToken.substring(0, 8) + "..." });

    res.json({
      success: true,
      message: "Session logged out successfully",
      sessionToken: sessionToken.substring(0, 8) + "...",
    });
  } catch (error) {
    log('ERROR', 'Logout session error', { error: error.message });
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
});

// Logout all sessions for user
router.post("/sessions/logout-all", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password required",
      });
    }

    // Verify credentials
    const isValidPassword = await verifyPasswordEnhanced({ username, password });
    if (!isValidPassword.success) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    const result = await databaseManager.query(
      "DELETE FROM appblddbo.TwoFactorSession WHERE UserLogin = ?",
      [username]
    );

    log('INFO', `All sessions logged out for user`, { username, sessionsRemoved: result.affectedRows || 0 });

    res.json({
      success: true,
      message: "All sessions logged out successfully",
      username,
      sessionsRemoved: result.affectedRows || 0,
    });
  } catch (error) {
    log('ERROR', 'Logout all sessions error', { username: req.body.username, error: error.message });
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
});

// =============================================================================
// DEVICE MANAGEMENT ROUTES 
// =============================================================================

// List user devices
// router.get("/devices/list/:username", async (req, res) => {
//   try {
//     const { username } = req.params;   

//     // Get user information including 2FA status
//     const userQuery = await databaseManager.query(
//       "SELECT TwoFactorUserID, Disable2FA FROM appblddbo.TwoFactorUser WHERE LoginName = ?",
//       [username]
//     );

//     // Case 1: User not found in TwoFactorUser = 2FA never activated
//     if (userQuery.length === 0) {
//       log('INFO', `User ${username} not found in TwoFactorUser - 2FA never activated`);
//       return res.json({
//         success: true,
//         message: "Devices retrieved",
//         username,
//         deviceCount: 0,
//         activeDevices: 0,
//         devices: [],
//         twoFactorStatus: "never_activated",
//         debugInfo: "User not in TwoFactorUser table",
//       });
//     }

//     const user = userQuery[0];
//     log('DEBUG', `User ${username} found - Disable2FA: ${user.Disable2FA}`);

//     // Case 2: User exists but 2FA is disabled
//     if (user.Disable2FA === 1) {
//       log('INFO', `User ${username} has 2FA disabled`);
//       return res.json({
//         success: true,
//         message: "Devices retrieved",
//         username,
//         deviceCount: 0,
//         activeDevices: 0,
//         devices: [],
//         twoFactorStatus: "disabled",
//         debugInfo: "User has Disable2FA = 1",
//       });
//     }

//     // Case 3: 2FA is enabled - get active devices
//     log('DEBUG', `User ${username} has 2FA enabled - loading devices`);
//     const devices = await databaseManager.query(
//       "SELECT * FROM appblddbo.TwoFactorDevice WHERE TwoFactorUserID = ? AND Inactive IS NULL",
//       [user.TwoFactorUserID]
//     );

//     log('DEBUG', `Found ${devices.length} active devices for ${username}`);

//     const deviceList = devices.map((device) => ({
//       deviceId: device.TwoFactorDeviceID,
//       authMethod: device.AuthMethod,
//       deviceInfo: device.DeviceInfo,
//       isActive: !device.Inactive,
//       secretData: device.SecretData ? maskSensitiveData(device.SecretData) : null,
//     }));

//     res.json({
//       success: true,
//       message: "Devices retrieved",
//       username,
//       deviceCount: deviceList.length,
//       activeDevices: deviceList.filter((d) => d.isActive).length,
//       devices: deviceList,
//       twoFactorStatus: deviceList.length > 0 ? "enabled" : "enabled_no_devices",
//       debugInfo: `${deviceList.length} active devices found`,
//     });
//   } catch (error) {
//     log('ERROR', 'List devices error', { username: req.params.username, error: error.message });
//     res.status(500).json({
//       success: false,
//       message: "Internal server error",
//       error: error.message,
//       debugInfo: "Database error occurred",
//     });
//   }
// });

router.get("/devices/list/:username", async (req, res) => {
  try {
    const { username } = req.params;   

    // Get user information including 2FA status
    const userQuery = await databaseManager.query(
      "SELECT TwoFactorUserID, Disable2FA FROM appblddbo.TwoFactorUser WHERE LoginName = ?",
      [username]
    );

    // Case 1: User not found in TwoFactorUser = 2FA never activated
    if (userQuery.length === 0) {
      log('INFO', `User ${username} not found in TwoFactorUser - 2FA never activated`);
      return res.json({
        success: true,
        message: "Devices retrieved",
        username,
        deviceCount: 0,
        activeDevices: 0,
        devices: [],
        twoFactorStatus: "never_activated",
        debugInfo: "User not in TwoFactorUser table",
      });
    }

    const user = userQuery[0];

    // ✅ CONVERSION EN INTEGER
    const userIdInt = parseInt(user.TwoFactorUserID);
    if (isNaN(userIdInt)) {
      throw new Error(`Invalid TwoFactorUserID: ${user.TwoFactorUserID}`);
    }

    log('DEBUG', `User ${username} found - Disable2FA: ${user.Disable2FA}, UserID: ${userIdInt}`);

    // Case 2: User exists but 2FA is disabled
    if (user.Disable2FA === 1) {
      log('INFO', `User ${username} has 2FA disabled`);
      return res.json({
        success: true,
        message: "Devices retrieved",
        username,
        deviceCount: 0,
        activeDevices: 0,
        devices: [],
        twoFactorStatus: "disabled",
        debugInfo: "User has Disable2FA = 1",
      });
    }

    // Case 3: 2FA is enabled - get active devices
    log('DEBUG', `User ${username} has 2FA enabled - loading devices`);
    const devices = await databaseManager.query(
      "SELECT * FROM appblddbo.TwoFactorDevice WHERE TwoFactorUserID = ? AND Inactive IS NULL",
      [userIdInt] // ← INTEGER
    );

    log('DEBUG', `Found ${devices.length} active devices for ${username}`);

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
      twoFactorStatus: deviceList.length > 0 ? "enabled" : "enabled_no_devices",
      debugInfo: `${deviceList.length} active devices found`,
    });
  } catch (error) {
    log('ERROR', 'List devices error', { username: req.params.username, error: error.message });
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
      debugInfo: "Database error occurred",
    });
  }
});




// Device rename for UTF-8 support
// router.put("/devices/rename/:deviceId", async (req, res) => {
//   try {
//     const { deviceId } = req.params;
//     const { username, password, newDeviceName } = req.body;

//     if (!username || !password || !newDeviceName) {
//       return res.status(400).json({
//         success: false,
//         message: "Username, password and new device name required",
//       });
//     }

//     // Validate device name length (support UTF-8 characters)
//     if (newDeviceName.trim().length < 1 || newDeviceName.trim().length > 200) {
//       return res.status(400).json({
//         success: false,
//         message: "Device name must be between 1 and 200 characters",
//       });
//     }

//     await databaseManager.query("BEGIN TRANSACTION");

//     // Verify credentials
//     const isValidPassword = await verifyPasswordEnhanced({ username, password });
//     if (!isValidPassword.success) {
//       await databaseManager.query("ROLLBACK TRANSACTION");
//       return res.status(401).json({
//         success: false,
//         message: "Invalid credentials",
//       });
//     }

//     // Verify device ownership
//     const deviceQuery = await databaseManager.query(
//       `SELECT d.*, u.LoginName 
//        FROM appblddbo.TwoFactorDevice d 
//        JOIN appblddbo.TwoFactorUser u ON d.TwoFactorUserID = u.TwoFactorUserID 
//        WHERE d.TwoFactorDeviceID = ? AND u.LoginName = ? AND d.Inactive IS NULL`,
//       [deviceId, username]
//     );

//     if (deviceQuery.length === 0) {
//       await databaseManager.query("ROLLBACK TRANSACTION");
//       return res.status(404).json({
//         success: false,
//         message: "Device not found or not owned by user",
//       });
//     }

//     const oldDeviceName = deviceQuery[0].DeviceInfo;

//     // Update device name with proper UTF-8 support
//     await databaseManager.query(
//       "UPDATE appblddbo.TwoFactorDevice SET DeviceInfo = ? WHERE TwoFactorDeviceID = ?",
//       [newDeviceName.trim(), deviceId]
//     );

//     // Update all sessions that reference this device
//     const updatedSessions = await updateSessionsDeviceInfo(username, oldDeviceName, newDeviceName.trim());

//     await databaseManager.query("COMMIT TRANSACTION");

//     log('INFO', `Device renamed`, { 
//       deviceId, 
//       oldName: oldDeviceName, 
//       newName: newDeviceName.trim(),
//       sessionsUpdated: updatedSessions 
//     });

//     res.json({
//       success: true,
//       message: "Device renamed successfully",
//       device: {
//         deviceId,
//         oldName: oldDeviceName,
//         newName: newDeviceName.trim(),
//       },
//       sessionsUpdated: updatedSessions,
//     });
//   } catch (error) {
//     await databaseManager.query("ROLLBACK TRANSACTION");
//     log('ERROR', 'Rename device error', { deviceId: req.params.deviceId, error: error.message });
//     res.status(500).json({
//       success: false,
//       message: "Internal server error",
//       error: error.message,
//     });
//   }
// });

router.put("/devices/rename/:deviceId", async (req, res) => {
  try {
    const { deviceId } = req.params;
    const { username, password, newDeviceName } = req.body;

    // ✅ VALIDATION ET CONVERSION
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

    // Validate device name length (support UTF-8 characters)
    if (newDeviceName.trim().length < 1 || newDeviceName.trim().length > 200) {
      return res.status(400).json({
        success: false,
        message: "Device name must be between 1 and 200 characters",
      });
    }

    await databaseManager.query("BEGIN TRANSACTION");

    // Verify credentials
    const isValidPassword = await verifyPasswordEnhanced({ username, password });
    if (!isValidPassword.success) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Verify device ownership
    const deviceQuery = await databaseManager.query(
      `SELECT d.*, u.LoginName 
       FROM appblddbo.TwoFactorDevice d 
       JOIN appblddbo.TwoFactorUser u ON d.TwoFactorUserID = u.TwoFactorUserID 
       WHERE d.TwoFactorDeviceID = ? AND u.LoginName = ? AND d.Inactive IS NULL`,
      [deviceIdInt, username] // ← INTEGER
    );

    if (deviceQuery.length === 0) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      return res.status(404).json({
        success: false,
        message: "Device not found or not owned by user",
      });
    }

    const oldDeviceName = deviceQuery[0].DeviceInfo;

    // Update device name with proper UTF-8 support
    await databaseManager.query(
      "UPDATE appblddbo.TwoFactorDevice SET DeviceInfo = ? WHERE TwoFactorDeviceID = ?",
      [newDeviceName.trim(), deviceIdInt] // ← INTEGER
    );

    // Update all sessions that reference this device
    const updatedSessions = await updateSessionsDeviceInfo(username, oldDeviceName, newDeviceName.trim());

    await databaseManager.query("COMMIT TRANSACTION");

    log('INFO', `Device renamed`, { 
      deviceId: deviceIdInt, 
      oldName: oldDeviceName, 
      newName: newDeviceName.trim(),
      sessionsUpdated: updatedSessions 
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
    log('ERROR', 'Rename device error', { 
      deviceId: parseInt(req.params.deviceId), 
      error: error.message 
    });
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
});

// Remove device with confirmation for last active device
// router.delete("/devices/remove/:deviceId", async (req, res) => {
//   try {
//     const { deviceId } = req.params;
//     const { username, password, confirmDelete = false } = req.body;

//     if (!username || !password) {
//       return res.status(400).json({
//         success: false,
//         message: "Username and password required",
//       });
//     }

//     await databaseManager.query("BEGIN TRANSACTION");

//     // Verify credentials
//     const isValidPassword = await verifyPasswordEnhanced({ username, password });
//     if (!isValidPassword.success) {
//       await databaseManager.query("ROLLBACK TRANSACTION");
//       return res.status(401).json({
//         success: false,
//         message: "Invalid credentials",
//       });
//     }

//     // Get device and verify ownership
//     const deviceQuery = await databaseManager.query(
//       `SELECT d.*, u.LoginName, u.TwoFactorUserID
//        FROM appblddbo.TwoFactorDevice d 
//        JOIN appblddbo.TwoFactorUser u ON d.TwoFactorUserID = u.TwoFactorUserID 
//        WHERE d.TwoFactorDeviceID = ? AND u.LoginName = ? AND d.Inactive IS NULL`,
//       [deviceId, username]
//     );

//     if (deviceQuery.length === 0) {
//       await databaseManager.query("ROLLBACK TRANSACTION");
//       return res.status(404).json({
//         success: false,
//         message: "Device not found or not owned by user",
//       });
//     }

//     // Check if this is the last active device
//     const activeDeviceCount = await databaseManager.query(
//       `SELECT COUNT(*) as count 
//        FROM appblddbo.TwoFactorDevice 
//        WHERE TwoFactorUserID = ? AND Inactive IS NULL`,
//       [deviceQuery[0].TwoFactorUserID]
//     );

//     if (activeDeviceCount[0].count === 1) {
//       // This is the last device - requires confirmation
//       if (!confirmDelete) {
//         await databaseManager.query("ROLLBACK TRANSACTION");
//         return res.status(400).json({
//           success: false,
//           message: "This is your last device. Removing it will disable 2FA.",
//           requiresConfirmation: true,
//           isLastDevice: true,
//           deviceInfo: deviceQuery[0].DeviceInfo,
//         });
//       }

//       // Call the stored procedure to disable 2FA device
//       try {
//         log('INFO', `Calling PRC_Disable2FADevice for last device: ${deviceId}`);

//         const procedureResult = await databaseManager.query(
//           "SELECT * FROM appblddbo.PRC_Disable2FADevice(?, ?, ?)",
//           [deviceId, password, username]
//         );

//         const result = formatProcedureResult(procedureResult, "PRC_Disable2FADevice");

//         log('INFO', 'PRC_Disable2FADevice result', result);

//         if (result.success) {
//           // Update all sessions to show 2FA disabled
//           const sessions = await databaseManager.query(
//             "SELECT SessionToken, SessionInfo FROM appblddbo.TwoFactorSession WHERE UserLogin = ?",
//             [username]
//           );

//           for (const session of sessions) {
//             try {
//               const sessionData = JSON.parse(session.SessionInfo);
//               sessionData.deviceInfo = "No Device (2FA Disabled)";
//               const updatedSessionInfo = JSON.stringify(sessionData);

//               await databaseManager.query(
//                 "UPDATE appblddbo.TwoFactorSession SET SessionInfo = ? WHERE SessionToken = ?",
//                 [updatedSessionInfo, session.SessionToken]
//               );
//             } catch (parseError) {
//               log('WARN', `Could not parse session info for token: ${session.SessionToken.substring(0, 8)}...`);
//             }
//           }

//           await databaseManager.query("COMMIT TRANSACTION");

//           log('INFO', `Last device removed and 2FA disabled: ${username}`);

//           res.json({
//             success: true,
//             message: "Last device removed and 2FA disabled successfully",
//             device: {
//               deviceId,
//               deviceInfo: deviceQuery[0].DeviceInfo,
//             },
//             twoFactorDisabled: true,
//             procedureResult: result.message,
//             currentSessionUpdated: true,
//           });
//         } else {
//           await databaseManager.query("ROLLBACK TRANSACTION");
//           res.status(400).json({
//             success: false,
//             message: result.message,
//             error: "Procedure execution failed",
//           });
//         }
//       } catch (error) {
//         await databaseManager.query("ROLLBACK TRANSACTION");
//         log('ERROR', 'PRC_Disable2FADevice error', { deviceId, error: error.message });
//         res.status(500).json({
//           success: false,
//           message: "Failed to disable 2FA device",
//           error: error.message,
//         });
//       }
//     } else {
//       // Not the last device - mark as inactive and clear sessions for this device
//       await databaseManager.query(
//         "UPDATE appblddbo.TwoFactorDevice SET Inactive = 1 WHERE TwoFactorDeviceID = ?",
//         [deviceId]
//       );

//       const cleanedSessions = await cleanupSessionsForDevice(username, parseInt(deviceId));

//       await databaseManager.query("COMMIT TRANSACTION");

//       log('INFO', `Device removed (marked inactive): ${deviceId}`);

//       res.json({
//         success: true,
//         message: "Device removed successfully",
//         device: {
//           deviceId,
//           deviceInfo: deviceQuery[0].DeviceInfo,
//         },
//         twoFactorDisabled: false,
//         sessionsCleanedUp: cleanedSessions,
//       });
//     }
//   } catch (error) {
//     await databaseManager.query("ROLLBACK TRANSACTION");
//     log('ERROR', 'Remove device error', { deviceId: req.params.deviceId, error: error.message });
//     res.status(500).json({
//       success: false,
//       message: "Internal server error",
//       error: error.message,
//     });
//   }
// });


router.delete("/devices/remove/:deviceId", async (req, res) => {
  try {
    const { deviceId } = req.params;
    const { username, password, confirmDelete = false } = req.body;

    // ✅ VALIDATION ET CONVERSION
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

    await databaseManager.query("BEGIN TRANSACTION");

    // Verify credentials
    const isValidPassword = await verifyPasswordEnhanced({ username, password });
    if (!isValidPassword.success) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Get device and verify ownership
    const deviceQuery = await databaseManager.query(
      `SELECT d.*, u.LoginName, u.TwoFactorUserID
       FROM appblddbo.TwoFactorDevice d 
       JOIN appblddbo.TwoFactorUser u ON d.TwoFactorUserID = u.TwoFactorUserID 
       WHERE d.TwoFactorDeviceID = ? AND u.LoginName = ? AND d.Inactive IS NULL`,
      [deviceIdInt, username] // ← INTEGER
    );

    if (deviceQuery.length === 0) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      return res.status(404).json({
        success: false,
        message: "Device not found or not owned by user",
      });
    }

    // ✅ CONVERSION EN INTEGER
    const userIdInt = parseInt(deviceQuery[0].TwoFactorUserID);
    if (isNaN(userIdInt)) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      throw new Error(`Invalid TwoFactorUserID: ${deviceQuery[0].TwoFactorUserID}`);
    }

    // Check if this is the last active device
    const activeDeviceCount = await databaseManager.query(
      `SELECT COUNT(*) as count 
       FROM appblddbo.TwoFactorDevice 
       WHERE TwoFactorUserID = ? AND Inactive IS NULL`,
      [userIdInt] // ← INTEGER
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

      // Call the stored procedure to disable 2FA device
      try {
        log('INFO', `Calling PRC_Disable2FADevice for last device: ${deviceIdInt}`);

        const procedureResult = await databaseManager.query(
          "SELECT * FROM appblddbo.PRC_Disable2FADevice(?, ?, ?)",
          [deviceIdInt, password, username] // ← INTEGER
        );

        const result = formatProcedureResult(procedureResult, "PRC_Disable2FADevice");

        if (result.success) {
          // Update all sessions to show 2FA disabled
          const sessions = await databaseManager.query(
            "SELECT SessionToken, SessionInfo FROM appblddbo.TwoFactorSession WHERE UserLogin = ?",
            [username]
          );

          for (const session of sessions) {
            try {
              const sessionData = JSON.parse(session.SessionInfo);
              sessionData.deviceInfo = "No Device (2FA Disabled)";
              const updatedSessionInfo = JSON.stringify(sessionData);

              await databaseManager.query(
                "UPDATE appblddbo.TwoFactorSession SET SessionInfo = ? WHERE SessionToken = ?",
                [updatedSessionInfo, session.SessionToken]
              );
            } catch (parseError) {
              log('WARN', `Could not parse session info for token: ${session.SessionToken.substring(0, 8)}...`);
            }
          }

          await databaseManager.query("COMMIT TRANSACTION");

          log('INFO', `Last device removed and 2FA disabled: ${username}`);

          res.json({
            success: true,
            message: "Last device removed and 2FA disabled successfully",
            device: {
              deviceId: deviceIdInt,
              deviceInfo: deviceQuery[0].DeviceInfo,
            },
            twoFactorDisabled: true,
            procedureResult: result.message,
            currentSessionUpdated: true,
          });
        } else {
          await databaseManager.query("ROLLBACK TRANSACTION");
          res.status(400).json({
            success: false,
            message: result.message,
            error: "Procedure execution failed",
          });
        }
      } catch (error) {
        await databaseManager.query("ROLLBACK TRANSACTION");
        log('ERROR', 'PRC_Disable2FADevice error', { deviceId: deviceIdInt, error: error.message });
        res.status(500).json({
          success: false,
          message: "Failed to disable 2FA device",
          error: error.message,
        });
      }
    } else {
      // Not the last device - mark as inactive and clear sessions for this device
      await databaseManager.query(
        "UPDATE appblddbo.TwoFactorDevice SET Inactive = 1 WHERE TwoFactorDeviceID = ?",
        [deviceIdInt] // ← INTEGER
      );

      const cleanedSessions = await cleanupSessionsForDevice(username, deviceIdInt);

      await databaseManager.query("COMMIT TRANSACTION");

      log('INFO', `Device removed (marked inactive): ${deviceIdInt}`);

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
    log('ERROR', 'Remove device error', { 
      deviceId: parseInt(req.params.deviceId), 
      error: error.message 
    });
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
});

// Add new device
// router.post("/devices/add", async (req, res) => {
//   try {
//     const { username, password, deviceInfo = "New Device" } = req.body;

//     if (!username || !password) {
//       return res.status(400).json({
//         success: false,
//         message: "Username and password required",
//       });
//     }

//     await databaseManager.query("BEGIN TRANSACTION");

//     // Verify credentials
//     const isValidPassword = await verifyPasswordEnhanced({ username, password });
//     if (!isValidPassword.success) {
//       await databaseManager.query("ROLLBACK TRANSACTION");
//       return res.status(401).json({
//         success: false,
//         message: "Invalid credentials",
//       });
//     }

//     // Get user
//     const userQuery = await databaseManager.query(
//       "SELECT * FROM appblddbo.TwoFactorUser WHERE LoginName = ?",
//       [username]
//     );

//     if (userQuery.length === 0) {
//       await databaseManager.query("ROLLBACK TRANSACTION");
//       return res.status(404).json({
//         success: false,
//         message: "User not found",
//       });
//     }

//     // Enhanced device info detection
//     const enhancedDeviceInfo = detectDeviceFromUserAgent(req.get("User-Agent"), deviceInfo);

//     // Check if device with same name already exists
//     const existingDevices = await databaseManager.query(
//       "SELECT * FROM appblddbo.TwoFactorDevice WHERE TwoFactorUserID = ? AND DeviceInfo = ? AND Inactive IS NULL",
//       [userQuery[0].TwoFactorUserID, enhancedDeviceInfo]
//     );

//     if (existingDevices.length > 0) {
//       await databaseManager.query("ROLLBACK TRANSACTION");
//       return res.status(409).json({
//         success: false,
//         message: `A device with name "${enhancedDeviceInfo}" already exists`,
//         suggestion: "Try using a different device name or remove the existing device first",
//       });
//     }

//     // Generate new TOTP secret
//     const totpData = await totpService.generateTOTP(username);

//     // Add device
//     const deviceId = await addTwoFactorDevice(
//       userQuery[0].TwoFactorUserID,
//       enhancedDeviceInfo,
//       totpData.secret
//     );

//     await databaseManager.query("COMMIT TRANSACTION");

//     log('INFO', `New device added`, { username, deviceInfo: enhancedDeviceInfo, deviceId });

//     res.status(201).json({
//       success: true,
//       message: "Device added successfully",
//       device: {
//         deviceId,
//         deviceInfo: enhancedDeviceInfo,
//         authMethod: "TOTP",
//       },
//       totpSetup: {
//         secret: totpData.secret,
//         qrCodeDataURL: totpData.qrCode,
//         manualEntryKey: totpData.manualEntryKey,
//       },
//     });
//   } catch (error) {
//     await databaseManager.query("ROLLBACK TRANSACTION");
//     log('ERROR', 'Add device error', { username: req.body.username, error: error.message });
//     res.status(500).json({
//       success: false,
//       message: "Internal server error",
//       error: error.message,
//     });
//   }
// });

router.post("/devices/add", async (req, res) => {
  try {
    const { username, password, deviceInfo = "New Device" } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password required",
      });
    }

    await databaseManager.query("BEGIN TRANSACTION");

    // Verify credentials
    const isValidPassword = await verifyPasswordEnhanced({ username, password });
    if (!isValidPassword.success) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Get user
    const userQuery = await databaseManager.query(
      "SELECT * FROM appblddbo.TwoFactorUser WHERE LoginName = ?",
      [username]
    );

    if (userQuery.length === 0) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    const user = userQuery[0];

    // ✅ CONVERSION EN INTEGER
    const userIdInt = parseInt(user.TwoFactorUserID);
    if (isNaN(userIdInt)) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      throw new Error(`Invalid TwoFactorUserID: ${user.TwoFactorUserID}`);
    }

    // Enhanced device info detection
    const enhancedDeviceInfo = detectDeviceFromUserAgent(req.get("User-Agent"), deviceInfo);

    // Check if device with same name already exists
    const existingDevices = await databaseManager.query(
      "SELECT * FROM appblddbo.TwoFactorDevice WHERE TwoFactorUserID = ? AND DeviceInfo = ? AND Inactive IS NULL",
      [userIdInt, enhancedDeviceInfo] // ← INTEGER
    );

    if (existingDevices.length > 0) {
      await databaseManager.query("ROLLBACK TRANSACTION");
      return res.status(409).json({
        success: false,
        message: `A device with name "${enhancedDeviceInfo}" already exists`,
        suggestion: "Try using a different device name or remove the existing device first",
      });
    }

    // Generate new TOTP secret
    const totpData = await totpService.generateTOTP(username);

    // Add device
    const deviceId = await addTwoFactorDevice(
      userIdInt, // ← INTEGER
      enhancedDeviceInfo,
      totpData.secret
    );

    await databaseManager.query("COMMIT TRANSACTION");

    log('INFO', `New device added`, { username, deviceInfo: enhancedDeviceInfo, deviceId });

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
    log('ERROR', 'Add device error', { username: req.body.username, error: error.message });
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
});

module.exports = router;