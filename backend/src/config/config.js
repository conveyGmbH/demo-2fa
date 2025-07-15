// Backend/src/config/config.js 

// Load environment variables from .env file
require('dotenv').config();

const config = {
    // Server configuration
    server: {
        port: process.env.PORT,
        host: process.env.HOST,
        env: process.env.NODE_ENV || 'development'
    },

    // Database configuration 
    database: {
        dsn: process.env.DB_DSN, 
        uid: process.env.DB_UID,
        pwd: process.env.DB_PWD,
        connectionString: process.env.DB_CONNECTION_STRING || null,
        pool: {
            min: parseInt(process.env.DB_POOL_MIN) || 2,
            max: parseInt(process.env.DB_POOL_MAX) || 10,
            idleTimeout: parseInt(process.env.DB_IDLE_TIMEOUT) || 30000
        }
    },

    // TOTP configuration 
    totp: {
        algorithm: process.env.TOTP_ALGORITHM,
        digits: parseInt(process.env.TOTP_DIGITS),
        period: parseInt(process.env.TOTP_PERIOD),
        size: parseInt(process.env.TOTP_SIZE),
        issuer: process.env.TOTP_ISSUER,
        label: process.env.TOTP_LABEL,
    },

    // Session configuration
    session: {
        maxSessions: parseInt(process.env.MAX_SESSIONS) || 5,
        sessionTimeout: parseInt(process.env.SESSION_TIMEOUT) || 3600000, // 1 hour
        cleanupInterval: parseInt(process.env.CLEANUP_INTERVAL) || 300000 // 5 minutes
    },

    // Security configuration
    security: {
        bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS) || 12,
        maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5,
        lockoutDuration: parseInt(process.env.LOCKOUT_DURATION) || 900000, // 15 minutes
        rateLimitWindow: parseInt(process.env.RATE_LIMIT_WINDOW) || 900000, // 15 minutes
        rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX) || 100
    },

    // Logging configuration
    logging: {
        level: process.env.LOG_LEVEL || 'info',
        file: process.env.LOG_FILE || 'combined.log',
        errorFile: process.env.LOG_ERROR_FILE || 'error.log',
        auditFile: process.env.LOG_AUDIT_FILE || 'audit.log'
    }
};

module.exports = config;