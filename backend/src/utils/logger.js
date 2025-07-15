// Backend/src/utils/logger.js - FIXED VERSION

/**
 * Logger utility for LeadSuccess 2FA system
 * Provides structured logging with multiple transports
 */

const fs = require('fs');
const path = require('path');
const util = require('util');

// Create logs directory if it doesn't exist
const logsDir = path.join(__dirname, '../../logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

/**
 * Log levels with colors and priorities
 */
const LOG_LEVELS = {
  ERROR: { priority: 0, color: '\x1b[31m', emoji: '❌' },
  WARN: { priority: 1, color: '\x1b[33m', emoji: '⚠️' },
  INFO: { priority: 2, color: '\x1b[32m', emoji: '✅' },
  DEBUG: { priority: 3, color: '\x1b[36m', emoji: '🔍' },
  TRACE: { priority: 4, color: '\x1b[35m', emoji: '📝' }
};

/**
 * Logger configuration
 */
const config = {
  level: (process.env.LOG_LEVEL || 'INFO').toUpperCase(), 
  enableConsole: process.env.NODE_ENV !== 'test',
  enableFile: process.env.NODE_ENV === 'production',
  maxFileSize: 10 * 1024 * 1024, // 10MB
  dateFormat: 'YYYY-MM-DD HH:mm:ss.SSS',
  sanitize: process.env.NODE_ENV === 'production'
};

/**
 * Validate and normalize log level
 */
function validateLogLevel(level) {
  const normalizedLevel = (level || 'INFO').toUpperCase();
  
  // If the level doesn't exist, default to INFO
  if (!LOG_LEVELS[normalizedLevel]) {
    console.warn(`⚠️  Invalid log level "${level}", defaulting to INFO`);
    return 'INFO';
  }
  
  return normalizedLevel;
}

// Apply validation to config
config.level = validateLogLevel(config.level);

/**
 * Logger class
 */
class Logger {
  constructor(name = 'LeadSuccess2FA') {
    this.name = name;
    this.streams = [];
    
    // Console stream
    if (config.enableConsole) {
      this.streams.push(this.consoleStream.bind(this));
    }
    
    // File stream
    if (config.enableFile) {
      this.setupFileStream();
    }
  }

  /**
   * Get current timestamp
   */
  getTimestamp() {
    const now = new Date();
    return now.toISOString();
  }

  /**
   * Format log message
   */
  formatMessage(level, message, data) {
    const timestamp = this.getTimestamp();
    const levelInfo = LOG_LEVELS[level];
    
    let formatted = {
      timestamp,
      level,
      name: this.name,
      message,
      ...(data && { data: this.sanitizeData(data) })
    };

    return formatted;
  }

  /**
   * Sanitize sensitive data
   */
  sanitizeData(data) {
    if (!config.sanitize) return data;
    
    const sensitiveKeys = [
      'password', 'pwd', 'secret', 'token', 'sessionToken',
      'apiKey', 'authorization', 'cookie', 'dbPassword'
    ];
    
    const sanitized = { ...data };
    
    const sanitizeObject = (obj) => {
      for (const key in obj) {
        const lowerKey = key.toLowerCase();
        
        if (sensitiveKeys.some(sensitive => lowerKey.includes(sensitive))) {
          obj[key] = '***REDACTED***';
        } else if (typeof obj[key] === 'object' && obj[key] !== null) {
          sanitizeObject(obj[key]);
        }
      }
    };
    
    sanitizeObject(sanitized);
    return sanitized;
  }

  /**
   * Console stream
   */
  consoleStream(level, message, data) {
    const levelInfo = LOG_LEVELS[level];
    const timestamp = this.getTimestamp();
    
    // Colorful console output
    const prefix = `${levelInfo.color}[${timestamp}] ${levelInfo.emoji} ${level}${'\x1b[0m'}`;
    const logMessage = `${prefix} [${this.name}] ${message}`;
    
    console.log(logMessage);
    
    if (data && Object.keys(data).length > 0) {
      console.log(util.inspect(data, { 
        colors: true, 
        depth: 3, 
        compact: false 
      }));
    }
  }

  /**
   * Setup file stream with rotation
   */
  setupFileStream() {
    const logFile = path.join(logsDir, `app-${new Date().toISOString().split('T')[0]}.log`);
    
    this.fileStream = fs.createWriteStream(logFile, { flags: 'a' });
    this.streams.push(this.writeToFile.bind(this));
    
    // Check file size periodically
    setInterval(() => {
      fs.stat(logFile, (err, stats) => {
        if (!err && stats.size > config.maxFileSize) {
          this.rotateLogFile();
        }
      });
    }, 60000); // Check every minute
  }

  /**
   * Write to file stream
   */
  writeToFile(level, message, data) {
    if (!this.fileStream) return;
    
    const formatted = this.formatMessage(level, message, data);
    const logLine = JSON.stringify(formatted) + '\n';
    
    this.fileStream.write(logLine);
  }

  /**
   * Rotate log file
   */
  rotateLogFile() {
    if (!this.fileStream) return;
    
    this.fileStream.end();
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const currentFile = path.join(logsDir, `app-${new Date().toISOString().split('T')[0]}.log`);
    const rotatedFile = path.join(logsDir, `app-${timestamp}.log`);
    
    fs.renameSync(currentFile, rotatedFile);
    this.setupFileStream();
  }

  /**
   *  Check if level should be logged with proper validation
   */
  shouldLog(level) {
    // Normalize and validate the incoming level
    const normalizedLevel = validateLogLevel(level);
    const normalizedConfigLevel = validateLogLevel(config.level);
    
    const currentPriority = LOG_LEVELS[normalizedConfigLevel].priority;
    const messagePriority = LOG_LEVELS[normalizedLevel].priority;
    
    return messagePriority <= currentPriority;
  }

  /**
   *  Main logging method with level validation
   */
  log(level, message, data = null) {
    // Normalize level to uppercase
    const normalizedLevel = validateLogLevel(level);
    
    if (!this.shouldLog(normalizedLevel)) return;
    
    this.streams.forEach(stream => {
      try {
        stream(normalizedLevel, message, data);
      } catch (error) {
        console.error('Logger stream error:', error);
      }
    });
  }

  // Convenience methods with proper level validation
  error(message, data) { this.log('ERROR', message, data); }
  warn(message, data) { this.log('WARN', message, data); }
  info(message, data) { this.log('INFO', message, data); }
  debug(message, data) { this.log('DEBUG', message, data); }
  trace(message, data) { this.log('TRACE', message, data); }

  /**
   * Log HTTP request
   */
  logRequest(req, res, duration) {
    const data = {
      method: req.method,
      url: req.originalUrl,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      ...(req.user && { userId: req.user.id })
    };

    const level = res.statusCode >= 400 ? 'ERROR' : 'INFO';
    this.log(level, `${req.method} ${req.originalUrl} - ${res.statusCode}`, data);
  }

  /**
   * Create child logger
   */
  child(name) {
    return new Logger(`${this.name}:${name}`);
  }
}

// Create default logger instance
const defaultLogger = new Logger();

/**
 * Express middleware for request logging
 */
const requestLogger = (req, res, next) => {
  const start = Date.now();
  
  // Log response when finished
  res.on('finish', () => {
    const duration = Date.now() - start;
    defaultLogger.logRequest(req, res, duration);
  });
  
  next();
};

/**
 * Error logger middleware
 */
const errorLogger = (err, req, res, next) => {
  defaultLogger.error('Unhandled error', {
    error: {
      message: err.message,
      stack: err.stack,
      code: err.code
    },
    request: {
      method: req.method,
      url: req.originalUrl,
      ip: req.ip
    }
  });
  
  next(err);
};

// Export logger instance and utilities
module.exports = defaultLogger;
module.exports.Logger = Logger;
module.exports.requestLogger = requestLogger;
module.exports.errorLogger = errorLogger;
module.exports.createLogger = (name) => new Logger(name);