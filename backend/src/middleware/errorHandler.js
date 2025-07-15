// Backend/src/middleware/errorHandler.js

/**
 * Error handling middleware for LeadSuccess 2FA API
 * Provides consistent error responses and logging
 */

const logger = require('../utils/logger');

/**
 * Custom API Error class
 */
class ApiError extends Error {
  constructor(statusCode, message, details = null) {
    super(message);
    this.statusCode = statusCode;
    this.details = details;
    this.timestamp = new Date().toISOString();
  }
}

/**
 * Async error wrapper for route handlers
 * @param {Function} fn - Async route handler function
 * @returns {Function} - Express middleware function
 */
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

/**
 * 404 Not Found handler
 */
const notFoundHandler = (req, res, next) => {
  const error = new ApiError(404, `Route not found: ${req.method} ${req.originalUrl}`);
  next(error);
};

/**
 * Main error handling middleware
 */
const errorHandler = (err, req, res, next) => {
  // Default to 500 server error
  let statusCode = err.statusCode || 500;
  let message = err.message || 'Internal Server Error';
  let details = err.details || null;

  // Log error details
  const errorLog = {
    timestamp: new Date().toISOString(),
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    error: {
      message: err.message,
      stack: err.stack,
      statusCode: statusCode
    }
  };

  // Don't leak error details in production
  if (process.env.NODE_ENV === 'production') {
    // Log full error internally
    logger.error('API Error', errorLog);
    
    // Generic messages for production
    if (statusCode === 500) {
      message = 'Internal server error occurred';
      details = null;
    }
  } else {
    // Development - log to console with full details
    console.error('🔥 API Error:', errorLog);
  }

  // Special handling for specific error types
  if (err.name === 'ValidationError') {
    statusCode = 400;
    message = 'Validation Error';
    details = err.errors;
  }

  if (err.name === 'UnauthorizedError') {
    statusCode = 401;
    message = 'Unauthorized';
  }

  if (err.code === 'ECONNREFUSED') {
    statusCode = 503;
    message = 'Database connection failed';
  }

  if (err.code === '23505') { 
    statusCode = 409;
    message = 'Duplicate entry';
  }

  // Send error response
  res.status(statusCode).json({
    success: false,
    message: message,
    ...(details && { details }),
    ...(process.env.NODE_ENV !== 'production' && { stack: err.stack }),
    timestamp: new Date().toISOString(),
    requestId: req.id || 'unknown'
  });
};

/**
 * Database error handler
 * Transforms database errors into user-friendly messages
 */
const handleDatabaseError = (error) => {
  const dbErrors = {
    'ER_DUP_ENTRY': { status: 409, message: 'Duplicate entry found' },
    'ER_NO_REFERENCED_ROW': { status: 400, message: 'Referenced record not found' },
    'ER_ROW_IS_REFERENCED': { status: 400, message: 'Cannot delete - record is referenced' },
    'ECONNREFUSED': { status: 503, message: 'Database connection failed' },
    'ETIMEDOUT': { status: 503, message: 'Database connection timeout' },
    'ENOTFOUND': { status: 503, message: 'Database server not found' }
  };

  const knownError = dbErrors[error.code];
  if (knownError) {
    throw new ApiError(knownError.status, knownError.message);
  }
  
  throw error;
};

/**
 * Validation error formatter
 * Formats validation errors into consistent structure
 */
const formatValidationError = (errors) => {
  const formatted = {};
  
  for (const field in errors) {
    formatted[field] = {
      message: errors[field].message,
      value: errors[field].value
    };
  }
  
  return formatted;
};

/**
 * Request timeout handler
 */
const timeoutHandler = (timeout = 30000) => {
  return (req, res, next) => {
    const timer = setTimeout(() => {
      const error = new ApiError(408, 'Request timeout');
      next(error);
    }, timeout);

    res.on('finish', () => clearTimeout(timer));
    res.on('close', () => clearTimeout(timer));
    
    next();
  };
};

/**
 * CORS error handler
 */
const corsErrorHandler = (err, req, res, next) => {
  if (err && err.message === 'Not allowed by CORS') {
    return res.status(403).json({
      success: false,
      message: 'CORS policy violation',
      origin: req.get('Origin'),
      allowedOrigins: process.env.NODE_ENV === 'production' ? 'Hidden' : [
        'http://localhost:3000',
        'http://localhost:4000',
        'http://localhost:5500'
      ]
    });
  }
  next(err);
};

/**
 * Rate limit error handler
 */
const rateLimitHandler = (req, res) => {
  res.status(429).json({
    success: false,
    message: 'Too many requests',
    retryAfter: res.get('Retry-After'),
    limit: res.get('X-RateLimit-Limit'),
    remaining: res.get('X-RateLimit-Remaining'),
    reset: res.get('X-RateLimit-Reset')
  });
};

module.exports = {
  ApiError,
  asyncHandler,
  errorHandler,
  notFoundHandler,
  handleDatabaseError,
  formatValidationError,
  timeoutHandler,
  corsErrorHandler,
  rateLimitHandler
};