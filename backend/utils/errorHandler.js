const logger = require('./logger');

/**
 * Custom error class for OSINT operations
 */
class OSINTError extends Error {
  constructor(message, statusCode = 500, type = 'INTERNAL_ERROR') {
    super(message);
    this.name = 'OSINTError';
    this.statusCode = statusCode;
    this.type = type;
    this.timestamp = new Date().toISOString();
  }
}

/**
 * API Error class for client errors
 */
class APIError extends Error {
  constructor(message, statusCode = 400, type = 'CLIENT_ERROR') {
    super(message);
    this.name = 'APIError';
    this.statusCode = statusCode;
    this.type = type;
    this.timestamp = new Date().toISOString();
  }
}

/**
 * Global error handler middleware
 */
const errorHandler = (err, req, res, next) => {
  let error = { ...err };
  error.message = err.message;

  // Log error
  logger.error(`Error ${error.statusCode || 500}: ${error.message}`, {
    path: req.path,
    method: req.method,
    ip: req.ip,
    stack: err.stack,
    body: req.body,
    query: req.query
  });

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const message = Object.values(err.errors).map(val => val.message).join(', ');
    error = new APIError(message, 400, 'VALIDATION_ERROR');
  }

  // Mongoose duplicate key error
  if (err.code === 11000) {
    const message = 'Duplicate field value entered';
    error = new APIError(message, 400, 'DUPLICATE_ERROR');
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    const message = 'Invalid token';
    error = new APIError(message, 401, 'INVALID_TOKEN');
  }

  // Rate limit error
  if (err.type === 'rate-limit') {
    error = new APIError('Too many requests', 429, 'RATE_LIMIT_EXCEEDED');
  }

  // File upload errors
  if (err.code === 'LIMIT_FILE_SIZE') {
    error = new APIError('File too large', 413, 'FILE_TOO_LARGE');
  }

  if (err.code === 'LIMIT_UNEXPECTED_FILE') {
    error = new APIError('Invalid file type', 400, 'INVALID_FILE_TYPE');
  }

  // API service errors
  if (err.response && err.response.status) {
    const status = err.response.status;
    let message = 'External API error';
    
    if (status === 401) {
      message = 'API authentication failed';
    } else if (status === 403) {
      message = 'API access forbidden';
    } else if (status === 429) {
      message = 'API rate limit exceeded';
    } else if (status >= 500) {
      message = 'External service unavailable';
    }
    
    error = new OSINTError(message, status, 'EXTERNAL_API_ERROR');
  }

  res.status(error.statusCode || 500).json({
    success: false,
    error: {
      type: error.type || 'INTERNAL_ERROR',
      message: error.message || 'Server Error',
      timestamp: error.timestamp || new Date().toISOString(),
      requestId: req.headers['x-request-id'] || 'unknown',
      ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    }
  });
};

/**
 * Async handler wrapper to catch async errors
 */
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

/**
 * Not found handler
 */
const notFound = (req, res, next) => {
  const error = new APIError(`Resource not found - ${req.originalUrl}`, 404, 'NOT_FOUND');
  next(error);
};

module.exports = {
  OSINTError,
  APIError,
  errorHandler,
  asyncHandler,
  notFound
};
