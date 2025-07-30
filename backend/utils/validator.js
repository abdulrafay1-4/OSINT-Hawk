const Joi = require('joi');
const validator = require('validator');
const { APIError } = require('./errorHandler');

/**
 * Validation schemas
 */
const schemas = {
  username: Joi.string()
    .alphanum()
    .min(1)
    .max(50)
    .required()
    .messages({
      'string.alphanum': 'Username must contain only alphanumeric characters',
      'string.min': 'Username must be at least 1 character long',
      'string.max': 'Username must not exceed 50 characters',
      'any.required': 'Username is required'
    }),

  email: Joi.string()
    .email()
    .required()
    .messages({
      'string.email': 'Must be a valid email address',
      'any.required': 'Email is required'
    }),

  domain: Joi.string()
    .domain()
    .required()
    .messages({
      'string.domain': 'Must be a valid domain name',
      'any.required': 'Domain is required'
    }),

  ip: Joi.string()
    .ip({ version: ['ipv4', 'ipv6'] })
    .required()
    .messages({
      'string.ip': 'Must be a valid IP address (IPv4 or IPv6)',
      'any.required': 'IP address is required'
    })
};

/**
 * Validate input based on type
 */
const validateInput = (type, value) => {
  if (!value || typeof value !== 'string') {
    throw new APIError('Invalid input value', 400, 'VALIDATION_ERROR');
  }

  // Sanitize input
  const sanitizedValue = value.trim().toLowerCase();

  // Validate based on type
  const schema = schemas[type];
  if (!schema) {
    throw new APIError('Invalid input type', 400, 'VALIDATION_ERROR');
  }

  const { error, value: validatedValue } = schema.validate(sanitizedValue);
  
  if (error) {
    throw new APIError(error.details[0].message, 400, 'VALIDATION_ERROR');
  }

  return validatedValue;
};

/**
 * Validate file upload
 */
const validateFile = (file) => {
  if (!file) {
    throw new APIError('No file provided', 400, 'VALIDATION_ERROR');
  }

  const allowedTypes = process.env.ALLOWED_FILE_TYPES?.split(',') || [
    '.exe', '.doc', '.docx', '.pdf', '.zip', '.rar', '.txt', '.dll', '.bat', '.ps1'
  ];

  const maxSize = parseInt(process.env.MAX_FILE_SIZE) || 50000000; // 50MB default

  // Check file size
  if (file.size > maxSize) {
    throw new APIError(`File size exceeds maximum allowed size of ${maxSize / 1000000}MB`, 413, 'FILE_TOO_LARGE');
  }

  // Check file extension
  const fileExt = '.' + file.originalname.split('.').pop().toLowerCase();
  if (!allowedTypes.includes(fileExt)) {
    throw new APIError(`File type ${fileExt} not allowed. Allowed types: ${allowedTypes.join(', ')}`, 400, 'INVALID_FILE_TYPE');
  }

  return true;
};

/**
 * Sanitize string to prevent XSS
 */
const sanitizeString = (str) => {
  if (typeof str !== 'string') return str;
  
  return str
    .replace(/[<>]/g, '') // Remove angle brackets
    .replace(/javascript:/gi, '') // Remove javascript: protocol
    .replace(/on\w+=/gi, '') // Remove event handlers
    .trim();
};

/**
 * Validate and sanitize query parameters
 */
const validateQuery = (req, res, next) => {
  try {
    const { value } = req.query;
    
    if (!value) {
      throw new APIError('Missing required parameter: value', 400, 'MISSING_PARAMETER');
    }

    // Get the type from route or determine from the path
    let type = req.routeType;
    if (!type) {
      const pathSegments = req.originalUrl.split('/').filter(segment => segment);
      type = pathSegments[pathSegments.length - 1];
    }

    // Validate the input
    const validatedValue = validateInput(type, value);
    
    // Add validated value to request
    req.validatedInput = {
      type,
      value: validatedValue,
      originalValue: value
    };

    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Check if string contains suspicious patterns
 */
const containsSuspiciousPatterns = (str) => {
  const suspiciousPatterns = [
    /(<script|<\/script)/gi,
    /(javascript:|data:|vbscript:)/gi,
    /(onload|onerror|onclick)/gi,
    /(\<|\>)/g,
    /(union|select|insert|update|delete|drop|create|alter)/gi
  ];

  return suspiciousPatterns.some(pattern => pattern.test(str));
};

/**
 * Advanced input validation middleware
 */
const advancedValidation = (req, res, next) => {
  try {
    // Check for suspicious patterns in all string inputs
    const checkStrings = (obj) => {
      for (const [key, value] of Object.entries(obj)) {
        if (typeof value === 'string') {
          if (containsSuspiciousPatterns(value)) {
            throw new APIError(`Suspicious pattern detected in ${key}`, 400, 'SECURITY_VIOLATION');
          }
        } else if (typeof value === 'object' && value !== null) {
          checkStrings(value);
        }
      }
    };

    // Validate query parameters
    if (req.query && Object.keys(req.query).length > 0) {
      checkStrings(req.query);
    }

    // Validate body parameters
    if (req.body && Object.keys(req.body).length > 0) {
      checkStrings(req.body);
    }

    next();
  } catch (error) {
    next(error);
  }
};

module.exports = {
  validateInput,
  validateFile,
  validateQuery,
  sanitizeString,
  advancedValidation,
  schemas
};
