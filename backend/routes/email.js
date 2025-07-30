const express = require('express');
const router = express.Router();
const emailService = require('../services/emailService');
const { validateQuery, advancedValidation } = require('../utils/validator');
const { asyncHandler } = require('../utils/errorHandler');
const logger = require('../utils/logger');

/**
 * @route   GET /osint/email
 * @desc    Investigate email address for breaches, mentions, and security
 * @access  Public
 * @param   {string} value - Email address to investigate
 * @example GET /osint/email?value=test@example.com
 */
router.get('/', advancedValidation, (req, res, next) => {
  req.routeType = 'email';
  next();
}, validateQuery, asyncHandler(async (req, res) => {
  const { value } = req.validatedInput;
  
  logger.info(`Email investigation request: ${value.replace(/(.{3}).*(@.*)/, '$1***$2')} from IP: ${req.ip}`);

  // Perform the investigation
  const results = await emailService.investigate(value);

  // Log the results summary (without exposing the full email)
  const maskedEmail = value.replace(/(.{3}).*(@.*)/, '$1***$2');
  logger.info(`Email investigation completed for ${maskedEmail}: risk level ${results.overallRisk}`);

  res.json({
    success: true,
    data: results,
    meta: {
      query: value.replace(/(.{3}).*(@.*)/, '$1***$2'), // Mask email in response meta
      type: 'email',
      timestamp: results.timestamp,
      processingTime: Date.now() - new Date(results.timestamp).getTime(),
      requestId: req.headers['x-request-id'] || 'unknown'
    }
  });
}));

/**
 * @route   GET /osint/email/sources
 * @desc    Get list of data sources used for email investigation
 * @access  Public
 */
router.get('/sources', (req, res) => {
  res.json({
    success: true,
    data: {
      sources: [
        {
          name: 'HaveIBeenPwned',
          description: 'Check email against known data breaches',
          dataAvailable: ['breach_history', 'compromise_details', 'affected_services'],
          requiresApiKey: true,
          website: 'https://haveibeenpwned.com'
        },
        {
          name: 'GitHub Search',
          description: 'Search for email mentions in public repositories',
          dataAvailable: ['code_exposure', 'repository_mentions', 'commit_history'],
          requiresApiKey: true,
          website: 'https://github.com'
        },
        {
          name: 'Domain Analysis',
          description: 'Analyze email domain properties and reputation',
          dataAvailable: ['domain_type', 'disposable_check', 'provider_info'],
          requiresApiKey: false,
          builtin: true
        }
      ],
      totalSources: 3,
      note: 'API keys required for enhanced functionality'
    }
  });
});

/**
 * @route   GET /osint/email/breach-categories
 * @desc    Get information about breach categories and data types
 * @access  Public
 */
router.get('/breach-categories', (req, res) => {
  res.json({
    success: true,
    data: {
      categories: {
        'Email addresses': 'Contact information exposure',
        'Passwords': 'Authentication credential compromise',
        'Usernames': 'Account identifier exposure',
        'Names': 'Personal identity information',
        'Phone numbers': 'Contact information exposure',
        'Physical addresses': 'Location information exposure',
        'Credit cards': 'Financial information compromise',
        'Social security numbers': 'Government ID compromise',
        'IP addresses': 'Network identifier exposure',
        'Dates of birth': 'Personal demographic data',
        'Geographic locations': 'Location tracking data',
        'Social media profiles': 'Online identity information'
      },
      riskLevels: {
        low: 'Basic contact information only',
        medium: 'Personal details or account information',
        high: 'Financial or authentication data',
        critical: 'Government IDs or highly sensitive data'
      },
      recommendations: {
        any_breach: [
          'Change passwords on affected accounts',
          'Enable two-factor authentication',
          'Monitor accounts for suspicious activity'
        ],
        password_breach: [
          'Change passwords immediately',
          'Check for password reuse across accounts',
          'Consider using a password manager'
        ],
        financial_breach: [
          'Monitor credit reports and bank statements',
          'Consider credit monitoring services',
          'Report to relevant financial institutions'
        ]
      }
    }
  });
});

/**
 * @route   GET /osint/email/help
 * @desc    Get help information for email investigation
 * @access  Public
 */
router.get('/help', (req, res) => {
  res.json({
    success: true,
    data: {
      endpoint: '/osint/email',
      method: 'GET',
      description: 'Investigate email address for security breaches, public exposure, and domain reputation',
      parameters: {
        value: {
          required: true,
          type: 'string',
          description: 'Email address to investigate',
          validation: 'Valid email format required',
          example: 'user@example.com'
        }
      },
      response: {
        description: 'Email investigation results with breach data, exposure analysis, and domain information',
        structure: {
          query: 'Original email query (masked for privacy)',
          type: 'Investigation type (email)',
          timestamp: 'Investigation timestamp',
          overallRisk: 'Risk assessment (low/medium/high/critical)',
          breachCheck: 'HaveIBeenPwned breach analysis',
          githubMentions: 'Public repository mention analysis',
          domainAnalysis: 'Email domain reputation and type analysis',
          recommendations: 'Security recommendations based on findings'
        }
      },
      riskLevels: {
        low: 'No breaches found, secure domain',
        medium: 'Minor breaches or suspicious domain',
        high: 'Multiple breaches or significant exposure',
        critical: 'Severe breaches with sensitive data exposure'
      },
      privacy: {
        note: 'Email addresses are masked in logs and response metadata for privacy',
        dataRetention: 'Investigation results are not stored permanently',
        apiSecurity: 'All API communications use HTTPS encryption'
      },
      examples: [
        '/osint/email?value=test@gmail.com',
        '/osint/email?value=user@company.com'
      ],
      rateLimits: '100 requests per 15 minutes per IP',
      tips: [
        'Results depend on configured API keys for full functionality',
        'Disposable email domains are flagged as high risk',
        'GitHub searches may reveal email in public commits'
      ]
    }
  });
});

module.exports = router;
