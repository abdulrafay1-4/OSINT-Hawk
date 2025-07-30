const express = require('express');
const router = express.Router();
const usernameService = require('../services/usernameService');
const { validateQuery, advancedValidation } = require('../utils/validator');
const { asyncHandler } = require('../utils/errorHandler');
const logger = require('../utils/logger');

/**
 * @route   GET /osint/username
 * @desc    Investigate username across multiple platforms
 * @access  Public
 * @param   {string} value - Username to investigate
 * @example GET /osint/username?value=johndoe
 */
router.get('/', advancedValidation, (req, res, next) => {
  // Set the type manually since we're at the root of this route
  req.routeType = 'username';
  next();
}, validateQuery, asyncHandler(async (req, res) => {
  const { value } = req.validatedInput;
  
  logger.info(`Username investigation request: ${value} from IP: ${req.ip}`);

  // Perform the investigation
  const results = await usernameService.investigate(value);

  // Log the results summary
  logger.info(`Username investigation completed for ${value}: found on ${results.foundOn}/${results.totalPlatforms} platforms`);

  res.json({
    success: true,
    data: results,
    meta: {
      query: value,
      type: 'username',
      timestamp: results.timestamp,
      processingTime: Date.now() - new Date(results.timestamp).getTime(),
      requestId: req.headers['x-request-id'] || 'unknown'
    }
  });
}));

/**
 * @route   GET /osint/username/platforms
 * @desc    Get list of supported platforms for username investigation
 * @access  Public
 */
router.get('/platforms', (req, res) => {
  res.json({
    success: true,
    data: {
      platforms: [
        {
          name: 'GitHub',
          description: 'Code repository platform',
          dataAvailable: ['profile', 'repositories', 'followers', 'activity'],
          apiLimited: true
        },
        {
          name: 'Reddit',
          description: 'Social news aggregation platform',
          dataAvailable: ['profile', 'karma', 'account_age'],
          apiLimited: false
        },
        {
          name: 'Twitter',
          description: 'Social media platform',
          dataAvailable: ['profile_existence'],
          apiLimited: true,
          note: 'Limited data due to API restrictions'
        },
        {
          name: 'Instagram',
          description: 'Photo sharing platform',
          dataAvailable: ['profile_existence'],
          apiLimited: true,
          note: 'Limited data due to API restrictions'
        }
      ],
      totalPlatforms: 4,
      note: 'Some platforms have limited data availability due to API restrictions'
    }
  });
});

/**
 * @route   GET /osint/username/help
 * @desc    Get help information for username investigation
 * @access  Public
 */
router.get('/help', (req, res) => {
  res.json({
    success: true,
    data: {
      endpoint: '/osint/username',
      method: 'GET',
      description: 'Investigate username availability and presence across multiple platforms',
      parameters: {
        value: {
          required: true,
          type: 'string',
          description: 'Username to investigate',
          validation: 'Alphanumeric characters only, 1-50 characters',
          example: 'johndoe'
        }
      },
      response: {
        description: 'Investigation results with platform-specific data',
        structure: {
          query: 'Original username query',
          type: 'Investigation type (username)',
          timestamp: 'Investigation timestamp',
          totalPlatforms: 'Number of platforms checked',
          foundOn: 'Number of platforms where username exists',
          overallRisk: 'Risk assessment (none/low/medium/high)',
          platforms: 'Array of platform-specific results',
          recommendations: 'Security recommendations based on findings'
        }
      },
      riskLevels: {
        none: 'Username not found on any platforms',
        low: 'Username found on 1-2 platforms',
        medium: 'Username found on 3+ platforms',
        high: 'Username found with concerning patterns or data exposure'
      },
      examples: [
        '/osint/username?value=johndoe',
        '/osint/username?value=testuser123'
      ],
      rateLimits: '100 requests per 15 minutes per IP',
      tips: [
        'Use consistent usernames across platforms for better detection',
        'Results may vary based on platform API availability',
        'GitHub results are most comprehensive with API token configured'
      ]
    }
  });
});

module.exports = router;
