const express = require('express');
const router = express.Router();
const ipService = require('../services/ipService');
const { validateQuery, advancedValidation } = require('../utils/validator');
const { asyncHandler } = require('../utils/errorHandler');
const logger = require('../utils/logger');

/**
 * @route   GET /osint/ip
 * @desc    Investigate IP address for geolocation, threats, and reputation
 * @access  Public
 * @param   {string} value - IP address to investigate
 * @example GET /osint/ip?value=8.8.8.8
 */
router.get('/', advancedValidation, (req, res, next) => {
  req.routeType = 'ip';
  next();
}, validateQuery, asyncHandler(async (req, res) => {
  const { value } = req.validatedInput;
  
  logger.info(`IP investigation request: ${value} from IP: ${req.ip}`);

  // Perform the investigation
  const results = await ipService.investigate(value);

  // Log the results summary
  logger.info(`IP investigation completed for ${value}: risk level ${results.overallRisk}`);

  res.json({
    success: true,
    data: results,
    meta: {
      query: value,
      type: 'ip',
      timestamp: results.timestamp,
      processingTime: Date.now() - new Date(results.timestamp).getTime(),
      requestId: req.headers['x-request-id'] || 'unknown'
    }
  });
}));

/**
 * @route   GET /osint/ip/geolocation/:ip
 * @desc    Get only geolocation information for an IP address
 * @access  Public
 * @param   {string} ip - IP address
 */
router.get('/geolocation/:ip', advancedValidation, asyncHandler(async (req, res) => {
  const ip = req.params.ip.trim();
  
  // Basic IP validation
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  
  if (!ipv4Regex.test(ip) && !ipv6Regex.test(ip)) {
    return res.status(400).json({
      success: false,
      error: {
        type: 'VALIDATION_ERROR',
        message: 'Invalid IP address format',
        timestamp: new Date().toISOString()
      }
    });
  }

  logger.info(`Geolocation lookup request: ${ip} from IP: ${req.ip}`);

  const geoResult = await ipService.getGeolocation(ip);

  res.json({
    success: true,
    data: {
      ip: ip,
      geolocation: geoResult,
      timestamp: new Date().toISOString()
    }
  });
}));

/**
 * @route   GET /osint/ip/threats/:ip
 * @desc    Get only threat intelligence for an IP address
 * @access  Public
 * @param   {string} ip - IP address
 */
router.get('/threats/:ip', advancedValidation, asyncHandler(async (req, res) => {
  const ip = req.params.ip.trim();
  
  // Basic IP validation
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  
  if (!ipv4Regex.test(ip) && !ipv6Regex.test(ip)) {
    return res.status(400).json({
      success: false,
      error: {
        type: 'VALIDATION_ERROR',
        message: 'Invalid IP address format',
        timestamp: new Date().toISOString()
      }
    });
  }

  logger.info(`Threat intelligence request: ${ip} from IP: ${req.ip}`);

  const [abuseResult, blacklistResult] = await Promise.allSettled([
    ipService.checkAbuseIPDB(ip),
    ipService.checkBlacklists(ip)
  ]);

  const threatData = {
    abuseIPDB: abuseResult.status === 'fulfilled' ? abuseResult.value : null,
    blacklists: blacklistResult.status === 'fulfilled' ? blacklistResult.value : null
  };

  res.json({
    success: true,
    data: {
      ip: ip,
      threats: threatData,
      timestamp: new Date().toISOString()
    }
  });
}));

/**
 * @route   GET /osint/ip/reverse/:ip
 * @desc    Get reverse DNS information for an IP address
 * @access  Public
 * @param   {string} ip - IP address
 */
router.get('/reverse/:ip', advancedValidation, asyncHandler(async (req, res) => {
  const ip = req.params.ip.trim();
  
  // Basic IP validation
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  
  if (!ipv4Regex.test(ip) && !ipv6Regex.test(ip)) {
    return res.status(400).json({
      success: false,
      error: {
        type: 'VALIDATION_ERROR',
        message: 'Invalid IP address format',
        timestamp: new Date().toISOString()
      }
    });
  }

  logger.info(`Reverse DNS lookup request: ${ip} from IP: ${req.ip}`);

  const reverseResult = await ipService.performReverseDNS(ip);

  res.json({
    success: true,
    data: {
      ip: ip,
      reverseDNS: reverseResult,
      timestamp: new Date().toISOString()
    }
  });
}));

/**
 * @route   GET /osint/ip/ranges
 * @desc    Get information about IP address ranges and classifications
 * @access  Public
 */
router.get('/ranges', (req, res) => {
  res.json({
    success: true,
    data: {
      classifications: {
        residential: {
          description: 'IP addresses assigned to home internet connections',
          riskLevel: 'low',
          characteristics: ['Dynamic assignment', 'ISP managed', 'Residential location'],
          commonPorts: [80, 443, 25, 110, 995, 143, 993]
        },
        datacenter: {
          description: 'IP addresses from hosting providers and data centers',
          riskLevel: 'medium',
          characteristics: ['Static assignment', 'Server hosting', 'Business location'],
          commonPorts: [22, 80, 443, 8080, 8443]
        },
        cloud: {
          description: 'IP addresses from major cloud service providers',
          riskLevel: 'medium',
          characteristics: ['Scalable infrastructure', 'API accessible', 'Global presence'],
          providers: ['AWS', 'Google Cloud', 'Azure', 'DigitalOcean']
        },
        mobile: {
          description: 'IP addresses from mobile carrier networks',
          riskLevel: 'low',
          characteristics: ['Mobile device access', 'Carrier managed', 'Location tracking'],
          commonPorts: [80, 443]
        },
        vpn_proxy: {
          description: 'IP addresses from VPN or proxy services',
          riskLevel: 'high',
          characteristics: ['Privacy focused', 'Traffic routing', 'Identity masking'],
          detection: ['Known VPN ranges', 'Hosting provider overlap']
        },
        tor: {
          description: 'IP addresses from Tor exit nodes',
          riskLevel: 'high',
          characteristics: ['Anonymity network', 'Encrypted routing', 'Exit node'],
          detection: ['Tor network lists', 'Known exit nodes']
        }
      },
      specialRanges: {
        private: {
          description: 'RFC 1918 private IP ranges',
          ranges: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
          riskLevel: 'low',
          note: 'Internal network addresses'
        },
        loopback: {
          description: 'Loopback addresses',
          ranges: ['127.0.0.0/8', '::1/128'],
          riskLevel: 'none',
          note: 'Local system addresses'
        },
        multicast: {
          description: 'Multicast addresses',
          ranges: ['224.0.0.0/4', 'ff00::/8'],
          riskLevel: 'low',
          note: 'Group communication addresses'
        },
        reserved: {
          description: 'Reserved or special-use addresses',
          ranges: ['0.0.0.0/8', '169.254.0.0/16', '240.0.0.0/4'],
          riskLevel: 'medium',
          note: 'Should not appear in normal traffic'
        }
      },
      riskFactors: [
        'Known malicious activity',
        'Blacklist presence',
        'VPN/Proxy usage',
        'Tor network participation',
        'Suspicious geolocation',
        'High-risk country origin',
        'Hosting provider reputation'
      ]
    }
  });
});

/**
 * @route   GET /osint/ip/help
 * @desc    Get help information for IP address investigation
 * @access  Public
 */
router.get('/help', (req, res) => {
  res.json({
    success: true,
    data: {
      endpoint: '/osint/ip',
      method: 'GET',
      description: 'Comprehensive IP address investigation including geolocation, threat intelligence, and reputation analysis',
      parameters: {
        value: {
          required: true,
          type: 'string',
          description: 'IP address to investigate (IPv4 or IPv6)',
          validation: 'Valid IP address format required',
          examples: ['192.168.1.1', '8.8.8.8', '2001:4860:4860::8888']
        }
      },
      response: {
        description: 'IP investigation results with comprehensive analysis',
        structure: {
          query: 'Original IP address query',
          type: 'Investigation type (ip)',
          timestamp: 'Investigation timestamp',
          overallRisk: 'Risk assessment (low/medium/high/critical)',
          geolocation: 'Location and network information',
          threatIntelligence: 'Security threat data from AbuseIPDB',
          reverseDNS: 'Reverse DNS lookup results',
          blacklistCheck: 'DNS blacklist verification',
          typeAnalysis: 'IP classification and characteristics',
          recommendations: 'Security recommendations based on findings'
        }
      },
      subEndpoints: {
        '/osint/ip/geolocation/:ip': 'Geolocation information only',
        '/osint/ip/threats/:ip': 'Threat intelligence only',
        '/osint/ip/reverse/:ip': 'Reverse DNS lookup only'
      },
      riskLevels: {
        low: 'Clean IP with no threats detected',
        medium: 'Some security concerns or unusual characteristics',
        high: 'Multiple threats or VPN/Proxy detection',
        critical: 'Active threats or malicious activity detected'
      },
      dataSources: {
        geolocation: ['IPinfo.io', 'IP-API.com'],
        threats: ['AbuseIPDB', 'DNS blacklists'],
        classification: ['ISP detection', 'Cloud provider identification'],
        privacy: ['VPN detection', 'Proxy identification', 'Tor exit node lists']
      },
      examples: [
        '/osint/ip?value=8.8.8.8',
        '/osint/ip?value=1.1.1.1',
        '/osint/ip/geolocation/8.8.4.4',
        '/osint/ip/threats/1.2.3.4'
      ],
      rateLimits: '100 requests per 15 minutes per IP',
      tips: [
        'API keys enhance data quality and remove limitations',
        'VPN/Proxy detection helps identify masked traffic',
        'Threat intelligence data is updated regularly',
        'Reverse DNS can reveal hosting provider information',
        'Private IP ranges are identified automatically'
      ]
    }
  });
});

module.exports = router;
