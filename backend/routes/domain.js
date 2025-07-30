const express = require('express');
const router = express.Router();
const domainService = require('../services/domainService');
const { validateQuery, advancedValidation } = require('../utils/validator');
const { asyncHandler } = require('../utils/errorHandler');
const logger = require('../utils/logger');

/**
 * @route   GET /osint/domain
 * @desc    Investigate domain for WHOIS, DNS, subdomains, and security
 * @access  Public
 * @param   {string} value - Domain name to investigate
 * @example GET /osint/domain?value=example.com
 */
router.get('/', advancedValidation, (req, res, next) => {
  req.routeType = 'domain';
  next();
}, validateQuery, asyncHandler(async (req, res) => {
  const { value } = req.validatedInput;
  
  logger.info(`Domain investigation request: ${value} from IP: ${req.ip}`);

  // Perform the investigation
  const results = await domainService.investigate(value);

  // Log the results summary
  logger.info(`Domain investigation completed for ${value}: risk level ${results.overallRisk}`);

  res.json({
    success: true,
    data: results,
    meta: {
      query: value,
      type: 'domain',
      timestamp: results.timestamp,
      processingTime: Date.now() - new Date(results.timestamp).getTime(),
      requestId: req.headers['x-request-id'] || 'unknown'
    }
  });
}));

/**
 * @route   GET /osint/domain/whois/:domain
 * @desc    Get only WHOIS information for a domain
 * @access  Public
 * @param   {string} domain - Domain name
 */
router.get('/whois/:domain', advancedValidation, asyncHandler(async (req, res) => {
  const domain = req.params.domain.toLowerCase().trim();
  
  // Basic domain validation
  if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(domain)) {
    return res.status(400).json({
      success: false,
      error: {
        type: 'VALIDATION_ERROR',
        message: 'Invalid domain format',
        timestamp: new Date().toISOString()
      }
    });
  }

  logger.info(`WHOIS lookup request: ${domain} from IP: ${req.ip}`);

  const whoisResult = await domainService.performWhoisLookup(domain);

  res.json({
    success: true,
    data: {
      domain: domain,
      whois: whoisResult,
      timestamp: new Date().toISOString()
    }
  });
}));

/**
 * @route   GET /osint/domain/dns/:domain
 * @desc    Get only DNS records for a domain
 * @access  Public
 * @param   {string} domain - Domain name
 */
router.get('/dns/:domain', advancedValidation, asyncHandler(async (req, res) => {
  const domain = req.params.domain.toLowerCase().trim();
  
  // Basic domain validation
  if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(domain)) {
    return res.status(400).json({
      success: false,
      error: {
        type: 'VALIDATION_ERROR',
        message: 'Invalid domain format',
        timestamp: new Date().toISOString()
      }
    });
  }

  logger.info(`DNS lookup request: ${domain} from IP: ${req.ip}`);

  const dnsResult = await domainService.performDnsLookup(domain);

  res.json({
    success: true,
    data: {
      domain: domain,
      dns: dnsResult,
      timestamp: new Date().toISOString()
    }
  });
}));

/**
 * @route   GET /osint/domain/subdomains/:domain
 * @desc    Get only subdomain discovery for a domain
 * @access  Public
 * @param   {string} domain - Domain name
 */
router.get('/subdomains/:domain', advancedValidation, asyncHandler(async (req, res) => {
  const domain = req.params.domain.toLowerCase().trim();
  
  // Basic domain validation
  if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(domain)) {
    return res.status(400).json({
      success: false,
      error: {
        type: 'VALIDATION_ERROR',
        message: 'Invalid domain format',
        timestamp: new Date().toISOString()
      }
    });
  }

  logger.info(`Subdomain discovery request: ${domain} from IP: ${req.ip}`);

  const subdomainResult = await domainService.discoverSubdomains(domain);

  res.json({
    success: true,
    data: {
      domain: domain,
      subdomains: subdomainResult,
      timestamp: new Date().toISOString()
    }
  });
}));

/**
 * @route   GET /osint/domain/security/:domain
 * @desc    Get only security analysis for a domain
 * @access  Public
 * @param   {string} domain - Domain name
 */
router.get('/security/:domain', advancedValidation, asyncHandler(async (req, res) => {
  const domain = req.params.domain.toLowerCase().trim();
  
  // Basic domain validation
  if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(domain)) {
    return res.status(400).json({
      success: false,
      error: {
        type: 'VALIDATION_ERROR',
        message: 'Invalid domain format',
        timestamp: new Date().toISOString()
      }
    });
  }

  logger.info(`Domain security check request: ${domain} from IP: ${req.ip}`);

  const securityResult = await domainService.checkDomainSecurity(domain);

  res.json({
    success: true,
    data: {
      domain: domain,
      security: securityResult,
      timestamp: new Date().toISOString()
    }
  });
}));

/**
 * @route   GET /osint/domain/tools
 * @desc    Get list of domain investigation tools and techniques
 * @access  Public
 */
router.get('/tools', (req, res) => {
  res.json({
    success: true,
    data: {
      techniques: [
        {
          name: 'WHOIS Lookup',
          description: 'Domain registration and ownership information',
          dataAvailable: ['registrar', 'creation_date', 'expiration_date', 'registrant_info', 'name_servers'],
          accuracy: 'High for public domains'
        },
        {
          name: 'DNS Records',
          description: 'Domain Name System configuration analysis',
          dataAvailable: ['A_records', 'AAAA_records', 'MX_records', 'NS_records', 'TXT_records', 'CNAME_records'],
          accuracy: 'Real-time'
        },
        {
          name: 'Subdomain Discovery',
          description: 'Certificate transparency log analysis',
          dataAvailable: ['subdomains', 'certificate_history', 'wildcard_certificates'],
          accuracy: 'High for domains with certificates'
        },
        {
          name: 'Security Analysis',
          description: 'SSL/TLS and email security configuration',
          dataAvailable: ['ssl_status', 'certificate_validity', 'SPF_records', 'DMARC_records', 'DKIM_records'],
          accuracy: 'Real-time'
        }
      ],
      dataSources: [
        'WHOIS databases',
        'DNS resolvers',
        'Certificate Transparency logs (crt.sh)',
        'SSL/TLS certificate validation',
        'Email security record analysis'
      ],
      limitations: [
        'WHOIS privacy protection may limit data availability',
        'Some domains may have restricted DNS queries',
        'Certificate transparency logs may not include all certificates',
        'Private/internal domains may not be discoverable'
      ]
    }
  });
});

/**
 * @route   GET /osint/domain/help
 * @desc    Get help information for domain investigation
 * @access  Public
 */
router.get('/help', (req, res) => {
  res.json({
    success: true,
    data: {
      endpoint: '/osint/domain',
      method: 'GET',
      description: 'Comprehensive domain investigation including WHOIS, DNS, subdomains, and security analysis',
      parameters: {
        value: {
          required: true,
          type: 'string',
          description: 'Domain name to investigate',
          validation: 'Valid domain format required',
          example: 'example.com'
        }
      },
      response: {
        description: 'Domain investigation results with comprehensive analysis',
        structure: {
          query: 'Original domain query',
          type: 'Investigation type (domain)',
          timestamp: 'Investigation timestamp',
          overallRisk: 'Risk assessment (low/medium/high)',
          whoisData: 'Domain registration information',
          dnsRecords: 'DNS configuration analysis',
          subdomains: 'Discovered subdomains from certificate logs',
          security: 'SSL/TLS and email security analysis',
          ageAnalysis: 'Domain age and registration timeline',
          recommendations: 'Security recommendations based on findings'
        }
      },
      subEndpoints: {
        '/osint/domain/whois/:domain': 'WHOIS information only',
        '/osint/domain/dns/:domain': 'DNS records only',
        '/osint/domain/subdomains/:domain': 'Subdomain discovery only',
        '/osint/domain/security/:domain': 'Security analysis only'
      },
      riskLevels: {
        low: 'Established domain with proper security configuration',
        medium: 'Some security concerns or unusual characteristics',
        high: 'Multiple security issues or suspicious indicators'
      },
      examples: [
        '/osint/domain?value=google.com',
        '/osint/domain?value=example.org',
        '/osint/domain/whois/github.com',
        '/osint/domain/subdomains/microsoft.com'
      ],
      rateLimits: '100 requests per 15 minutes per IP',
      tips: [
        'New domains (< 30 days) are flagged as higher risk',
        'Missing security records (SPF, DMARC) increase risk scores',
        'Certificate transparency logs provide historical subdomain data',
        'Use sub-endpoints for focused analysis on specific aspects'
      ]
    }
  });
});

module.exports = router;
