const axios = require('axios');
const whois = require('whois');
const dns = require('dns').promises;
const logger = require('../utils/logger');
const { OSINTError } = require('../utils/errorHandler');

/**
 * Domain analysis service
 * Performs comprehensive domain investigation including WHOIS, DNS, and subdomain discovery
 */
class DomainService {
  constructor() {
    this.securityTrailsApiKey = process.env.SECURITYTRAILS_API_KEY;
  }

  /**
   * Perform WHOIS lookup
   */
  async performWhoisLookup(domain) {
    return new Promise((resolve) => {
      whois.lookup(domain, (err, data) => {
        if (err) {
          logger.error(`WHOIS lookup error for ${domain}:`, err.message);
          resolve({
            status: 'error',
            error: err.message,
            data: null
          });
          return;
        }

        try {
          const parsedData = this.parseWhoisData(data);
          resolve({
            status: 'success',
            data: parsedData,
            raw: data
          });
        } catch (parseError) {
          logger.error(`WHOIS parsing error for ${domain}:`, parseError.message);
          resolve({
            status: 'error',
            error: 'Failed to parse WHOIS data',
            data: null,
            raw: data
          });
        }
      });
    });
  }

  /**
   * Parse WHOIS data into structured format
   */
  parseWhoisData(whoisText) {
    const lines = whoisText.split('\n');
    const data = {};

    const patterns = {
      registrar: /registrar:\s*(.+)/i,
      registrant: /registrant.*?:\s*(.+)/i,
      creationDate: /creat(?:ed|ion).*?:\s*(.+)/i,
      expirationDate: /expir(?:y|ation).*?:\s*(.+)/i,
      updatedDate: /updated.*?:\s*(.+)/i,
      nameServers: /name server:\s*(.+)/gi,
      status: /status:\s*(.+)/gi,
      registrantOrg: /registrant.*?organization:\s*(.+)/i,
      registrantCountry: /registrant.*?country:\s*(.+)/i,
      adminEmail: /admin.*?email:\s*(.+)/i,
      techEmail: /tech.*?email:\s*(.+)/i
    };

    lines.forEach(line => {
      line = line.trim();
      
      Object.entries(patterns).forEach(([key, pattern]) => {
        if (key === 'nameServers' || key === 'status') {
          const matches = whoisText.match(pattern);
          if (matches) {
            data[key] = matches.map(match => match.split(':')[1].trim());
          }
        } else {
          const match = line.match(pattern);
          if (match && !data[key]) {
            data[key] = match[1].trim();
          }
        }
      });
    });

    return data;
  }

  /**
   * Perform DNS record lookup
   */
  async performDnsLookup(domain) {
    try {
      const results = {};

      // A records
      try {
        results.A = await dns.resolve4(domain);
      } catch (err) {
        results.A = [];
      }

      // AAAA records (IPv6)
      try {
        results.AAAA = await dns.resolve6(domain);
      } catch (err) {
        results.AAAA = [];
      }

      // MX records
      try {
        results.MX = await dns.resolveMx(domain);
      } catch (err) {
        results.MX = [];
      }

      // NS records
      try {
        results.NS = await dns.resolveNs(domain);
      } catch (err) {
        results.NS = [];
      }

      // TXT records
      try {
        results.TXT = await dns.resolveTxt(domain);
      } catch (err) {
        results.TXT = [];
      }

      // CNAME records
      try {
        results.CNAME = await dns.resolveCname(domain);
      } catch (err) {
        results.CNAME = [];
      }

      // SOA record
      try {
        results.SOA = await dns.resolveSoa(domain);
      } catch (err) {
        results.SOA = null;
      }

      return {
        status: 'success',
        records: results
      };
    } catch (error) {
      logger.error(`DNS lookup error for ${domain}:`, error.message);
      return {
        status: 'error',
        error: error.message,
        records: {}
      };
    }
  }

  /**
   * Discover subdomains using certificate transparency logs
   */
  async discoverSubdomains(domain) {
    try {
      // Using crt.sh certificate transparency logs
      const response = await axios.get(
        `https://crt.sh/?q=%.${domain}&output=json`,
        {
          timeout: 15000,
          validateStatus: (status) => status < 500
        }
      );

      if (response.status === 200 && Array.isArray(response.data)) {
        const subdomains = new Set();
        
        response.data.forEach(cert => {
          if (cert.name_value) {
            const names = cert.name_value.split('\n');
            names.forEach(name => {
              name = name.trim().toLowerCase();
              if (name.includes(domain) && !name.includes('*')) {
                subdomains.add(name);
              }
            });
          }
        });

        const subdomainList = Array.from(subdomains)
          .filter(sub => sub !== domain)
          .slice(0, 50); // Limit to 50 subdomains

        return {
          status: 'success',
          count: subdomainList.length,
          subdomains: subdomainList,
          source: 'Certificate Transparency Logs'
        };
      }

      return {
        status: 'no_data',
        count: 0,
        subdomains: [],
        source: 'Certificate Transparency Logs'
      };
    } catch (error) {
      logger.error(`Subdomain discovery error for ${domain}:`, error.message);
      return {
        status: 'error',
        error: error.message,
        count: 0,
        subdomains: []
      };
    }
  }

  /**
   * Check domain reputation and security
   */
  async checkDomainSecurity(domain) {
    try {
      const securityChecks = {
        hasSSL: false,
        hasValidCert: false,
        hasSPF: false,
        hasDMARC: false,
        hasDKIM: false,
        riskLevel: 'unknown'
      };

      // Check for SSL/TLS
      try {
        const response = await axios.get(`https://${domain}`, {
          timeout: 10000,
          maxRedirects: 0,
          validateStatus: () => true
        });
        securityChecks.hasSSL = true;
        securityChecks.hasValidCert = true;
      } catch (error) {
        if (error.code === 'CERT_HAS_EXPIRED' || error.code === 'CERT_UNTRUSTED') {
          securityChecks.hasSSL = true;
          securityChecks.hasValidCert = false;
        }
      }

      // Check for email security records
      try {
        const txtRecords = await dns.resolveTxt(domain);
        txtRecords.forEach(record => {
          const recordText = record.join('').toLowerCase();
          if (recordText.includes('v=spf1')) {
            securityChecks.hasSPF = true;
          }
          if (recordText.includes('v=dmarc1')) {
            securityChecks.hasDMARC = true;
          }
        });

        // Check for DKIM
        try {
          const dkimRecords = await dns.resolveTxt(`default._domainkey.${domain}`);
          if (dkimRecords.length > 0) {
            securityChecks.hasDKIM = true;
          }
        } catch (err) {
          // DKIM not found or error
        }
      } catch (err) {
        // TXT records not available
      }

      // Calculate risk level
      let riskScore = 0;
      if (!securityChecks.hasSSL) riskScore += 2;
      if (!securityChecks.hasValidCert) riskScore += 1;
      if (!securityChecks.hasSPF) riskScore += 1;
      if (!securityChecks.hasDMARC) riskScore += 1;

      if (riskScore >= 4) securityChecks.riskLevel = 'high';
      else if (riskScore >= 2) securityChecks.riskLevel = 'medium';
      else securityChecks.riskLevel = 'low';

      return {
        status: 'success',
        security: securityChecks
      };
    } catch (error) {
      logger.error(`Domain security check error for ${domain}:`, error.message);
      return {
        status: 'error',
        error: error.message,
        security: {}
      };
    }
  }

  /**
   * Get domain age and registration info
   */
  analyzeDomainAge(whoisData) {
    try {
      if (!whoisData || !whoisData.creationDate) {
        return {
          age: 'unknown',
          ageInDays: null,
          riskLevel: 'medium'
        };
      }

      const creationDate = new Date(whoisData.creationDate);
      const now = new Date();
      const ageInDays = Math.floor((now - creationDate) / (1000 * 60 * 60 * 24));
      const ageInYears = Math.floor(ageInDays / 365);

      let riskLevel = 'low';
      if (ageInDays < 30) riskLevel = 'high';
      else if (ageInDays < 365) riskLevel = 'medium';

      return {
        age: ageInYears > 0 ? `${ageInYears} years` : `${ageInDays} days`,
        ageInDays: ageInDays,
        creationDate: creationDate.toISOString(),
        riskLevel: riskLevel
      };
    } catch (error) {
      return {
        age: 'unknown',
        ageInDays: null,
        riskLevel: 'medium',
        error: error.message
      };
    }
  }

  /**
   * Comprehensive domain investigation
   */
  async investigate(domain) {
    try {
      logger.info(`Starting domain investigation for: ${domain}`);

      const [whoisResult, dnsResult, subdomainResult, securityResult] = await Promise.allSettled([
        this.performWhoisLookup(domain),
        this.performDnsLookup(domain),
        this.discoverSubdomains(domain),
        this.checkDomainSecurity(domain)
      ]);

      const whoisData = whoisResult.status === 'fulfilled' ? whoisResult.value : null;
      const dnsData = dnsResult.status === 'fulfilled' ? dnsResult.value : null;
      const subdomainData = subdomainResult.status === 'fulfilled' ? subdomainResult.value : null;
      const securityData = securityResult.status === 'fulfilled' ? securityResult.value : null;

      // Analyze domain age
      const ageAnalysis = this.analyzeDomainAge(whoisData?.data);

      // Calculate overall risk
      const riskFactors = [
        ageAnalysis.riskLevel,
        securityData?.security?.riskLevel
      ].filter(Boolean);

      const overallRisk = this.calculateOverallRisk(riskFactors);

      const summary = {
        query: domain,
        type: 'domain',
        timestamp: new Date().toISOString(),
        overallRisk: overallRisk,
        whoisData: whoisData,
        dnsRecords: dnsData,
        subdomains: subdomainData,
        security: securityData,
        ageAnalysis: ageAnalysis,
        recommendations: this.generateRecommendations(whoisData, securityData, ageAnalysis, subdomainData)
      };

      logger.info(`Domain investigation completed for ${domain}: risk level ${overallRisk}`);
      return summary;

    } catch (error) {
      logger.error(`Domain investigation failed for ${domain}:`, error);
      throw new OSINTError(`Domain investigation failed: ${error.message}`, 500, 'SERVICE_ERROR');
    }
  }

  /**
   * Calculate overall risk
   */
  calculateOverallRisk(riskFactors) {
    const riskValues = { low: 1, medium: 2, high: 3, unknown: 1.5 };
    const totalRisk = riskFactors.reduce((sum, risk) => sum + (riskValues[risk] || 1), 0);
    const avgRisk = totalRisk / riskFactors.length;

    if (avgRisk >= 2.5) return 'high';
    if (avgRisk >= 1.5) return 'medium';
    return 'low';
  }

  /**
   * Generate recommendations
   */
  generateRecommendations(whoisData, securityData, ageAnalysis, subdomainData) {
    const recommendations = [];

    if (ageAnalysis.ageInDays !== null && ageAnalysis.ageInDays < 30) {
      recommendations.push('Domain is very new - exercise caution');
      recommendations.push('Verify domain legitimacy through additional means');
    }

    if (securityData?.security) {
      const security = securityData.security;
      
      if (!security.hasSSL) {
        recommendations.push('Domain does not support SSL/TLS - security risk');
      }
      
      if (!security.hasValidCert && security.hasSSL) {
        recommendations.push('Domain has invalid SSL certificate');
      }
      
      if (!security.hasSPF) {
        recommendations.push('Domain lacks SPF record - email spoofing risk');
      }
      
      if (!security.hasDMARC) {
        recommendations.push('Domain lacks DMARC record - email security concern');
      }
    }

    if (subdomainData?.count > 20) {
      recommendations.push('Large number of subdomains detected - review for suspicious activity');
    }

    if (whoisData?.status === 'error') {
      recommendations.push('WHOIS data unavailable - domain may be private or restricted');
    }

    if (recommendations.length === 0) {
      recommendations.push('Domain appears to have standard security configuration');
      recommendations.push('Continue monitoring for changes');
    }

    return recommendations;
  }
}

module.exports = new DomainService();
