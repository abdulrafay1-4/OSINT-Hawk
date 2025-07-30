const axios = require('axios');
const logger = require('../utils/logger');
const { OSINTError } = require('../utils/errorHandler');

/**
 * IP address intelligence service
 * Performs comprehensive IP investigation including geolocation, threat intelligence, and reputation checks
 */
class IPService {
  constructor() {
    this.abuseIPDBApiKey = process.env.ABUSEIPDB_API_KEY;
    this.ipinfoApiKey = process.env.IPINFO_API_KEY;
  }

  /**
   * Get IP geolocation information
   */
  async getGeolocation(ip) {
    try {
      // Try IPinfo first (if API key available)
      if (this.ipinfoApiKey) {
        const response = await axios.get(
          `https://ipinfo.io/${ip}?token=${this.ipinfoApiKey}`,
          {
            timeout: 10000,
            validateStatus: (status) => status < 500
          }
        );

        if (response.status === 200) {
          const data = response.data;
          return {
            service: 'IPinfo',
            status: 'success',
            ip: ip,
            location: {
              city: data.city,
              region: data.region,
              country: data.country,
              countryName: this.getCountryName(data.country),
              coordinates: data.loc ? data.loc.split(',').map(coord => parseFloat(coord)) : null,
              timezone: data.timezone,
              postal: data.postal
            },
            network: {
              org: data.org,
              isp: data.org,
              asn: data.org ? data.org.split(' ')[0] : null,
              hostname: data.hostname
            },
            privacy: {
              isVPN: Boolean(data.privacy?.vpn),
              isProxy: Boolean(data.privacy?.proxy),
              isTor: Boolean(data.privacy?.tor),
              isHosting: Boolean(data.privacy?.hosting)
            }
          };
        }
      }

      // Fallback to free IP-API service
      const response = await axios.get(
        `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query,proxy,hosting`,
        {
          timeout: 10000,
          validateStatus: (status) => status < 500
        }
      );

      if (response.status === 200 && response.data.status === 'success') {
        const data = response.data;
        return {
          service: 'IP-API',
          status: 'success',
          ip: ip,
          location: {
            city: data.city,
            region: data.regionName,
            country: data.countryCode,
            countryName: data.country,
            coordinates: [data.lat, data.lon],
            timezone: data.timezone,
            postal: data.zip
          },
          network: {
            org: data.org,
            isp: data.isp,
            asn: data.as,
            hostname: null
          },
          privacy: {
            isVPN: false,
            isProxy: Boolean(data.proxy),
            isTor: false,
            isHosting: Boolean(data.hosting)
          }
        };
      }

      return {
        service: 'Unknown',
        status: 'no_data',
        error: 'No geolocation data available',
        ip: ip
      };
    } catch (error) {
      logger.error(`Geolocation lookup error for ${ip}:`, error.message);
      return {
        service: 'Error',
        status: 'error',
        error: error.message,
        ip: ip
      };
    }
  }

  /**
   * Check IP against AbuseIPDB threat intelligence
   */
  async checkAbuseIPDB(ip) {
    try {
      if (!this.abuseIPDBApiKey) {
        logger.warn('AbuseIPDB API key not configured');
        return {
          service: 'AbuseIPDB',
          status: 'unavailable',
          error: 'API key not configured',
          ip: ip
        };
      }

      const response = await axios.get(
        `https://api.abuseipdb.com/api/v2/check`,
        {
          params: {
            ipAddress: ip,
            maxAgeInDays: 90,
            verbose: true
          },
          headers: {
            'Key': this.abuseIPDBApiKey,
            'Accept': 'application/json'
          },
          timeout: 15000,
          validateStatus: (status) => status < 500
        }
      );

      if (response.status === 200) {
        const data = response.data.data;
        
        let riskLevel = 'low';
        if (data.abuseConfidencePercentage >= 75) riskLevel = 'critical';
        else if (data.abuseConfidencePercentage >= 50) riskLevel = 'high';
        else if (data.abuseConfidencePercentage >= 25) riskLevel = 'medium';

        return {
          service: 'AbuseIPDB',
          status: 'success',
          ip: ip,
          abuseConfidence: data.abuseConfidencePercentage,
          isWhitelisted: data.isWhitelisted,
          countryCode: data.countryCode,
          usageType: data.usageType,
          isp: data.isp,
          domain: data.domain,
          totalReports: data.totalReports,
          numDistinctUsers: data.numDistinctUsers,
          lastReportedAt: data.lastReportedAt,
          riskLevel: riskLevel,
          categories: data.reports ? data.reports.map(report => ({
            categories: report.categories,
            reportedAt: report.reportedAt,
            comment: report.comment
          })) : []
        };
      } else if (response.status === 429) {
        return {
          service: 'AbuseIPDB',
          status: 'rate_limited',
          error: 'API rate limit exceeded',
          ip: ip
        };
      }

      return {
        service: 'AbuseIPDB',
        status: 'no_data',
        error: 'No threat intelligence data available',
        ip: ip
      };
    } catch (error) {
      logger.error(`AbuseIPDB check error for ${ip}:`, error.message);
      return {
        service: 'AbuseIPDB',
        status: 'error',
        error: error.message,
        ip: ip
      };
    }
  }

  /**
   * Perform reverse DNS lookup
   */
  async performReverseDNS(ip) {
    try {
      const dns = require('dns').promises;
      const hostnames = await dns.reverse(ip);
      
      return {
        status: 'success',
        hostnames: hostnames,
        primaryHostname: hostnames[0] || null
      };
    } catch (error) {
      return {
        status: 'no_data',
        error: 'No reverse DNS records found',
        hostnames: []
      };
    }
  }

  /**
   * Check if IP is in known service ranges
   */
  analyzeIPType(ip, geoData) {
    const analysis = {
      type: 'unknown',
      isCloudProvider: false,
      isDatacenter: false,
      isResidential: false,
      isMobile: false,
      provider: null,
      riskLevel: 'medium'
    };

    if (!geoData?.network?.org) {
      return analysis;
    }

    const org = geoData.network.org.toLowerCase();

    // Cloud providers
    const cloudProviders = [
      { names: ['amazon', 'aws', 'ec2'], provider: 'Amazon Web Services' },
      { names: ['google', 'gcp', 'cloud'], provider: 'Google Cloud' },
      { names: ['microsoft', 'azure'], provider: 'Microsoft Azure' },
      { names: ['digitalocean'], provider: 'DigitalOcean' },
      { names: ['linode'], provider: 'Linode' },
      { names: ['vultr'], provider: 'Vultr' },
      { names: ['ovh'], provider: 'OVH' },
      { names: ['hetzner'], provider: 'Hetzner' },
      { names: ['cloudflare'], provider: 'Cloudflare' }
    ];

    for (const cloud of cloudProviders) {
      if (cloud.names.some(name => org.includes(name))) {
        analysis.type = 'cloud';
        analysis.isCloudProvider = true;
        analysis.provider = cloud.provider;
        analysis.riskLevel = 'medium';
        break;
      }
    }

    // Datacenter/hosting providers
    const datacenterKeywords = ['datacenter', 'hosting', 'server', 'colocation', 'data center'];
    if (datacenterKeywords.some(keyword => org.includes(keyword))) {
      analysis.type = analysis.type === 'unknown' ? 'datacenter' : analysis.type;
      analysis.isDatacenter = true;
      analysis.riskLevel = 'medium';
    }

    // ISPs (likely residential)
    const ispKeywords = ['telecom', 'communications', 'internet', 'broadband', 'cable'];
    if (ispKeywords.some(keyword => org.includes(keyword))) {
      analysis.type = analysis.type === 'unknown' ? 'residential' : analysis.type;
      analysis.isResidential = true;
      analysis.riskLevel = 'low';
    }

    // Mobile carriers
    const mobileKeywords = ['mobile', 'cellular', 'wireless', 'gsm', 'lte'];
    if (mobileKeywords.some(keyword => org.includes(keyword))) {
      analysis.type = 'mobile';
      analysis.isMobile = true;
      analysis.riskLevel = 'low';
    }

    // VPN/Proxy detection
    if (geoData.privacy?.isVPN || geoData.privacy?.isProxy) {
      analysis.type = 'vpn_proxy';
      analysis.riskLevel = 'high';
    }

    // Tor detection
    if (geoData.privacy?.isTor) {
      analysis.type = 'tor';
      analysis.riskLevel = 'high';
    }

    return analysis;
  }

  /**
   * Check IP against public blacklists
   */
  async checkBlacklists(ip) {
    const blacklists = [
      'zen.spamhaus.org',
      'bl.spamcop.net',
      'cbl.abuseat.org',
      'dnsbl.sorbs.net'
    ];

    const results = [];
    const dns = require('dns').promises;

    for (const blacklist of blacklists) {
      try {
        // Reverse IP for DNS blacklist query
        const reversedIP = ip.split('.').reverse().join('.');
        const query = `${reversedIP}.${blacklist}`;
        
        await dns.resolve4(query);
        
        // If we get here, IP is listed
        results.push({
          blacklist: blacklist,
          listed: true,
          status: 'listed'
        });
      } catch (error) {
        // IP not listed (expected for clean IPs)
        results.push({
          blacklist: blacklist,
          listed: false,
          status: 'clean'
        });
      }
    }

    const listedCount = results.filter(r => r.listed).length;
    
    return {
      status: 'success',
      totalChecked: blacklists.length,
      listedCount: listedCount,
      riskLevel: listedCount > 0 ? (listedCount >= 2 ? 'high' : 'medium') : 'low',
      results: results
    };
  }

  /**
   * Get country name from country code
   */
  getCountryName(countryCode) {
    const countries = {
      'US': 'United States',
      'CA': 'Canada',
      'GB': 'United Kingdom',
      'DE': 'Germany',
      'FR': 'France',
      'JP': 'Japan',
      'CN': 'China',
      'RU': 'Russia',
      'BR': 'Brazil',
      'IN': 'India',
      'AU': 'Australia',
      'NL': 'Netherlands',
      'SE': 'Sweden',
      'NO': 'Norway',
      'DK': 'Denmark',
      'FI': 'Finland',
      'IT': 'Italy',
      'ES': 'Spain',
      'PL': 'Poland',
      'CH': 'Switzerland'
    };

    return countries[countryCode] || countryCode;
  }

  /**
   * Comprehensive IP investigation
   */
  async investigate(ip) {
    try {
      logger.info(`Starting IP investigation for: ${ip}`);

      const [geoResult, abuseResult, dnsResult, blacklistResult] = await Promise.allSettled([
        this.getGeolocation(ip),
        this.checkAbuseIPDB(ip),
        this.performReverseDNS(ip),
        this.checkBlacklists(ip)
      ]);

      const geoData = geoResult.status === 'fulfilled' ? geoResult.value : null;
      const abuseData = abuseResult.status === 'fulfilled' ? abuseResult.value : null;
      const dnsData = dnsResult.status === 'fulfilled' ? dnsResult.value : null;
      const blacklistData = blacklistResult.status === 'fulfilled' ? blacklistResult.value : null;

      // Analyze IP type
      const typeAnalysis = this.analyzeIPType(ip, geoData);

      // Calculate overall risk
      const riskFactors = [
        abuseData?.riskLevel,
        blacklistData?.riskLevel,
        typeAnalysis.riskLevel
      ].filter(Boolean);

      const overallRisk = this.calculateOverallRisk(riskFactors);

      const summary = {
        query: ip,
        type: 'ip',
        timestamp: new Date().toISOString(),
        overallRisk: overallRisk,
        geolocation: geoData,
        threatIntelligence: abuseData,
        reverseDNS: dnsData,
        blacklistCheck: blacklistData,
        typeAnalysis: typeAnalysis,
        recommendations: this.generateRecommendations(geoData, abuseData, blacklistData, typeAnalysis)
      };

      logger.info(`IP investigation completed for ${ip}: risk level ${overallRisk}`);
      return summary;

    } catch (error) {
      logger.error(`IP investigation failed for ${ip}:`, error);
      throw new OSINTError(`IP investigation failed: ${error.message}`, 500, 'SERVICE_ERROR');
    }
  }

  /**
   * Calculate overall risk
   */
  calculateOverallRisk(riskFactors) {
    const riskValues = { low: 1, medium: 2, high: 3, critical: 4, unknown: 1.5 };
    const totalRisk = riskFactors.reduce((sum, risk) => sum + (riskValues[risk] || 1), 0);
    const avgRisk = totalRisk / riskFactors.length;

    if (avgRisk >= 3.5) return 'critical';
    if (avgRisk >= 2.5) return 'high';
    if (avgRisk >= 1.5) return 'medium';
    return 'low';
  }

  /**
   * Generate recommendations
   */
  generateRecommendations(geoData, abuseData, blacklistData, typeAnalysis) {
    const recommendations = [];

    if (abuseData?.abuseConfidence >= 50) {
      recommendations.push('IP has high abuse confidence - block or monitor closely');
      recommendations.push('Review recent reports and threat indicators');
    }

    if (blacklistData?.listedCount > 0) {
      recommendations.push(`IP is listed on ${blacklistData.listedCount} blacklist(s) - investigate further`);
      recommendations.push('Consider blocking or implementing additional security measures');
    }

    if (typeAnalysis.type === 'vpn_proxy' || typeAnalysis.type === 'tor') {
      recommendations.push('IP is associated with VPN/Proxy/Tor - verify legitimate use');
      recommendations.push('Implement additional verification for sensitive operations');
    }

    if (typeAnalysis.isCloudProvider) {
      recommendations.push('IP belongs to cloud provider - monitor for automated activity');
      recommendations.push('Verify legitimate business use if unexpected');
    }

    if (geoData?.location?.country) {
      const riskCountries = ['CN', 'RU', 'KP', 'IR'];
      if (riskCountries.includes(geoData.location.country)) {
        recommendations.push('IP originates from high-risk country - enhanced monitoring recommended');
      }
    }

    if (recommendations.length === 0) {
      recommendations.push('IP appears to be clean with no immediate threats detected');
      recommendations.push('Continue standard monitoring practices');
    }

    return recommendations;
  }
}

module.exports = new IPService();
