const axios = require('axios');
const logger = require('../utils/logger');
const { OSINTError } = require('../utils/errorHandler');

/**
 * Email intelligence service
 * Performs comprehensive email investigation including breach checks
 */
class EmailService {
  constructor() {
    this.hibpApiKey = process.env.HAVEIBEENPWNED_API_KEY;
    this.githubToken = process.env.GITHUB_API_TOKEN;
  }

  /**
   * Check email against HaveIBeenPwned database
   */
  async checkHaveIBeenPwned(email) {
    try {
      // Email validation and analysis (free alternatives)
  let breachResults = {
    service: 'EmailAnalysis',
    status: 'success',
    breaches: [],
    analysis: {}
  };

  try {
    // Basic email pattern analysis
    const emailParts = email.split('@');
    const username = emailParts[0];
    const domain = emailParts[1];

    // Check for common patterns that might indicate compromised accounts
    const suspiciousPatterns = {
      randomNumbers: /\d{4,}$/.test(username), // ends with 4+ numbers
      commonPasswords: /^(admin|test|user|guest|demo|sample)/i.test(username),
      disposableEmail: isDisposableEmail(domain),
      commonProvider: isCommonEmailProvider(domain)
    };

    // Domain reputation check (basic)
    const domainAnalysis = {
      isDisposable: suspiciousPatterns.disposableEmail,
      isCommonProvider: suspiciousPatterns.commonProvider,
      hasTypo: checkForCommonTypos(domain)
    };

    // Social media username detection
    const socialPatterns = {
      likelyUsername: username.length >= 3 && !/\d{4,}$/.test(username),
      containsPersonalInfo: /\d{4}|19\d{2}|20\d{2}/.test(username), // birth years
      commonFormat: /^[a-zA-Z]+\d{0,3}$/.test(username)
    };

    breachResults = {
      service: 'EmailAnalysis',
      status: 'success',
      breaches: [], // No breach data without paid API
      analysis: {
        domain: domainAnalysis,
        username: socialPatterns,
        suspiciousPatterns,
        recommendations: generateEmailRecommendations(suspiciousPatterns, socialPatterns)
      }
    };

  } catch (error) {
    breachResults = {
      service: 'EmailAnalysis',
      status: 'error',
      error: error.message,
      breaches: [],
      analysis: {}
    };
  }

  // Helper functions for email analysis
  function isDisposableEmail(domain) {
    const disposableDomains = [
      '10minutemail.com', 'tempmail.org', 'guerrillamail.com', 
      'mailinator.com', 'throwaway.email', 'temp-mail.org',
      'getnada.com', 'maildrop.cc', 'yopmail.com'
    ];
    return disposableDomains.includes(domain.toLowerCase());
  }

  function isCommonEmailProvider(domain) {
    const commonProviders = [
      'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
      'aol.com', 'icloud.com', 'protonmail.com', 'live.com'
    ];
    return commonProviders.includes(domain.toLowerCase());
  }

  function checkForCommonTypos(domain) {
    const commonTypos = {
      'gmail.com': ['gmial.com', 'gmai.com', 'gmaol.com'],
      'yahoo.com': ['yaho.com', 'yahho.com', 'yahooo.com'],
      'hotmail.com': ['hotmai.com', 'hotmial.com', 'hotmali.com']
    };
    
    for (const [correct, typos] of Object.entries(commonTypos)) {
      if (typos.includes(domain.toLowerCase())) {
        return { hasTypo: true, suggestion: correct };
      }
    }
    return { hasTypo: false };
  }

  function generateEmailRecommendations(suspicious, social) {
    const recommendations = [];
    
    if (suspicious.disposableEmail) {
      recommendations.push('Email uses disposable/temporary service - high risk');
    }
    if (suspicious.randomNumbers) {
      recommendations.push('Username ends with random numbers - may indicate automated creation');
    }
    if (suspicious.commonPasswords) {
      recommendations.push('Username follows common default pattern - check for weak security');
    }
    if (social.containsPersonalInfo) {
      recommendations.push('Username may contain personal information (birth year)');
    }
    if (!suspicious.disposableEmail && social.likelyUsername) {
      recommendations.push('Username suitable for social media search');
    }
    
    if (recommendations.length === 0) {
      recommendations.push('No immediate security concerns detected');
    }
    
    return recommendations;
  },

  /**
   * Check for email mentions on GitHub (simplified without API)
   */
  async checkGitHubMentions(email) {
    // Simplified GitHub analysis without API
    return {
      service: 'GitHub',
      status: 'unavailable',
      error: 'API token not configured',
      mentions: []
    };
  },

      const searchQuery = `"${email}" in:file`;
      const response = await axios.get(
        `https://api.github.com/search/code?q=${encodeURIComponent(searchQuery)}`,
        {
          headers: {
            'Authorization': `token ${this.githubToken}`,
            'User-Agent': 'OSINT-Hawk/1.0',
            'Accept': 'application/vnd.github.v3+json'
          },
          timeout: 15000,
          validateStatus: (status) => status < 500
        }
      );

      if (response.status === 200) {
        const mentions = response.data.items.slice(0, 10).map(item => ({
          repository: item.repository.full_name,
          filePath: item.path,
          htmlUrl: item.html_url,
          score: item.score,
          repositoryUrl: item.repository.html_url,
          isPrivate: item.repository.private,
          language: item.repository.language,
          stars: item.repository.stargazers_count
        }));

        return {
          service: 'GitHub',
          status: mentions.length > 0 ? 'found' : 'clean',
          mentionCount: response.data.total_count,
          mentions: mentions,
          riskLevel: mentions.length > 0 ? 'medium' : 'low',
          lastChecked: new Date().toISOString()
        };
      } else if (response.status === 403) {
        return {
          service: 'GitHub',
          status: 'rate_limited',
          error: 'API rate limit exceeded',
          mentions: [],
          riskLevel: 'unknown'
        };
      }
    } catch (error) {
      logger.error(`GitHub search error for ${email}:`, error.message);
      return {
        service: 'GitHub',
        status: 'error',
        error: error.message,
        mentions: [],
        riskLevel: 'unknown'
      };
    }
  }

  /**
   * Analyze email domain for reputation
   */
  async analyzeDomain(email) {
    try {
      const domain = email.split('@')[1];
      
      // Check if it's a disposable email domain
      const disposableDomains = [
        '10minutemail.com', 'mailinator.com', 'guerrillamail.com',
        'temp-mail.org', 'throwaway.email', 'yopmail.com'
      ];

      const isDisposable = disposableDomains.includes(domain.toLowerCase());

      // Check if it's a common email provider
      const commonProviders = [
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
        'icloud.com', 'aol.com', 'protonmail.com'
      ];

      const isCommonProvider = commonProviders.includes(domain.toLowerCase());

      return {
        domain: domain,
        isDisposable: isDisposable,
        isCommonProvider: isCommonProvider,
        riskLevel: isDisposable ? 'high' : (isCommonProvider ? 'low' : 'medium'),
        analysis: {
          type: isDisposable ? 'disposable' : (isCommonProvider ? 'common' : 'custom'),
          reputation: isDisposable ? 'poor' : 'unknown'
        }
      };
    } catch (error) {
      logger.error(`Domain analysis error for ${email}:`, error.message);
      return {
        domain: email.split('@')[1],
        error: error.message,
        riskLevel: 'unknown'
      };
    }
  }

  /**
   * Calculate breach risk level based on breach data
   */
  calculateBreachRisk(breaches) {
    if (breaches.length === 0) return 'low';
    
    let riskScore = 0;
    
    breaches.forEach(breach => {
      // Base score for any breach
      riskScore += 1;
      
      // Additional risk for sensitive data
      if (breach.isSensitive) riskScore += 2;
      
      // Additional risk for unverified breaches
      if (!breach.isVerified) riskScore += 1;
      
      // Additional risk for large breaches
      if (breach.pwnCount > 1000000) riskScore += 1;
      
      // Additional risk for recent breaches
      const breachDate = new Date(breach.breachDate);
      const monthsAgo = (Date.now() - breachDate.getTime()) / (1000 * 60 * 60 * 24 * 30);
      if (monthsAgo < 12) riskScore += 1;
      
      // Risk for sensitive data types
      const sensitiveDataTypes = ['passwords', 'social security numbers', 'credit cards', 'phone numbers'];
      if (breach.dataClasses.some(dataClass => 
        sensitiveDataTypes.some(sensitive => 
          dataClass.toLowerCase().includes(sensitive)
        )
      )) {
        riskScore += 2;
      }
    });

    if (riskScore >= 8) return 'critical';
    if (riskScore >= 5) return 'high';
    if (riskScore >= 3) return 'medium';
    return 'low';
  }

  /**
   * Comprehensive email investigation
   */
  async investigate(email) {
    try {
      logger.info(`Starting email investigation for: ${email}`);

      const [hibpResult, githubResult, domainResult] = await Promise.allSettled([
        this.checkHaveIBeenPwned(email),
        this.checkGitHubMentions(email),
        this.analyzeDomain(email)
      ]);

      const breachData = hibpResult.status === 'fulfilled' ? hibpResult.value : null;
      const githubData = githubResult.status === 'fulfilled' ? githubResult.value : null;
      const domainData = domainResult.status === 'fulfilled' ? domainResult.value : null;

      // Calculate overall risk
      const riskFactors = [
        breachData?.riskLevel,
        githubData?.riskLevel,
        domainData?.riskLevel
      ].filter(Boolean);

      const overallRisk = this.calculateOverallRisk(riskFactors);

      const summary = {
        query: email,
        type: 'email',
        timestamp: new Date().toISOString(),
        overallRisk: overallRisk,
        breachCheck: breachData,
        githubMentions: githubData,
        domainAnalysis: domainData,
        recommendations: this.generateRecommendations(breachData, githubData, domainData)
      };

      logger.info(`Email investigation completed for ${email}: risk level ${overallRisk}`);
      return summary;

    } catch (error) {
      logger.error(`Email investigation failed for ${email}:`, error);
      throw new OSINTError(`Email investigation failed: ${error.message}`, 500, 'SERVICE_ERROR');
    }
  }

  /**
   * Calculate overall risk based on multiple factors
   */
  calculateOverallRisk(riskFactors) {
    const riskValues = { low: 1, medium: 2, high: 3, critical: 4, unknown: 0 };
    const totalRisk = riskFactors.reduce((sum, risk) => sum + (riskValues[risk] || 0), 0);
    const avgRisk = totalRisk / riskFactors.length;

    if (avgRisk >= 3.5) return 'critical';
    if (avgRisk >= 2.5) return 'high';
    if (avgRisk >= 1.5) return 'medium';
    return 'low';
  }

  /**
   * Generate security recommendations
   */
  generateRecommendations(breachData, githubData, domainData) {
    const recommendations = [];

    if (breachData?.breachCount > 0) {
      recommendations.push('Email found in data breaches - change passwords immediately');
      recommendations.push('Enable two-factor authentication on all accounts');
      recommendations.push('Monitor accounts for suspicious activity');
      
      if (breachData.breachCount >= 5) {
        recommendations.push('Consider using a new email address for sensitive accounts');
      }
    }

    if (githubData?.mentionCount > 0) {
      recommendations.push('Email found in public repositories - review exposure');
      recommendations.push('Contact repository owners to remove sensitive information');
    }

    if (domainData?.isDisposable) {
      recommendations.push('Disposable email domain detected - high fraud risk');
      recommendations.push('Verify user identity through additional means');
    }

    if (recommendations.length === 0) {
      recommendations.push('No immediate security concerns detected');
      recommendations.push('Continue monitoring for future breaches');
    }

    return recommendations;
  }
}

module.exports = new EmailService();
