const axios = require('axios');
const logger = require('../utils/logger');
const { OSINTError } = require('../utils/errorHandler');

/**
 * Email intelligence service
 * Performs comprehensive email investigation with free alternatives
 */
class EmailService {
  constructor() {
    this.githubToken = process.env.GITHUB_API_TOKEN;
  }

  /**
   * Email analysis using free methods (no HaveIBeenPwned)
   */
  async analyzeEmail(email) {
    try {
      // Basic email pattern analysis
      const emailParts = email.split('@');
      const username = emailParts[0];
      const domain = emailParts[1];

      // Check for common patterns that might indicate compromised accounts
      const suspiciousPatterns = {
        randomNumbers: /\d{4,}$/.test(username), // ends with 4+ numbers
        commonPasswords: /^(admin|test|user|guest|demo|sample)/i.test(username),
        disposableEmail: this.isDisposableEmail(domain),
        commonProvider: this.isCommonEmailProvider(domain)
      };

      // Domain reputation check (basic)
      const domainAnalysis = {
        isDisposable: suspiciousPatterns.disposableEmail,
        isCommonProvider: suspiciousPatterns.commonProvider,
        hasTypo: this.checkForCommonTypos(domain)
      };

      // Social media username detection
      const socialPatterns = {
        likelyUsername: username.length >= 3 && !/\d{4,}$/.test(username),
        containsPersonalInfo: /\d{4}|19\d{2}|20\d{2}/.test(username), // birth years
        commonFormat: /^[a-zA-Z]+\d{0,3}$/.test(username)
      };

      return {
        service: 'EmailAnalysis',
        status: 'success',
        breaches: [], // No breach data without paid API
        analysis: {
          domain: domainAnalysis,
          username: socialPatterns,
          suspiciousPatterns,
          recommendations: this.generateEmailRecommendations(suspiciousPatterns, socialPatterns)
        }
      };

    } catch (error) {
      return {
        service: 'EmailAnalysis',
        status: 'error',
        error: error.message,
        breaches: [],
        analysis: {}
      };
    }
  }

  /**
   * Check for GitHub mentions (simplified)
   */
  async checkGitHubMentions(email) {
    return {
      service: 'GitHub',
      status: 'unavailable',
      error: 'API token not configured',
      mentions: []
    };
  }

  /**
   * Analyze email domain
   */
  async analyzeDomain(email) {
    try {
      const domain = email.split('@')[1];
      
      const analysis = {
        domain,
        isDisposable: this.isDisposableEmail(domain),
        isCommonProvider: this.isCommonEmailProvider(domain),
        riskLevel: 'low'
      };

      if (analysis.isDisposable) {
        analysis.riskLevel = 'high';
        analysis.type = 'disposable';
        analysis.reputation = 'poor';
      } else if (analysis.isCommonProvider) {
        analysis.riskLevel = 'low';
        analysis.type = 'common-provider';
        analysis.reputation = 'good';
      } else {
        analysis.riskLevel = 'medium';
        analysis.type = 'custom';
        analysis.reputation = 'unknown';
      }

      return analysis;
    } catch (error) {
      logger.error(`Domain analysis error for ${email}:`, error);
      return {
        domain: email.split('@')[1] || 'unknown',
        error: error.message,
        riskLevel: 'unknown'
      };
    }
  }

  /**
   * Main investigation method
   */
  async investigate(email) {
    try {
      logger.info(`Starting email investigation for: ${this.maskEmail(email)}`);

      // Perform all checks
      const [breachData, githubData, domainData] = await Promise.all([
        this.analyzeEmail(email),
        this.checkGitHubMentions(email),
        this.analyzeDomain(email)
      ]);

      // Calculate overall risk
      const riskFactors = {
        breachCount: breachData.breaches?.length || 0,
        githubMentions: githubData.mentions?.length || 0,
        domainRisk: domainData.riskLevel,
        disposableEmail: domainData.isDisposable
      };

      const overallRisk = this.calculateOverallRisk(riskFactors);
      const recommendations = this.generateRecommendations(breachData, githubData, domainData);

      const result = {
        query: this.maskEmail(email),
        type: 'email',
        timestamp: new Date().toISOString(),
        overallRisk,
        breachCheck: breachData,
        githubMentions: githubData,
        domainAnalysis: domainData,
        recommendations
      };

      logger.info(`Email investigation completed for ${this.maskEmail(email)}: risk level ${overallRisk}`);
      return result;

    } catch (error) {
      logger.error(`Email investigation failed for ${this.maskEmail(email)}:`, error);
      throw new OSINTError(`Email investigation failed: ${error.message}`, 'EMAIL_INVESTIGATION_ERROR');
    }
  }

  /**
   * Helper methods
   */
  isDisposableEmail(domain) {
    const disposableDomains = [
      '10minutemail.com', 'tempmail.org', 'guerrillamail.com', 
      'mailinator.com', 'throwaway.email', 'temp-mail.org',
      'getnada.com', 'maildrop.cc', 'yopmail.com', 'sharklasers.com',
      'getairmail.com', 'mail7.io', 'inboxkitten.com'
    ];
    return disposableDomains.includes(domain.toLowerCase());
  }

  isCommonEmailProvider(domain) {
    const commonProviders = [
      'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
      'aol.com', 'icloud.com', 'protonmail.com', 'live.com',
      'msn.com', 'comcast.net', 'verizon.net'
    ];
    return commonProviders.includes(domain.toLowerCase());
  }

  checkForCommonTypos(domain) {
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

  generateEmailRecommendations(suspicious, social) {
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
  }

  calculateOverallRisk(riskFactors) {
    let riskScore = 0;

    if (riskFactors.disposableEmail) riskScore += 3;
    if (riskFactors.domainRisk === 'high') riskScore += 2;
    if (riskFactors.domainRisk === 'medium') riskScore += 1;
    if (riskFactors.breachCount > 0) riskScore += 2;
    if (riskFactors.githubMentions > 0) riskScore += 1;

    if (riskScore >= 4) return 'high';
    if (riskScore >= 2) return 'medium';
    return 'low';
  }

  generateRecommendations(breachData, githubData, domainData) {
    const recommendations = [];

    if (domainData.isDisposable) {
      recommendations.push('Disposable email domain detected - high fraud risk');
      recommendations.push('Verify user identity through additional means');
    }

    if (breachData.analysis?.suspiciousPatterns?.commonPasswords) {
      recommendations.push('Username follows common default pattern - security concern');
    }

    if (breachData.analysis?.socialPatterns?.likelyUsername && !domainData.isDisposable) {
      recommendations.push('Username suitable for social media investigation');
    }

    if (recommendations.length === 0) {
      recommendations.push('No immediate security concerns detected');
      recommendations.push('Continue monitoring for future breaches');
    }

    return recommendations;
  }

  maskEmail(email) {
    const [username, domain] = email.split('@');
    if (username.length <= 3) {
      return `${username[0]}***@${domain}`;
    }
    return `${username.substring(0, 3)}***@${domain}`;
  }
}

module.exports = new EmailService();
