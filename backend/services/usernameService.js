const axios = require('axios');
const logger = require('../utils/logger');
const { OSINTError } = require('../utils/errorHandler');

/**
 * Username investigation service
 * Checks username availability across multiple platforms
 */
class UsernameService {
  constructor() {
    this.platforms = {
      github: {
        url: 'https://api.github.com/users/',
        method: 'GET',
        headers: {
          'User-Agent': 'OSINT-Hawk/1.0',
          ...(process.env.GITHUB_API_TOKEN && {
            'Authorization': `token ${process.env.GITHUB_API_TOKEN}`
          })
        }
      },
      reddit: {
        url: 'https://www.reddit.com/user/',
        method: 'GET',
        headers: {
          'User-Agent': 'OSINT-Hawk/1.0'
        }
      },
      twitter: {
        url: 'https://twitter.com/',
        method: 'GET',
        headers: {
          'User-Agent': 'OSINT-Hawk/1.0'
        }
      },
      instagram: {
        url: 'https://www.instagram.com/',
        method: 'GET',
        headers: {
          'User-Agent': 'OSINT-Hawk/1.0'
        }
      }
    };
  }

  /**
   * Check username on GitHub
   */
  async checkGitHub(username) {
    try {
      const config = this.platforms.github;
      const response = await axios.get(`${config.url}${username}`, {
        headers: config.headers,
        timeout: 10000,
        validateStatus: (status) => status < 500 // Don't throw on 404
      });

      if (response.status === 200) {
        const userData = response.data;
        return {
          platform: 'GitHub',
          username: username,
          exists: true,
          profileUrl: userData.html_url,
          avatar: userData.avatar_url,
          publicRepos: userData.public_repos,
          followers: userData.followers,
          following: userData.following,
          accountCreated: userData.created_at,
          lastUpdated: userData.updated_at,
          bio: userData.bio,
          company: userData.company,
          location: userData.location,
          blog: userData.blog,
          email: userData.email,
          riskLevel: 'low',
          evidence: {
            profileData: {
              name: userData.name,
              publicRepos: userData.public_repos,
              followers: userData.followers
            }
          }
        };
      } else if (response.status === 404) {
        return {
          platform: 'GitHub',
          username: username,
          exists: false,
          profileUrl: null,
          riskLevel: 'none',
          evidence: null
        };
      }
    } catch (error) {
      logger.error(`GitHub API error for username ${username}:`, error.message);
      return {
        platform: 'GitHub',
        username: username,
        exists: null,
        error: 'Service unavailable',
        riskLevel: 'unknown'
      };
    }
  }

  /**
   * Check username on Reddit
   */
  async checkReddit(username) {
    try {
      const config = this.platforms.reddit;
      const response = await axios.get(`${config.url}${username}/about.json`, {
        headers: config.headers,
        timeout: 10000,
        validateStatus: (status) => status < 500
      });

      if (response.status === 200 && response.data.data) {
        const userData = response.data.data;
        return {
          platform: 'Reddit',
          username: username,
          exists: true,
          profileUrl: `https://www.reddit.com/user/${username}`,
          accountCreated: new Date(userData.created_utc * 1000).toISOString(),
          karma: {
            comment: userData.comment_karma,
            link: userData.link_karma,
            total: userData.total_karma
          },
          isVerified: userData.verified,
          riskLevel: 'low',
          evidence: {
            karma: userData.total_karma,
            verified: userData.verified
          }
        };
      } else {
        return {
          platform: 'Reddit',
          username: username,
          exists: false,
          profileUrl: null,
          riskLevel: 'none',
          evidence: null
        };
      }
    } catch (error) {
      logger.error(`Reddit API error for username ${username}:`, error.message);
      return {
        platform: 'Reddit',
        username: username,
        exists: null,
        error: 'Service unavailable',
        riskLevel: 'unknown'
      };
    }
  }

  /**
   * Check username availability using web scraping (fallback)
   */
  async checkWebPresence(username, platform) {
    try {
      const config = this.platforms[platform];
      if (!config) return null;

      const response = await axios.get(`${config.url}${username}`, {
        headers: config.headers,
        timeout: 10000,
        validateStatus: (status) => status < 500,
        maxRedirects: 3
      });

      const exists = response.status === 200 && 
                    !response.data.includes('not found') &&
                    !response.data.includes('doesn\'t exist') &&
                    !response.data.includes('suspended');

      return {
        platform: platform.charAt(0).toUpperCase() + platform.slice(1),
        username: username,
        exists: exists,
        profileUrl: exists ? `${config.url}${username}` : null,
        statusCode: response.status,
        riskLevel: exists ? 'low' : 'none',
        evidence: exists ? { statusCode: response.status } : null
      };
    } catch (error) {
      logger.error(`Web presence check error for ${platform}/${username}:`, error.message);
      return {
        platform: platform.charAt(0).toUpperCase() + platform.slice(1),
        username: username,
        exists: null,
        error: 'Service unavailable',
        riskLevel: 'unknown'
      };
    }
  }

  /**
   * Comprehensive username investigation
   */
  async investigate(username) {
    try {
      logger.info(`Starting username investigation for: ${username}`);

      const results = await Promise.allSettled([
        this.checkGitHub(username),
        this.checkReddit(username),
        this.checkWebPresence(username, 'twitter'),
        this.checkWebPresence(username, 'instagram')
      ]);

      const findings = results.map(result => 
        result.status === 'fulfilled' ? result.value : null
      ).filter(Boolean);

      // Calculate overall risk assessment
      const existingProfiles = findings.filter(f => f.exists === true);
      const totalProfiles = findings.filter(f => f.exists !== null).length;
      
      let overallRisk = 'none';
      if (existingProfiles.length > 0) {
        overallRisk = existingProfiles.length >= 3 ? 'medium' : 'low';
      }

      const summary = {
        query: username,
        type: 'username',
        timestamp: new Date().toISOString(),
        totalPlatforms: totalProfiles,
        foundOn: existingProfiles.length,
        overallRisk: overallRisk,
        platforms: findings,
        recommendations: this.generateRecommendations(existingProfiles)
      };

      logger.info(`Username investigation completed for ${username}: found on ${existingProfiles.length}/${totalProfiles} platforms`);
      return summary;

    } catch (error) {
      logger.error(`Username investigation failed for ${username}:`, error);
      throw new OSINTError(`Username investigation failed: ${error.message}`, 500, 'SERVICE_ERROR');
    }
  }

  /**
   * Generate security recommendations based on findings
   */
  generateRecommendations(existingProfiles) {
    const recommendations = [];

    if (existingProfiles.length === 0) {
      recommendations.push('Username appears to be available across checked platforms');
      recommendations.push('Consider registering on key platforms to secure the username');
    } else {
      recommendations.push('Username is in use on multiple platforms');
      recommendations.push('Review privacy settings on existing profiles');
      
      if (existingProfiles.length >= 3) {
        recommendations.push('High platform presence detected - monitor for impersonation');
        recommendations.push('Consider enabling two-factor authentication on all accounts');
      }

      // GitHub specific recommendations
      const githubProfile = existingProfiles.find(p => p.platform === 'GitHub');
      if (githubProfile && githubProfile.email) {
        recommendations.push('Public email detected on GitHub profile - consider privacy review');
      }
    }

    return recommendations;
  }
}

module.exports = new UsernameService();
