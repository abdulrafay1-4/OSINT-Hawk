const axios = require('axios');
const FormData = require('form-data');
const logger = require('../utils/logger');
const { OSINTError } = require('../utils/errorHandler');
const { generateHash, generateFileHash, getFileMetadata } = require('../utils/hashUtils');

/**
 * File analysis service
 * Performs comprehensive file investigation including hash analysis and VirusTotal scanning
 */
class FileService {
  constructor() {
    this.virusTotalApiKey = process.env.VIRUSTOTAL_API_KEY;
    this.maxFileSize = parseInt(process.env.MAX_FILE_SIZE) || 50000000; // 50MB default
  }

  /**
   * Generate comprehensive file hashes
   */
  async generateFileHashes(filePath, buffer) {
    try {
      let hashes;
      
      if (buffer) {
        hashes = generateHash.all(buffer);
      } else {
        hashes = await generateFileHash(filePath);
      }

      return {
        status: 'success',
        hashes: hashes,
        algorithms: ['MD5', 'SHA1', 'SHA256']
      };
    } catch (error) {
      logger.error(`Hash generation error:`, error.message);
      return {
        status: 'error',
        error: error.message,
        hashes: null
      };
    }
  }

  /**
   * Submit file to VirusTotal for analysis
   */
  async submitToVirusTotal(buffer, filename) {
    try {
      if (!this.virusTotalApiKey) {
        logger.warn('VirusTotal API key not configured');
        return {
          service: 'VirusTotal',
          status: 'unavailable',
          error: 'API key not configured'
        };
      }

      // Check file size limit (VirusTotal free tier: 32MB)
      const vtMaxSize = 32 * 1024 * 1024; // 32MB
      if (buffer.length > vtMaxSize) {
        return {
          service: 'VirusTotal',
          status: 'size_limit_exceeded',
          error: `File size ${(buffer.length / 1024 / 1024).toFixed(2)}MB exceeds VirusTotal limit of 32MB`,
          fileSize: buffer.length
        };
      }

      // Create form data for file upload
      const formData = new FormData();
      formData.append('file', buffer, filename);

      const response = await axios.post(
        'https://www.virustotal.com/api/v3/files',
        formData,
        {
          headers: {
            'x-apikey': this.virusTotalApiKey,
            ...formData.getHeaders()
          },
          timeout: 120000, // 2 minutes for file upload
          maxBodyLength: vtMaxSize,
          maxContentLength: vtMaxSize
        }
      );

      if (response.status === 200) {
        const analysisId = response.data.data.id;
        
        // Wait a moment then get the analysis results
        await new Promise(resolve => setTimeout(resolve, 5000));
        
        return await this.getVirusTotalAnalysis(analysisId);
      }

      return {
        service: 'VirusTotal',
        status: 'upload_failed',
        error: 'Failed to upload file to VirusTotal'
      };
    } catch (error) {
      logger.error(`VirusTotal upload error:`, error.message);
      
      if (error.response?.status === 429) {
        return {
          service: 'VirusTotal',
          status: 'rate_limited',
          error: 'VirusTotal API rate limit exceeded'
        };
      }

      return {
        service: 'VirusTotal',
        status: 'error',
        error: error.message
      };
    }
  }

  /**
   * Check existing file hash in VirusTotal
   */
  async checkHashInVirusTotal(hash) {
    try {
      if (!this.virusTotalApiKey) {
        return {
          service: 'VirusTotal',
          status: 'unavailable',
          error: 'API key not configured'
        };
      }

      const response = await axios.get(
        `https://www.virustotal.com/api/v3/files/${hash}`,
        {
          headers: {
            'x-apikey': this.virusTotalApiKey
          },
          timeout: 30000,
          validateStatus: (status) => status < 500
        }
      );

      if (response.status === 200) {
        return this.parseVirusTotalResponse(response.data);
      } else if (response.status === 404) {
        return {
          service: 'VirusTotal',
          status: 'not_found',
          message: 'File hash not found in VirusTotal database',
          hash: hash
        };
      }

      return {
        service: 'VirusTotal',
        status: 'no_data',
        error: 'No data available from VirusTotal'
      };
    } catch (error) {
      logger.error(`VirusTotal hash check error:`, error.message);
      return {
        service: 'VirusTotal',
        status: 'error',
        error: error.message
      };
    }
  }

  /**
   * Get VirusTotal analysis results
   */
  async getVirusTotalAnalysis(analysisId) {
    try {
      let attempts = 0;
      const maxAttempts = 6; // Wait up to 1 minute
      
      while (attempts < maxAttempts) {
        const response = await axios.get(
          `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
          {
            headers: {
              'x-apikey': this.virusTotalApiKey
            },
            timeout: 30000
          }
        );

        if (response.status === 200) {
          const analysis = response.data.data.attributes;
          
          if (analysis.status === 'completed') {
            // Get the file report
            const fileId = response.data.data.meta.file_info.sha256;
            return await this.checkHashInVirusTotal(fileId);
          } else if (analysis.status === 'queued' || analysis.status === 'in-progress') {
            attempts++;
            await new Promise(resolve => setTimeout(resolve, 10000)); // Wait 10 seconds
            continue;
          }
        }
        
        break;
      }

      return {
        service: 'VirusTotal',
        status: 'analysis_timeout',
        error: 'Analysis took too long to complete',
        analysisId: analysisId
      };
    } catch (error) {
      logger.error(`VirusTotal analysis error:`, error.message);
      return {
        service: 'VirusTotal',
        status: 'error',
        error: error.message
      };
    }
  }

  /**
   * Parse VirusTotal response into structured format
   */
  parseVirusTotalResponse(data) {
    try {
      const attributes = data.data.attributes;
      const stats = attributes.last_analysis_stats;
      
      const engines = Object.entries(attributes.last_analysis_results || {}).map(([engine, result]) => ({
        engine: engine,
        category: result.category,
        result: result.result,
        version: result.version,
        update: result.update
      }));

      const maliciousEngines = engines.filter(e => e.category === 'malicious');
      const suspiciousEngines = engines.filter(e => e.category === 'suspicious');

      let riskLevel = 'low';
      if (stats.malicious > 0) {
        if (stats.malicious >= 5) riskLevel = 'critical';
        else if (stats.malicious >= 2) riskLevel = 'high';
        else riskLevel = 'medium';
      } else if (stats.suspicious > 0) {
        riskLevel = 'medium';
      }

      return {
        service: 'VirusTotal',
        status: 'success',
        hash: attributes.sha256,
        scanDate: new Date(attributes.last_analysis_date * 1000).toISOString(),
        stats: {
          harmless: stats.harmless || 0,
          malicious: stats.malicious || 0,
          suspicious: stats.suspicious || 0,
          undetected: stats.undetected || 0,
          timeout: stats.timeout || 0,
          total: Object.keys(attributes.last_analysis_results || {}).length
        },
        riskLevel: riskLevel,
        maliciousEngines: maliciousEngines,
        suspiciousEngines: suspiciousEngines,
        fileInfo: {
          size: attributes.size,
          type: attributes.type_description,
          magicBytes: attributes.magic,
          firstSeen: attributes.first_submission_date ? new Date(attributes.first_submission_date * 1000).toISOString() : null,
          lastSeen: attributes.last_submission_date ? new Date(attributes.last_submission_date * 1000).toISOString() : null,
          names: attributes.names || []
        },
        reputation: attributes.reputation || 0,
        communityScore: {
          harmless: attributes.total_votes?.harmless || 0,
          malicious: attributes.total_votes?.malicious || 0
        }
      };
    } catch (error) {
      logger.error('Error parsing VirusTotal response:', error.message);
      return {
        service: 'VirusTotal',
        status: 'parse_error',
        error: 'Failed to parse VirusTotal response',
        rawData: data
      };
    }
  }

  /**
   * Analyze file metadata and properties
   */
  analyzeFileProperties(metadata, hashes) {
    const analysis = {
      suspicious: false,
      riskFactors: [],
      riskLevel: 'low'
    };

    // Check file size
    if (metadata.size > 100 * 1024 * 1024) { // 100MB
      analysis.riskFactors.push('Large file size');
    }

    // Check file extension
    const highRiskExtensions = ['.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs', '.js', '.jar', '.dll'];
    if (highRiskExtensions.includes(metadata.extension.toLowerCase())) {
      analysis.riskFactors.push('Potentially dangerous file type');
      analysis.suspicious = true;
    }

    // Check for double extensions
    const nameWithoutPath = metadata.originalName.toLowerCase();
    const extensionCount = (nameWithoutPath.match(/\./g) || []).length;
    if (extensionCount > 1) {
      analysis.riskFactors.push('Multiple file extensions detected');
      analysis.suspicious = true;
    }

    // Check for suspicious file names
    const suspiciousNames = ['crack', 'keygen', 'patch', 'loader', 'activator', 'hack'];
    if (suspiciousNames.some(name => nameWithoutPath.includes(name))) {
      analysis.riskFactors.push('Suspicious filename detected');
      analysis.suspicious = true;
    }

    // Calculate risk level
    if (analysis.suspicious && analysis.riskFactors.length >= 2) {
      analysis.riskLevel = 'high';
    } else if (analysis.suspicious || analysis.riskFactors.length > 0) {
      analysis.riskLevel = 'medium';
    }

    return analysis;
  }

  /**
   * Check file against known malware hashes
   */
  async checkMalwareDatabase(hashes) {
    // This is a placeholder for integration with malware hash databases
    // You could integrate with services like:
    // - MalwareBazaar
    // - Hybrid Analysis
    // - YARA rules
    
    const knownMalwareHashes = [
      // Add known malware hashes here
      '5d41402abc4b2a76b9719d911017c592', // Example MD5
      '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae', // Example SHA256
    ];

    const results = {
      md5: knownMalwareHashes.includes(hashes.md5),
      sha1: knownMalwareHashes.includes(hashes.sha1),
      sha256: knownMalwareHashes.includes(hashes.sha256)
    };

    const isKnownMalware = Object.values(results).some(Boolean);

    return {
      status: 'success',
      isKnownMalware: isKnownMalware,
      matchedHashes: results,
      riskLevel: isKnownMalware ? 'critical' : 'low'
    };
  }

  /**
   * Comprehensive file investigation
   */
  async investigate(filePath, buffer, originalName) {
    try {
      logger.info(`Starting file investigation for: ${originalName}`);

      // Generate file metadata
      const metadata = getFileMetadata(filePath, originalName);

      // Generate hashes
      const hashResult = await this.generateFileHashes(filePath, buffer);
      
      if (hashResult.status !== 'success') {
        throw new OSINTError('Failed to generate file hashes', 500, 'HASH_ERROR');
      }

      const hashes = hashResult.hashes;

      // Run parallel analysis
      const [vtHashResult, vtUploadResult, malwareDbResult] = await Promise.allSettled([
        this.checkHashInVirusTotal(hashes.sha256),
        buffer ? this.submitToVirusTotal(buffer, originalName) : Promise.resolve(null),
        this.checkMalwareDatabase(hashes)
      ]);

      const virusTotalHash = vtHashResult.status === 'fulfilled' ? vtHashResult.value : null;
      const virusTotalUpload = vtUploadResult.status === 'fulfilled' ? vtUploadResult.value : null;
      const malwareDb = malwareDbResult.status === 'fulfilled' ? malwareDbResult.value : null;

      // Analyze file properties
      const propertyAnalysis = this.analyzeFileProperties(metadata, hashes);

      // Determine best VirusTotal result
      let virusTotalResult = virusTotalHash;
      if (virusTotalHash?.status === 'not_found' && virusTotalUpload?.status === 'success') {
        virusTotalResult = virusTotalUpload;
      }

      // Calculate overall risk
      const riskFactors = [
        virusTotalResult?.riskLevel,
        malwareDb?.riskLevel,
        propertyAnalysis.riskLevel
      ].filter(Boolean);

      const overallRisk = this.calculateOverallRisk(riskFactors);

      const summary = {
        query: originalName,
        type: 'file',
        timestamp: new Date().toISOString(),
        overallRisk: overallRisk,
        metadata: metadata,
        hashes: hashes,
        virusTotalResult: virusTotalResult,
        malwareDatabase: malwareDb,
        propertyAnalysis: propertyAnalysis,
        recommendations: this.generateRecommendations(virusTotalResult, malwareDb, propertyAnalysis, metadata)
      };

      logger.info(`File investigation completed for ${originalName}: risk level ${overallRisk}`);
      return summary;

    } catch (error) {
      logger.error(`File investigation failed for ${originalName}:`, error);
      throw new OSINTError(`File investigation failed: ${error.message}`, 500, 'SERVICE_ERROR');
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
  generateRecommendations(vtResult, malwareDb, propertyAnalysis, metadata) {
    const recommendations = [];

    if (malwareDb?.isKnownMalware) {
      recommendations.push('⚠️ CRITICAL: File matches known malware signatures - DO NOT EXECUTE');
      recommendations.push('Quarantine file immediately and scan system for infections');
    }

    if (vtResult?.status === 'success') {
      if (vtResult.stats.malicious > 0) {
        recommendations.push(`⚠️ WARNING: ${vtResult.stats.malicious}/${vtResult.stats.total} antivirus engines flagged this file as malicious`);
        recommendations.push('Do not execute this file - consider it dangerous');
      } else if (vtResult.stats.suspicious > 0) {
        recommendations.push(`⚠️ CAUTION: ${vtResult.stats.suspicious}/${vtResult.stats.total} antivirus engines flagged this file as suspicious`);
        recommendations.push('Exercise extreme caution if considering execution');
      } else if (vtResult.stats.total > 0) {
        recommendations.push('✅ File appears clean according to VirusTotal analysis');
      }
    } else if (vtResult?.status === 'not_found') {
      recommendations.push('ℹ️ File not found in VirusTotal database - may be new or uncommon');
      recommendations.push('Exercise caution with unknown files');
    }

    if (propertyAnalysis.suspicious) {
      recommendations.push('⚠️ File has suspicious properties:');
      propertyAnalysis.riskFactors.forEach(factor => {
        recommendations.push(`  • ${factor}`);
      });
    }

    // File-specific recommendations
    const extension = metadata.extension.toLowerCase();
    if (['.exe', '.bat', '.cmd', '.scr'].includes(extension)) {
      recommendations.push('🔒 Executable file detected - scan in isolated environment before running');
    }

    if (metadata.size > 50 * 1024 * 1024) { // 50MB
      recommendations.push('📦 Large file size - verify authenticity and purpose');
    }

    if (recommendations.length === 0) {
      recommendations.push('✅ No immediate security concerns detected');
      recommendations.push('Continue with standard security practices');
    }

    return recommendations;
  }
}

module.exports = new FileService();
