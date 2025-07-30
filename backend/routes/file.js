const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const router = express.Router();
const fileService = require('../services/fileService');
const { validateFile, advancedValidation } = require('../utils/validator');
const { asyncHandler } = require('../utils/errorHandler');
const { generateSecureFilename, cleanupTempFile } = require('../utils/hashUtils');
const logger = require('../utils/logger');

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, '../../uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const secureFilename = generateSecureFilename(file.originalname);
    cb(null, secureFilename);
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE) || 50000000, // 50MB default
    files: 1 // Only allow one file at a time
  },
  fileFilter: (req, file, cb) => {
    try {
      validateFile(file);
      cb(null, true);
    } catch (error) {
      cb(error, false);
    }
  }
});

/**
 * @route   POST /osint/file
 * @desc    Investigate uploaded file for malware, hashes, and security
 * @access  Public
 * @param   {file} file - File to investigate (multipart/form-data)
 * @example POST /osint/file (with file in form data)
 */
router.post('/', advancedValidation, upload.single('file'), asyncHandler(async (req, res) => {
  let tempFilePath = null;

  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: {
          type: 'VALIDATION_ERROR',
          message: 'No file uploaded',
          timestamp: new Date().toISOString()
        }
      });
    }

    tempFilePath = req.file.path;
    const originalName = req.file.originalname;
    const fileBuffer = fs.readFileSync(tempFilePath);

    logger.info(`File investigation request: ${originalName} (${(req.file.size / 1024).toFixed(2)}KB) from IP: ${req.ip}`);

    // Perform the investigation
    const results = await fileService.investigate(tempFilePath, fileBuffer, originalName);

    // Log the results summary
    logger.info(`File investigation completed for ${originalName}: risk level ${results.overallRisk}`);

    res.json({
      success: true,
      data: results,
      meta: {
        originalFilename: originalName,
        fileSize: req.file.size,
        uploadTime: new Date().toISOString(),
        type: 'file',
        timestamp: results.timestamp,
        processingTime: Date.now() - new Date(results.timestamp).getTime(),
        requestId: req.headers['x-request-id'] || 'unknown'
      }
    });

  } catch (error) {
    logger.error(`File investigation failed:`, error);
    throw error;
  } finally {
    // Clean up temporary file
    if (tempFilePath) {
      setTimeout(() => {
        cleanupTempFile(tempFilePath);
      }, 5000); // Wait 5 seconds before cleanup to ensure processing is complete
    }
  }
}));

/**
 * @route   POST /osint/file/hash
 * @desc    Check file hash against threat intelligence databases
 * @access  Public
 * @param   {string} hash - File hash to check (MD5, SHA1, or SHA256)
 * @example POST /osint/file/hash {"hash": "d41d8cd98f00b204e9800998ecf8427e"}
 */
router.post('/hash', advancedValidation, asyncHandler(async (req, res) => {
  const { hash } = req.body;

  if (!hash || typeof hash !== 'string') {
    return res.status(400).json({
      success: false,
      error: {
        type: 'VALIDATION_ERROR',
        message: 'Hash value is required',
        timestamp: new Date().toISOString()
      }
    });
  }

  // Validate hash format
  const hashRegex = {
    md5: /^[a-fA-F0-9]{32}$/,
    sha1: /^[a-fA-F0-9]{40}$/,
    sha256: /^[a-fA-F0-9]{64}$/
  };

  const hashType = Object.entries(hashRegex).find(([type, regex]) => regex.test(hash));
  
  if (!hashType) {
    return res.status(400).json({
      success: false,
      error: {
        type: 'VALIDATION_ERROR',
        message: 'Invalid hash format. Supported formats: MD5 (32 chars), SHA1 (40 chars), SHA256 (64 chars)',
        timestamp: new Date().toISOString()
      }
    });
  }

  logger.info(`Hash investigation request: ${hashType[0].toUpperCase()} ${hash.substring(0, 8)}... from IP: ${req.ip}`);

  // Check hash in VirusTotal
  const vtResult = await fileService.checkHashInVirusTotal(hash);

  // Check against malware database
  const malwareResult = await fileService.checkMalwareDatabase({ [hashType[0]]: hash });

  const results = {
    query: hash,
    hashType: hashType[0].toUpperCase(),
    type: 'file_hash',
    timestamp: new Date().toISOString(),
    virusTotal: vtResult,
    malwareDatabase: malwareResult,
    overallRisk: fileService.calculateOverallRisk([
      vtResult?.riskLevel,
      malwareResult?.riskLevel
    ].filter(Boolean)),
    recommendations: fileService.generateRecommendations(vtResult, malwareResult, null, null)
  };

  logger.info(`Hash investigation completed: ${hashType[0].toUpperCase()} risk level ${results.overallRisk}`);

  res.json({
    success: true,
    data: results,
    meta: {
      hashType: hashType[0].toUpperCase(),
      type: 'file_hash',
      timestamp: results.timestamp,
      processingTime: Date.now() - new Date(results.timestamp).getTime(),
      requestId: req.headers['x-request-id'] || 'unknown'
    }
  });
}));

/**
 * @route   GET /osint/file/formats
 * @desc    Get list of supported file formats and their risk levels
 * @access  Public
 */
router.get('/formats', (req, res) => {
  res.json({
    success: true,
    data: {
      supportedFormats: {
        executables: {
          extensions: ['.exe', '.dll', '.com', '.scr', '.bat', '.cmd', '.ps1'],
          riskLevel: 'high',
          description: 'Executable files that can run code',
          maxSize: '50MB',
          note: 'These files are scanned with extra caution'
        },
        documents: {
          extensions: ['.doc', '.docx', '.pdf', '.txt', '.rtf'],
          riskLevel: 'medium',
          description: 'Document files that may contain macros or embedded content',
          maxSize: '50MB',
          note: 'Macros and embedded objects are flagged'
        },
        archives: {
          extensions: ['.zip', '.rar', '.7z', '.tar', '.gz'],
          riskLevel: 'medium',
          description: 'Compressed archive files',
          maxSize: '50MB',
          note: 'Archives are not extracted for security reasons'
        },
        media: {
          extensions: ['.jpg', '.png', '.gif', '.mp4', '.avi', '.mp3'],
          riskLevel: 'low',
          description: 'Media files with limited code execution capability',
          maxSize: '50MB',
          note: 'Metadata is analyzed for hidden content'
        }
      },
      restrictions: {
        maxFileSize: process.env.MAX_FILE_SIZE || '50MB',
        allowedExtensions: (process.env.ALLOWED_FILE_TYPES || '.exe,.doc,.docx,.pdf,.zip,.rar,.txt,.dll,.bat,.ps1').split(','),
        rateLimits: '100 requests per 15 minutes per IP',
        virusTotalLimit: '32MB for VirusTotal scanning'
      },
      riskAssessment: {
        critical: 'Known malware signatures detected',
        high: 'Multiple antivirus engines flagged as malicious',
        medium: 'Some suspicious characteristics or limited detections',
        low: 'No threats detected, appears safe'
      }
    }
  });
});

/**
 * @route   GET /osint/file/hash-types
 * @desc    Get information about supported hash algorithms
 * @access  Public
 */
router.get('/hash-types', (req, res) => {
  res.json({
    success: true,
    data: {
      algorithms: {
        md5: {
          length: 32,
          description: 'MD5 (Message Digest 5) - Fast but cryptographically broken',
          example: 'd41d8cd98f00b204e9800998ecf8427e',
          strength: 'Low',
          usage: 'File integrity, legacy systems',
          note: 'Vulnerable to collision attacks'
        },
        sha1: {
          length: 40,
          description: 'SHA-1 (Secure Hash Algorithm 1) - Deprecated but still used',
          example: 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
          strength: 'Medium',
          usage: 'Version control, digital signatures',
          note: 'Vulnerable to collision attacks since 2017'
        },
        sha256: {
          length: 64,
          description: 'SHA-256 (Secure Hash Algorithm 256-bit) - Current standard',
          example: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          strength: 'High',
          usage: 'Security applications, blockchain, modern systems',
          note: 'Currently considered secure'
        }
      },
      recommendations: {
        preferred: 'SHA-256',
        acceptable: 'SHA-1 for legacy compatibility',
        deprecated: 'MD5 should be avoided for security purposes',
        note: 'All hash types are supported for threat intelligence lookup'
      },
      useCases: {
        malwareDetection: 'Compare against known malware signature databases',
        fileIntegrity: 'Verify file has not been modified',
        threatIntelligence: 'Check against security vendor databases',
        forensics: 'Create unique file fingerprints for investigation'
      }
    }
  });
});

/**
 * @route   GET /osint/file/help
 * @desc    Get help information for file investigation
 * @access  Public
 */
router.get('/help', (req, res) => {
  res.json({
    success: true,
    data: {
      endpoints: {
        fileUpload: {
          endpoint: 'POST /osint/file',
          description: 'Upload and analyze a file for malware, security threats, and properties',
          contentType: 'multipart/form-data',
          parameters: {
            file: {
              required: true,
              type: 'file',
              description: 'File to analyze',
              maxSize: '50MB',
              allowedTypes: 'Executables, documents, archives, and more'
            }
          }
        },
        hashCheck: {
          endpoint: 'POST /osint/file/hash',
          description: 'Check a file hash against threat intelligence databases',
          contentType: 'application/json',
          parameters: {
            hash: {
              required: true,
              type: 'string',
              description: 'File hash (MD5, SHA1, or SHA256)',
              validation: 'Valid hexadecimal hash string'
            }
          }
        }
      },
      response: {
        description: 'File analysis results with security assessment',
        structure: {
          query: 'Original filename or hash',
          type: 'Analysis type (file or file_hash)',
          timestamp: 'Analysis timestamp',
          overallRisk: 'Risk assessment (low/medium/high/critical)',
          metadata: 'File properties and information',
          hashes: 'Generated file hashes (MD5, SHA1, SHA256)',
          virusTotalResult: 'VirusTotal scan results',
          malwareDatabase: 'Known malware signature check',
          propertyAnalysis: 'File characteristic analysis',
          recommendations: 'Security recommendations based on findings'
        }
      },
      analysisComponents: {
        hashGeneration: 'Calculate MD5, SHA1, and SHA256 hashes',
        virusTotalScan: 'Submit to VirusTotal for antivirus scanning',
        malwareDetection: 'Check against known malware signatures',
        propertyAnalysis: 'Analyze file properties and characteristics',
        riskAssessment: 'Calculate overall security risk level'
      },
      riskLevels: {
        low: 'File appears safe with no threats detected',
        medium: 'Some suspicious characteristics or limited detections',
        high: 'Multiple security concerns or antivirus detections',
        critical: 'Known malware or severe security threats detected'
      },
      examples: {
        fileUpload: 'curl -X POST -F "file=@suspicious.exe" http://localhost:3001/osint/file',
        hashCheck: 'curl -X POST -H "Content-Type: application/json" -d \'{"hash":"d41d8cd98f00b204e9800998ecf8427e"}\' http://localhost:3001/osint/file/hash'
      },
      security: {
        fileHandling: 'Files are processed in isolated environment',
        dataRetention: 'Temporary files are deleted after analysis',
        virusTotal: 'Files are submitted to VirusTotal for public analysis',
        privacy: 'Consider privacy implications before uploading sensitive files'
      },
      rateLimits: '100 requests per 15 minutes per IP',
      tips: [
        'Use hash checking for faster analysis of known files',
        'VirusTotal submissions become public - avoid sensitive files',
        'Large files may take longer to process',
        'Multiple hash formats are supported for maximum compatibility',
        'File metadata analysis can reveal suspicious characteristics'
      ]
    }
  });
});

// Error handling middleware for multer
router.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    let message = 'File upload error';
    let statusCode = 400;

    switch (error.code) {
      case 'LIMIT_FILE_SIZE':
        message = `File too large. Maximum size is ${(parseInt(process.env.MAX_FILE_SIZE) || 50000000) / 1000000}MB`;
        statusCode = 413;
        break;
      case 'LIMIT_FILE_COUNT':
        message = 'Too many files. Only one file is allowed';
        break;
      case 'LIMIT_UNEXPECTED_FILE':
        message = 'Unexpected file field name. Use "file" as the field name';
        break;
      default:
        message = error.message;
    }

    return res.status(statusCode).json({
      success: false,
      error: {
        type: 'FILE_UPLOAD_ERROR',
        message: message,
        code: error.code,
        timestamp: new Date().toISOString()
      }
    });
  }

  next(error);
});

module.exports = router;
