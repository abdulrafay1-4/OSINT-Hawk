const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Generate hash for file or string
 */
const generateHash = {
  /**
   * Generate MD5 hash
   */
  md5: (input) => {
    if (Buffer.isBuffer(input)) {
      return crypto.createHash('md5').update(input).digest('hex');
    }
    return crypto.createHash('md5').update(input, 'utf8').digest('hex');
  },

  /**
   * Generate SHA1 hash
   */
  sha1: (input) => {
    if (Buffer.isBuffer(input)) {
      return crypto.createHash('sha1').update(input).digest('hex');
    }
    return crypto.createHash('sha1').update(input, 'utf8').digest('hex');
  },

  /**
   * Generate SHA256 hash
   */
  sha256: (input) => {
    if (Buffer.isBuffer(input)) {
      return crypto.createHash('sha256').update(input).digest('hex');
    }
    return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
  },

  /**
   * Generate all common hashes for a file buffer
   */
  all: (buffer) => {
    return {
      md5: generateHash.md5(buffer),
      sha1: generateHash.sha1(buffer),
      sha256: generateHash.sha256(buffer),
      size: buffer.length
    };
  }
};

/**
 * Generate hash from file path
 */
const generateFileHash = async (filePath) => {
  return new Promise((resolve, reject) => {
    const md5Hash = crypto.createHash('md5');
    const sha1Hash = crypto.createHash('sha1');
    const sha256Hash = crypto.createHash('sha256');
    
    const stream = fs.createReadStream(filePath);
    let fileSize = 0;

    stream.on('data', (chunk) => {
      fileSize += chunk.length;
      md5Hash.update(chunk);
      sha1Hash.update(chunk);
      sha256Hash.update(chunk);
    });

    stream.on('end', () => {
      resolve({
        md5: md5Hash.digest('hex'),
        sha1: sha1Hash.digest('hex'),
        sha256: sha256Hash.digest('hex'),
        size: fileSize
      });
    });

    stream.on('error', (error) => {
      reject(error);
    });
  });
};

/**
 * Get file metadata
 */
const getFileMetadata = (filePath, originalName) => {
  const stats = fs.statSync(filePath);
  const ext = path.extname(originalName).toLowerCase();
  
  return {
    originalName,
    extension: ext,
    mimeType: getMimeType(ext),
    size: stats.size,
    created: stats.birthtime,
    modified: stats.mtime,
    path: filePath
  };
};

/**
 * Get MIME type from file extension
 */
const getMimeType = (extension) => {
  const mimeTypes = {
    '.exe': 'application/x-msdownload',
    '.dll': 'application/x-msdownload',
    '.doc': 'application/msword',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.pdf': 'application/pdf',
    '.zip': 'application/zip',
    '.rar': 'application/x-rar-compressed',
    '.txt': 'text/plain',
    '.bat': 'application/x-bat',
    '.ps1': 'application/x-powershell',
    '.jar': 'application/java-archive',
    '.apk': 'application/vnd.android.package-archive'
  };

  return mimeTypes[extension] || 'application/octet-stream';
};

/**
 * Generate secure filename
 */
const generateSecureFilename = (originalName) => {
  const timestamp = Date.now();
  const random = crypto.randomBytes(8).toString('hex');
  const ext = path.extname(originalName);
  const baseName = path.basename(originalName, ext).replace(/[^a-zA-Z0-9]/g, '_');
  
  return `${timestamp}_${random}_${baseName}${ext}`;
};

/**
 * Clean up temporary files
 */
const cleanupTempFile = (filePath) => {
  if (fs.existsSync(filePath)) {
    try {
      fs.unlinkSync(filePath);
      return true;
    } catch (error) {
      console.error('Error cleaning up temp file:', error);
      return false;
    }
  }
  return false;
};

/**
 * Validate file signature (magic bytes)
 */
const validateFileSignature = (buffer, expectedType) => {
  const signatures = {
    'exe': [0x4D, 0x5A], // MZ
    'pdf': [0x25, 0x50, 0x44, 0x46], // %PDF
    'zip': [0x50, 0x4B, 0x03, 0x04], // PK..
    'doc': [0xD0, 0xCF, 0x11, 0xE0], // MS Office
    'png': [0x89, 0x50, 0x4E, 0x47], // PNG
    'jpg': [0xFF, 0xD8, 0xFF], // JPEG
    'gif': [0x47, 0x49, 0x46, 0x38] // GIF8
  };

  const signature = signatures[expectedType];
  if (!signature) return true; // Skip validation if no signature defined

  for (let i = 0; i < signature.length; i++) {
    if (buffer[i] !== signature[i]) {
      return false;
    }
  }

  return true;
};

module.exports = {
  generateHash,
  generateFileHash,
  getFileMetadata,
  getMimeType,
  generateSecureFilename,
  cleanupTempFile,
  validateFileSignature
};
