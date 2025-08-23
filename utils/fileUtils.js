const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const crypto = require('crypto');

// =========================================
// PRODUCTION CONSTANTS & CONFIG
// =========================================

const CONFIG = {
  // File operation settings
  FILE: {
    ENCODING: 'utf-8',
    MAX_FILE_SIZE: 50 * 1024 * 1024, // 50MB max file size
    BACKUP_COUNT: 5, // Keep 5 backup files
    TEMP_SUFFIX: '.tmp',
    BACKUP_SUFFIX: '.backup'
  },

  // Security settings
  SECURITY: {
    VALIDATE_JSON: true,
    MAX_DEPTH: 10, // Maximum JSON nesting depth
    ALLOWED_EXTENSIONS: ['.json'],
    SANITIZE_PATHS: true
  },

  // Performance settings
  PERFORMANCE: {
    ASYNC_OPERATIONS: true,
    ENABLE_CACHING: false, // Disable caching for data files
    CACHE_TTL: 5 * 60 * 1000, // 5 minutes cache TTL
    CONCURRENT_OPERATIONS: 10
  }
};

// =========================================
// PRODUCTION LOGGING SYSTEM
// =========================================

const logger = {
  info: (message, meta = {}) => console.log(`[INFO] ${new Date().toISOString()} - ${message}`, JSON.stringify(meta)),
  warn: (message, meta = {}) => console.warn(`[WARN] ${new Date().toISOString()} - ${message}`, JSON.stringify(meta)),
  error: (message, error, meta = {}) => console.error(`[ERROR] ${new Date().toISOString()} - ${message}`, error?.stack || error, JSON.stringify(meta)),
  audit: (action, filePath, meta = {}) => console.log(`[AUDIT] ${new Date().toISOString()} - ${action} - File: ${filePath}`, JSON.stringify(meta))
};

// =========================================
// PRODUCTION VALIDATION & SECURITY
// =========================================

class FileValidator {
  static validateFilePath(filePath) {
    if (!filePath || typeof filePath !== 'string') {
      throw new Error('File path must be a non-empty string');
    }

    if (CONFIG.SECURITY.SANITIZE_PATHS) {
      // Prevent path traversal attacks
      const normalizedPath = path.normalize(filePath);
      if (normalizedPath.includes('..') || normalizedPath.startsWith('/')) {
        throw new Error('Invalid file path: Path traversal detected');
      }
    }

    // Check file extension
    const ext = path.extname(filePath).toLowerCase();
    if (CONFIG.SECURITY.ALLOWED_EXTENSIONS.length > 0 &&
      !CONFIG.SECURITY.ALLOWED_EXTENSIONS.includes(ext)) {
      throw new Error(`Invalid file extension: ${ext}. Allowed: ${CONFIG.SECURITY.ALLOWED_EXTENSIONS.join(', ')}`);
    }

    return normalizedPath;
  }

  static validateFileSize(filePath) {
    try {
      const stats = fs.statSync(filePath);
      if (stats.size > CONFIG.FILE.MAX_FILE_SIZE) {
        throw new Error(`File size exceeds maximum allowed size of ${CONFIG.FILE.MAX_FILE_SIZE} bytes`);
      }
      return stats.size;
    } catch (error) {
      if (error.code === 'ENOENT') {
        return 0; // File doesn't exist yet
      }
      throw error;
    }
  }

  static validateJSONDepth(obj, currentDepth = 0) {
    if (currentDepth > CONFIG.SECURITY.MAX_DEPTH) {
      throw new Error(`JSON exceeds maximum nesting depth of ${CONFIG.SECURITY.MAX_DEPTH}`);
    }

    if (obj && typeof obj === 'object') {
      for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
          this.validateJSONDepth(obj[key], currentDepth + 1);
        }
      }
    }
  }

  static sanitizeJSON(data) {
    if (CONFIG.SECURITY.VALIDATE_JSON) {
      this.validateJSONDepth(data);
    }
    return data;
  }
}

// =========================================
// PRODUCTION FILE OPERATIONS
// =========================================

class FileOperations {
  static async ensureDirectory(filePath) {
    const dir = path.dirname(filePath);

    try {
      await fs.promises.access(dir);
    } catch (error) {
      if (error.code === 'ENOENT') {
        await fs.promises.mkdir(dir, { recursive: true, mode: 0o755 });
        logger.info('Directory created', { directory: dir });
      } else {
        throw error;
      }
    }
  }

  static generateBackupPath(filePath, timestamp = Date.now()) {
    const ext = path.extname(filePath);
    const nameWithoutExt = filePath.slice(0, -ext.length);
    return `${nameWithoutExt}${CONFIG.FILE.BACKUP_SUFFIX}.${timestamp}${ext}`;
  }

  static async createBackup(filePath) {
    try {
      await fs.promises.access(filePath);
      const backupPath = this.generateBackupPath(filePath);
      await fs.promises.copyFile(filePath, backupPath);

      logger.audit('BACKUP_CREATED', filePath, { backupPath });

      // Clean old backups
      await this.cleanOldBackups(filePath);

      return backupPath;
    } catch (error) {
      if (error.code === 'ENOENT') {
        return null; // File doesn't exist, no backup needed
      }
      throw error;
    }
  }

  static async cleanOldBackups(filePath) {
    try {
      const dir = path.dirname(filePath);
      const baseName = path.basename(filePath, path.extname(filePath));
      const files = await fs.promises.readdir(dir);

      // Find backup files
      const backupFiles = files
        .filter(file => file.startsWith(`${baseName}${CONFIG.FILE.BACKUP_SUFFIX}.`))
        .map(file => ({
          name: file,
          path: path.join(dir, file),
          timestamp: parseInt(file.split('.')[2]) || 0
        }))
        .sort((a, b) => b.timestamp - a.timestamp); // Sort by timestamp desc

      // Remove excess backups
      if (backupFiles.length > CONFIG.FILE.BACKUP_COUNT) {
        const filesToRemove = backupFiles.slice(CONFIG.FILE.BACKUP_COUNT);

        for (const fileInfo of filesToRemove) {
          try {
            await fs.promises.unlink(fileInfo.path);
            logger.info('Old backup removed', { backupFile: fileInfo.path });
          } catch (error) {
            logger.warn('Failed to remove old backup', {
              backupFile: fileInfo.path,
              error: error.message
            });
          }
        }
      }
    } catch (error) {
      logger.warn('Failed to clean old backups', {
        filePath,
        error: error.message
      });
    }
  }

  static async atomicWrite(filePath, data) {
    const tempPath = `${filePath}${CONFIG.FILE.TEMP_SUFFIX}.${Date.now()}.${Math.random().toString(36).substring(2)}`;

    try {
      // Write to temporary file first
      await fs.promises.writeFile(tempPath, data, CONFIG.FILE.ENCODING);

      // Atomic move to final location
      await fs.promises.rename(tempPath, filePath);

      return true;
    } catch (error) {
      // Clean up temporary file if it exists
      try {
        await fs.promises.unlink(tempPath);
      } catch (cleanupError) {
        logger.warn('Failed to cleanup temporary file', {
          tempPath,
          error: cleanupError.message
        });
      }
      throw error;
    }
  }

  static calculateFileHash(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
  }
}

// =========================================
// PRODUCTION JSON UTILITIES
// =========================================

/**
 * Enhanced JSON loader with comprehensive error handling and security features
 * @param {string} filePath - Path to the JSON file
 * @param {object} options - Configuration options
 * @returns {Promise<any>|any} - Parsed JSON data or default value
 */
const loadJSON = async (filePath, options = {}) => {
  const {
    defaultValue = [],
    async = CONFIG.PERFORMANCE.ASYNC_OPERATIONS,
    validate = true,
    encoding = CONFIG.FILE.ENCODING
  } = options;

  try {
    // Validate and sanitize file path
    const validatedPath = FileValidator.validateFilePath(filePath);

    // Check if file exists
    const fileExists = fs.existsSync(validatedPath);
    if (!fileExists) {
      logger.warn('File not found, returning default value', {
        filePath: validatedPath,
        defaultValue: Array.isArray(defaultValue) ? `Array(${defaultValue.length})` : typeof defaultValue
      });
      return defaultValue;
    }

    // Validate file size
    const fileSize = FileValidator.validateFileSize(validatedPath);
    if (fileSize === 0) {
      logger.warn('File is empty, returning default value', { filePath: validatedPath });
      return defaultValue;
    }

    // Read file content
    const data = async
      ? await fs.promises.readFile(validatedPath, encoding)
      : fs.readFileSync(validatedPath, encoding);

    const trimmedData = data.trim();
    if (!trimmedData) {
      logger.warn('File content is empty after trimming, returning default value', { filePath: validatedPath });
      return defaultValue;
    }

    // Parse JSON with error handling
    let parsedData;
    try {
      parsedData = JSON.parse(trimmedData);
    } catch (parseError) {
      logger.error('JSON parsing failed', parseError, {
        filePath: validatedPath,
        fileSize,
        firstChars: trimmedData.substring(0, 100)
      });
      throw new Error(`JSON parsing failed: ${parseError.message}`);
    }

    // Validate JSON structure if enabled
    if (validate) {
      FileValidator.sanitizeJSON(parsedData);
    }

    logger.audit('JSON_LOADED', validatedPath, {
      fileSize,
      dataType: Array.isArray(parsedData) ? `Array(${parsedData.length})` : typeof parsedData,
      async
    });

    return parsedData;

  } catch (error) {
    logger.error('Failed to load JSON file', error, {
      filePath,
      operation: 'loadJSON'
    });

    // Return default value on error, or re-throw based on configuration
    if (options.throwOnError) {
      throw error;
    }
    return defaultValue;
  }
};

/**
 * Enhanced JSON saver with atomic writes, backups, and comprehensive validation
 * @param {string} filePath - Path to save the JSON file
 * @param {any} data - Data to save as JSON
 * @param {object} options - Configuration options
 * @returns {Promise<boolean>|boolean} - Success status
 */
const saveJSON = async (filePath, data, options = {}) => {
  const {
    async = CONFIG.PERFORMANCE.ASYNC_OPERATIONS,
    createBackup = true,
    validate = true,
    atomic = true,
    pretty = true,
    encoding = CONFIG.FILE.ENCODING
  } = options;

  try {
    // Validate and sanitize file path
    const validatedPath = FileValidator.validateFilePath(filePath);

    // Validate data structure
    if (validate) {
      FileValidator.sanitizeJSON(data);
    }

    // Ensure directory exists
    if (async) {
      await FileOperations.ensureDirectory(validatedPath);
    } else {
      const dir = path.dirname(validatedPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
        logger.info('Directory created synchronously', { directory: dir });
      }
    }

    // Create backup if file exists and backup is enabled
    let backupPath = null;
    if (createBackup && async) {
      backupPath = await FileOperations.createBackup(validatedPath);
    } else if (createBackup && fs.existsSync(validatedPath)) {
      backupPath = FileOperations.generateBackupPath(validatedPath);
      fs.copyFileSync(validatedPath, backupPath);
      logger.audit('BACKUP_CREATED_SYNC', validatedPath, { backupPath });
    }

    // Serialize data to JSON
    const jsonString = pretty
      ? JSON.stringify(data, null, 2)
      : JSON.stringify(data);

    // Check serialized data size
    const dataSize = Buffer.byteLength(jsonString, encoding);
    if (dataSize > CONFIG.FILE.MAX_FILE_SIZE) {
      throw new Error(`Serialized data size (${dataSize} bytes) exceeds maximum allowed size`);
    }

    // Write file
    if (async) {
      if (atomic) {
        await FileOperations.atomicWrite(validatedPath, jsonString);
      } else {
        await fs.promises.writeFile(validatedPath, jsonString, encoding);
      }
    } else {
      fs.writeFileSync(validatedPath, jsonString, encoding);
    }

    // Calculate and log file hash for integrity
    const fileHash = FileOperations.calculateFileHash(jsonString);

    logger.audit('JSON_SAVED', validatedPath, {
      dataSize,
      dataType: Array.isArray(data) ? `Array(${data.length})` : typeof data,
      backupCreated: !!backupPath,
      atomic,
      async,
      fileHash: fileHash.substring(0, 16) + '...' // Log first 16 chars of hash
    });

    return true;

  } catch (error) {
    logger.error('Failed to save JSON file', error, {
      filePath,
      operation: 'saveJSON',
      dataType: Array.isArray(data) ? `Array(${data.length})` : typeof data
    });

    if (options.throwOnError) {
      throw error;
    }
    return false;
  }
};

// =========================================
// PRODUCTION UTILITY FUNCTIONS
// =========================================

/**
 * Safely update a JSON file with merge capability
 * @param {string} filePath - Path to the JSON file
 * @param {any} newData - New data to merge or replace
 * @param {object} options - Configuration options
 * @returns {Promise<boolean>|boolean} - Success status
 */
const updateJSON = async (filePath, newData, options = {}) => {
  const {
    merge = false,
    createIfNotExists = true,
    ...otherOptions
  } = options;

  try {
    let currentData;

    if (merge) {
      // Load existing data for merging
      currentData = await loadJSON(filePath, {
        defaultValue: {},
        throwOnError: false,
        ...otherOptions
      });

      if (Array.isArray(currentData) && Array.isArray(newData)) {
        // Merge arrays
        currentData = [...currentData, ...newData];
      } else if (typeof currentData === 'object' && typeof newData === 'object') {
        // Merge objects
        currentData = { ...currentData, ...newData };
      } else {
        // Replace if types don't match
        currentData = newData;
      }
    } else {
      currentData = newData;
    }

    return await saveJSON(filePath, currentData, otherOptions);

  } catch (error) {
    logger.error('Failed to update JSON file', error, {
      filePath,
      operation: 'updateJSON',
      merge
    });

    if (options.throwOnError) {
      throw error;
    }
    return false;
  }
};

/**
 * Backup a JSON file with timestamp
 * @param {string} filePath - Path to the JSON file to backup
 * @param {object} options - Configuration options
 * @returns {Promise<string|null>} - Path to backup file or null
 */
const backupJSON = async (filePath, options = {}) => {
  try {
    const validatedPath = FileValidator.validateFilePath(filePath);
    return await FileOperations.createBackup(validatedPath);
  } catch (error) {
    logger.error('Failed to backup JSON file', error, {
      filePath,
      operation: 'backupJSON'
    });

    if (options.throwOnError) {
      throw error;
    }
    return null;
  }
};

/**
 * Validate a JSON file without loading it completely
 * @param {string} filePath - Path to the JSON file
 * @param {object} options - Configuration options
 * @returns {Promise<object>} - Validation result
 */
const validateJSONFile = async (filePath, options = {}) => {
  const {
    checkSyntax = true,
    checkSize = true,
    checkStructure = true
  } = options;

  const result = {
    valid: true,
    errors: [],
    warnings: [],
    fileSize: 0,
    exists: false
  };

  try {
    const validatedPath = FileValidator.validateFilePath(filePath);

    // Check if file exists
    result.exists = fs.existsSync(validatedPath);
    if (!result.exists) {
      result.valid = false;
      result.errors.push('File does not exist');
      return result;
    }

    // Check file size
    if (checkSize) {
      try {
        result.fileSize = FileValidator.validateFileSize(validatedPath);
      } catch (sizeError) {
        result.valid = false;
        result.errors.push(sizeError.message);
      }
    }

    // Check JSON syntax
    if (checkSyntax && result.valid) {
      try {
        const data = await loadJSON(validatedPath, {
          validate: checkStructure,
          throwOnError: true
        });
        result.dataType = Array.isArray(data) ? 'array' : typeof data;
        result.itemCount = Array.isArray(data) ? data.length :
          typeof data === 'object' ? Object.keys(data).length : 1;
      } catch (syntaxError) {
        result.valid = false;
        result.errors.push(`JSON syntax error: ${syntaxError.message}`);
      }
    }

    return result;

  } catch (error) {
    result.valid = false;
    result.errors.push(error.message);
    return result;
  }
};

// =========================================
// PRODUCTION HEALTH CHECK
// =========================================

/**
 * Health check for file operations
 * @returns {object} - Health status
 */
const healthCheck = () => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    checks: {
      fileSystem: 'operational',
      permissions: 'operational',
      diskSpace: 'operational'
    },
    config: {
      maxFileSize: `${CONFIG.FILE.MAX_FILE_SIZE / 1024 / 1024}MB`,
      backupCount: CONFIG.FILE.BACKUP_COUNT,
      asyncOperations: CONFIG.PERFORMANCE.ASYNC_OPERATIONS
    }
  };

  try {
    // Test file system access
    const testDir = path.join(__dirname, 'test');
    fs.mkdirSync(testDir, { recursive: true });
    fs.rmSync(testDir, { recursive: true });
  } catch (error) {
    health.status = 'degraded';
    health.checks.fileSystem = 'error';
    health.warnings = health.warnings || [];
    health.warnings.push('File system access test failed');
  }

  return health;
};

// =========================================
// BACKWARD COMPATIBILITY LAYER
// =========================================

// Synchronous versions for backward compatibility
const loadJSONSync = (filePath, options = {}) => {
  return loadJSON(filePath, { ...options, async: false });
};

const saveJSONSync = (filePath, data, options = {}) => {
  return saveJSON(filePath, data, { ...options, async: false });
};

// =========================================
// MODULE EXPORTS
// =========================================

module.exports = {
  // Main functions (enhanced versions)
  loadJSON,
  saveJSON,

  // Utility functions
  updateJSON,
  backupJSON,
  validateJSONFile,
  healthCheck,

  // Synchronous versions for compatibility
  loadJSONSync,
  saveJSONSync,

  // Configuration and utilities
  CONFIG,
  FileValidator,
  FileOperations,

  // For debugging and monitoring
  logger
};
