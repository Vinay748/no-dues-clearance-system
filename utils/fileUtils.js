const fs = require('fs');
const path = require('path');

// Enhanced JSON loading with better error handling and validation
const loadJSON = (file) => {
  try {
    // Check if file exists
    if (!fs.existsSync(file)) {
      console.warn(`⚠️ File not found: ${file}. Returning empty array.`);
      return [];
    }

    // Get file stats to check if it's actually a file
    const stats = fs.statSync(file);
    if (!stats.isFile()) {
      console.warn(`⚠️ Path is not a file: ${file}. Returning empty array.`);
      return [];
    }

    // Read file content
    const data = fs.readFileSync(file, 'utf-8').trim();

    // Check if file is empty
    if (!data) {
      console.warn(`⚠️ File is empty: ${file}. Returning empty array.`);
      return [];
    }

    // Parse JSON with better error handling
    const parsedData = JSON.parse(data);
    
    // Validate that parsed data is not null or undefined
    if (parsedData === null || parsedData === undefined) {
      console.warn(`⚠️ File contains null/undefined data: ${file}. Returning empty array.`);
      return [];
    }

    console.log(`✅ Successfully loaded JSON from ${file}`);
    return parsedData;

  } catch (err) {
    if (err instanceof SyntaxError) {
      console.error(`🔴 JSON parsing error in ${file}:`, err.message);
    } else if (err.code === 'ENOENT') {
      console.error(`🔴 File not found: ${file}`);
    } else if (err.code === 'EACCES') {
      console.error(`🔴 Permission denied accessing ${file}`);
    } else if (err.code === 'EISDIR') {
      console.error(`🔴 Path is a directory, not a file: ${file}`);
    } else {
      console.error(`🔴 Error reading or parsing JSON from ${file}:`, err);
    }
    return [];
  }
};

// Enhanced JSON saving with atomic write operations and backup
const saveJSON = (file, data, options = {}) => {
  try {
    // Validate input data
    if (data === null || data === undefined) {
      console.error(`🔴 Cannot save null or undefined data to ${file}`);
      return false;
    }

    // Set default options
    const defaultOptions = {
      createBackup: false,
      prettyPrint: true,
      atomicWrite: true,
      encoding: 'utf-8'
    };
    const config = { ...defaultOptions, ...options };

    // Ensure directory exists
    const dir = path.dirname(file);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
      console.log(`📁 Created missing directory: ${dir}`);
    }

    // Create backup if requested and file exists
    if (config.createBackup && fs.existsSync(file)) {
      const backupFile = `${file}.backup.${Date.now()}`;
      fs.copyFileSync(file, backupFile);
      console.log(`💾 Created backup: ${backupFile}`);
    }

    // Stringify data with proper formatting
    const jsonString = config.prettyPrint 
      ? JSON.stringify(data, null, 2)
      : JSON.stringify(data);

    if (config.atomicWrite) {
      // Atomic write: write to temporary file first, then rename
      const tempFile = `${file}.tmp.${Date.now()}`;
      
      try {
        fs.writeFileSync(tempFile, jsonString, config.encoding);
        fs.renameSync(tempFile, file);
        console.log(`✅ Data atomically saved to ${file}`);
      } catch (atomicError) {
        // Clean up temp file if it exists
        if (fs.existsSync(tempFile)) {
          fs.unlinkSync(tempFile);
        }
        throw atomicError;
      }
    } else {
      // Direct write
      fs.writeFileSync(file, jsonString, config.encoding);
      console.log(`✅ Data saved to ${file}`);
    }

    return true;

  } catch (err) {
    if (err.code === 'ENOSPC') {
      console.error(`🔴 No space left on device when writing to ${file}`);
    } else if (err.code === 'EACCES') {
      console.error(`🔴 Permission denied writing to ${file}`);
    } else if (err.code === 'EMFILE' || err.code === 'ENFILE') {
      console.error(`🔴 Too many open files when writing to ${file}`);
    } else {
      console.error(`🔴 Error writing JSON to ${file}:`, err);
    }
    return false;
  }
};

// Asynchronous JSON loading function
const loadJSONAsync = (file) => {
  return new Promise((resolve, reject) => {
    // Check if file exists
    if (!fs.existsSync(file)) {
      console.warn(`⚠️ File not found: ${file}. Returning empty array.`);
      return resolve([]);
    }

    fs.readFile(file, 'utf-8', (err, data) => {
      if (err) {
        console.error(`🔴 Error reading file ${file}:`, err);
        return resolve([]);
      }

      const trimmedData = data.trim();
      if (!trimmedData) {
        console.warn(`⚠️ File is empty: ${file}. Returning empty array.`);
        return resolve([]);
      }

      try {
        const parsedData = JSON.parse(trimmedData);
        console.log(`✅ Successfully loaded JSON from ${file} (async)`);
        resolve(parsedData);
      } catch (parseError) {
        console.error(`🔴 JSON parsing error in ${file}:`, parseError.message);
        resolve([]);
      }
    });
  });
};

// Asynchronous JSON saving function
const saveJSONAsync = (file, data, options = {}) => {
  return new Promise((resolve, reject) => {
    try {
      // Validate input data
      if (data === null || data === undefined) {
        console.error(`🔴 Cannot save null or undefined data to ${file}`);
        return resolve(false);
      }

      const defaultOptions = {
        prettyPrint: true,
        encoding: 'utf-8'
      };
      const config = { ...defaultOptions, ...options };

      // Ensure directory exists
      const dir = path.dirname(file);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
        console.log(`📁 Created missing directory: ${dir}`);
      }

      // Stringify data
      const jsonString = config.prettyPrint 
        ? JSON.stringify(data, null, 2)
        : JSON.stringify(data);

      fs.writeFile(file, jsonString, config.encoding, (err) => {
        if (err) {
          console.error(`🔴 Error writing JSON to ${file}:`, err);
          return resolve(false);
        }
        console.log(`✅ Data saved to ${file} (async)`);
        resolve(true);
      });

    } catch (err) {
      console.error(`🔴 Error preparing to write JSON to ${file}:`, err);
      resolve(false);
    }
  });
};

// Utility function to safely merge JSON data
const mergeJSON = (file, newData, mergeKey = null) => {
  try {
    const existingData = loadJSON(file);
    let mergedData;

    if (Array.isArray(existingData)) {
      if (Array.isArray(newData)) {
        mergedData = [...existingData, ...newData];
      } else {
        mergedData = [...existingData, newData];
      }
    } else if (typeof existingData === 'object' && typeof newData === 'object') {
      if (mergeKey && existingData[mergeKey] && newData[mergeKey]) {
        // Merge arrays by key
        mergedData = {
          ...existingData,
          [mergeKey]: [...(existingData[mergeKey] || []), ...(newData[mergeKey] || [])]
        };
      } else {
        // Simple object merge
        mergedData = { ...existingData, ...newData };
      }
    } else {
      console.warn(`⚠️ Cannot merge incompatible data types for ${file}`);
      return false;
    }

    return saveJSON(file, mergedData);
  } catch (err) {
    console.error(`🔴 Error merging JSON for ${file}:`, err);
    return false;
  }
};

// Utility function to validate JSON file
const validateJSON = (file) => {
  try {
    const data = loadJSON(file);
    return {
      isValid: true,
      data: data,
      size: fs.existsSync(file) ? fs.statSync(file).size : 0,
      lastModified: fs.existsSync(file) ? fs.statSync(file).mtime : null
    };
  } catch (err) {
    return {
      isValid: false,
      error: err.message,
      size: 0,
      lastModified: null
    };
  }
};

module.exports = { 
  loadJSON, 
  saveJSON,
  loadJSONAsync,
  saveJSONAsync,
  mergeJSON,
  validateJSON
};
