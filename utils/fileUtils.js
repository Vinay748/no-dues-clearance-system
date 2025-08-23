const fs = require('fs');
const path = require('path');


// Load JSON Data from File
const loadJSON = (file) => {
  try {
    if (!fs.existsSync(file)) {
      console.warn(`⚠️ File not found: ${file}. Returning empty array.`);
      return [];
    }


    const data = fs.readFileSync(file, 'utf-8').trim();


    if (!data) {
      console.warn(`⚠️ File is empty: ${file}. Returning empty array.`);
      return [];
    }


    return JSON.parse(data);
  } catch (err) {
    console.error(`🔴 Error reading or parsing JSON from ${file}:`, err);
    return [];
  }
};


// Save JSON Data to File (auto creates directories if missing)
const saveJSON = (file, data) => {
  try {
    const dir = path.dirname(file);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
      console.log(`📁 Created missing directory: ${dir}`);
    }


    fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf-8');
    console.log(`✅ Data saved to ${file}`);
  } catch (err) {
    console.error(`🔴 Error writing JSON to ${file}:`, err);
  }
};


module.exports = { loadJSON, saveJSON };