// checkhash.js
const bcrypt = require('bcrypt');

const plainPassword = '01011970';
const storedHash = '$2b$10$QcUV7ztprG29mVbJGFG3ReazcDKwgWkextBTp.XPP302SBiDbdOrS'; // Replace with actual hash

bcrypt.compare(plainPassword, storedHash, (err, result) => {
  if (err) {
    console.error('Error comparing:', err);
    return;
  }

  if (result) {
    console.log('✅ Password is correct!');
  } else {
    console.log('❌ Password is incorrect!');
  }
});
