const XLSX = require('xlsx');
const fs = require('fs');
const bcrypt = require('bcrypt');

// Load Excel
const workbook = XLSX.readFile('./employee_dataset.xlsx');
const sheet = workbook.Sheets[workbook.SheetNames[0]];
const data = XLSX.utils.sheet_to_json(sheet);

// Utility to format DOB as DDMMYYYY
const formatDOB = (dob) => {
  const date = new Date(dob);
  const dd = String(date.getDate()).padStart(2, '0');
  const mm = String(date.getMonth() + 1).padStart(2, '0');
  const yyyy = date.getFullYear();
  return `${dd}${mm}${yyyy}`;
};

// Hash password
const hashPassword = async (plainPassword) => {
  const saltRounds = 10;
  return await bcrypt.hash(plainPassword, saltRounds);
};

const generateUsers = async () => {
  const users = [];
  const plainUsers = [];

  for (const row of data) {
    const employeeId = row['Employee Code']?.toString().trim();
    const name = row['Employee Name']?.trim();
    const department = row['Department']?.trim();
    const dob = row['DOB'];

    if (!employeeId || !name || !department || !dob) continue;

    const plainPassword = formatDOB(dob);
    const hashedPassword = await hashPassword(plainPassword);

    users.push({
      employeeId,
      name,
      department,
      password: hashedPassword
    });

    plainUsers.push({
      employeeId,
      name,
      department,
      password: plainPassword
    });
  }

  fs.writeFileSync('./data/users.json', JSON.stringify(users, null, 2));
  fs.writeFileSync('./data/users_plain.json', JSON.stringify(plainUsers, null, 2));
  console.log('✅ Hashed users saved to data/users.json');
  console.log('✅ Plain users saved to data/users_plain.json');
};

generateUsers();
