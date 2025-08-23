// ✅ Check if the user is authenticated (logged in)
const isAuthenticated = (req, res, next) => {
  if (!req.session || !req.session.user) {
    console.warn('🔒 Blocked: Not authenticated');
    return res.status(401).json({ success: false, message: 'Please log in first' });
  }
  next();
};

// ✅ Restrict access to specific roles or multiple roles (case-insensitive)
const roleAuth = (requiredRole) => {
  // Normalize requiredRole to an array of lowercase strings
  const roles = Array.isArray(requiredRole)
    ? requiredRole.map(r => r.toLowerCase())
    : [requiredRole.toLowerCase()];

  return (req, res, next) => {
    // Debug logging for troubleshooting
    console.log('🔍 Role auth check for:', roles.join(', '));
    console.log('🔍 Session user:', req.session?.user ? 'exists' : 'missing');

    // FIXED: Check session and user object structure
    if (!req.session || !req.session.user) {
      console.warn(`⛔ Unauthorized access attempt. No session or user found. URL: ${req.originalUrl}`);
      return res.status(401).json({ success: false, message: 'Not authenticated - no session found' });
    }

    // FIXED: Check for role in user object, not directly in session
    const userRole = req.session.user.role;

    if (!userRole) {
      console.warn(`⛔ Unauthorized access attempt. No role found in user session. URL: ${req.originalUrl}`);
      return res.status(403).json({ success: false, message: 'Access denied: No role found in user session' });
    }

    const normalizedUserRole = userRole.toLowerCase();

    if (!roles.includes(normalizedUserRole)) {
      console.warn(`⛔ Unauthorized access attempt. Required: ${roles.join(', ')}, Found: ${userRole}, URL: ${req.originalUrl}`);
      return res.status(403).json({
        success: false,
        message: `Access denied: Required role '${roles.join(' or ')}', found '${userRole}'`
      });
    }

    // Success - log the access grant
    console.log(`✅ Access granted for ${userRole} to ${roles.join(' or ')} endpoint: ${req.originalUrl}`);
    next();
  };
};

// ✅ Enhanced middleware for specific employee access (bonus)
const employeeAuth = (req, res, next) => {
  if (!req.session?.user) {
    return res.status(401).json({ success: false, message: 'Not authenticated' });
  }

  const user = req.session.user;

  if (user.role !== 'employee') {
    return res.status(403).json({ success: false, message: 'Employee access required' });
  }

  // Ensure employee has required identifiers
  const employeeId = user.employeeId || user.id;
  if (!employeeId) {
    return res.status(403).json({ success: false, message: 'Invalid employee session - missing ID' });
  }

  console.log(`✅ Employee access granted: ${employeeId} (${user.name || 'Unknown'})`);
  next();
};

// ✅ Enhanced middleware for HOD access (bonus)
const hodAuth = (req, res, next) => {
  if (!req.session?.user) {
    return res.status(401).json({ success: false, message: 'Not authenticated' });
  }

  const user = req.session.user;

  if (user.role !== 'hod') {
    return res.status(403).json({ success: false, message: 'HOD access required' });
  }

  const hodId = user.hodId || user.id;
  if (!hodId) {
    return res.status(403).json({ success: false, message: 'Invalid HOD session - missing ID' });
  }

  console.log(`✅ HOD access granted: ${hodId} (${user.name || 'Unknown'})`);
  next();
};

// ✅ Enhanced middleware for IT access (bonus)
const itAuth = (req, res, next) => {
  if (!req.session?.user) {
    return res.status(401).json({ success: false, message: 'Not authenticated' });
  }

  const user = req.session.user;

  if (user.role !== 'it') {
    return res.status(403).json({ success: false, message: 'IT access required' });
  }

  const itId = user.itId || user.id;
  if (!itId) {
    return res.status(403).json({ success: false, message: 'Invalid IT session - missing ID' });
  }

  console.log(`✅ IT access granted: ${itId} (${user.name || 'Unknown'})`);
  next();
};

// ✅ Middleware to check if user has any of multiple roles
const multiRoleAuth = (...allowedRoles) => {
  const normalizedRoles = allowedRoles.map(role => role.toLowerCase());

  return (req, res, next) => {
    if (!req.session?.user) {
      return res.status(401).json({ success: false, message: 'Not authenticated' });
    }

    const userRole = req.session.user.role?.toLowerCase();

    if (!userRole || !normalizedRoles.includes(userRole)) {
      return res.status(403).json({
        success: false,
        message: `Access denied: Required one of [${allowedRoles.join(', ')}], found '${req.session.user.role || 'none'}'`
      });
    }

    console.log(`✅ Multi-role access granted: ${req.session.user.role} matches [${allowedRoles.join(', ')}]`);
    next();
  };
};

module.exports = {
  roleAuth,
  isAuthenticated,
  employeeAuth,    // Specific employee middleware
  hodAuth,         // Specific HOD middleware  
  itAuth,          // Specific IT middleware
  multiRoleAuth,   // Multiple roles middleware
};
