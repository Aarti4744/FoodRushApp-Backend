// middleware/auth.middleware.js
const jwt = require('jsonwebtoken');

const authenticateToken = (req, res, next) => {
  // ✅ Get token from Authorization header or request body
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1] || req.body.token;

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  try {
    // ✅ Verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // ✅ Add user info to request object
    req.user = {
      id: decoded.id,
      email: decoded.email,
      name: decoded.name
    };
    
    next(); // ✅ Continue to next middleware/route handler
  } catch (err) {
    if (err.name === 'JsonWebTokenError') {
      return res.status(403).json({ message: 'Invalid token' });
    }
    if (err.name === 'TokenExpiredError') {
      return res.status(403).json({ message: 'Token expired' });
    }
    return res.status(500).json({ error: err.message });
  }
};

module.exports = authenticateToken;