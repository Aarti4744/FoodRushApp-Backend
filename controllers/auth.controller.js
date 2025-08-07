const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const transporter = require('../config/email.config');
const generateOtp = require('../utils/generateOtp');
const otpModel = require('../models/otp.model');
const verifiedEmailStore = require('../utils/verifiedEmails');
const userModel = require('../models/user.model');
const generateToken = require('../config/token.config');

// ✅ Send OTP
exports.sendOtp = async (req, res) => {
  const { email } = req.body || {};

  if (!email) return res.status(400).json({ message: "Email is required" });

  const otp = generateOtp();
  const expiresAt = new Date(Date.now() + 1 * 60 * 1000); // 1 minute

  try {
    await otpModel.saveOtp(email, otp, expiresAt);

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP Code',
      text: `Your OTP is ${otp}. It is valid for 1 minute.`
    });

    res.status(200).json({ message: 'OTP sent successfully', email });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// ✅ Verify OTP
exports.verifyOtp = async (req, res) => {
  const { email, otp } = req.body || {};

  if (!email || !otp) return res.status(400).json({ message: "Email and OTP required" });

  try {
    const results = await otpModel.verifyOtp(email, otp);
    if (results.length === 0) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    await otpModel.markOtpUsed(results[0].id);
    verifiedEmailStore.add(email);

    res.status(200).json({ message: 'OTP verified successfully', verifiedEmail: email });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// ✅ Register - Generates unique token for the user
exports.register = async (req, res) => {
  const { name, email, password, confirmPassword } = req.body || {};

  if (!name || !email || !password || !confirmPassword) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ message: 'Passwords do not match' });
  }

  if (!verifiedEmailStore.has(email)) {
    return res.status(403).json({ message: 'Email not verified with OTP' });
  }

  try {
    const exists = await userModel.userExists(email);
    if (exists) {
      return res.status(409).json({ message: 'User already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await userModel.createUser(name, email, hashedPassword);

    const [userResult] = await userModel.getUserByEmail(email);
    const user = userResult[0];

    // ✅ Generate unique token for this specific user
    const token = generateToken({ 
      id: user.id, 
      email: user.email,
      name: user.name 
    });
    
    verifiedEmailStore.remove(email);

    res.status(201).json({
      message: 'User registered successfully',
      user: { 
        id: user.id, 
        name: user.name, 
        email: user.email 
      },
      token // ✅ This token is unique for this user
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// ✅ Login - Hybrid: Bearer token + email/password validation
exports.login = async (req, res) => {
  // ✅ Get token from Authorization header
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Extract token from "Bearer <token>"
  
  // ✅ Get email/password from body
  const { email, password } = req.body || {};

  // ✅ Check if both token and email/password are provided
  if (!token) {
    return res.status(401).json({ message: "Authorization Bearer token is required" });
  }
  
  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required in body" });
  }

  try {
    // ✅ Step 1: Verify and decode the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const { id: tokenId, email: tokenEmail, name: tokenName } = decoded;

    // ✅ Step 2: Verify email/password from database
    const [userResult] = await userModel.getUserWithPasswordByEmail(email);
    const user = userResult[0];

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
      return res.status(401).json({ message: "Incorrect password" });
    }

    // ✅ Step 3: Cross-validate token data with database user
    if (tokenEmail !== user.email || tokenId !== user.id) {
      return res.status(403).json({ 
        message: "Token and user credentials don't match" 
      });
    }

    // ✅ Step 4: Generate new token for security
    const newToken = generateToken({ 
      id: user.id, 
      email: user.email,
      name: user.name 
    });

    res.status(200).json({
      message: "Login successful (hybrid authentication)",
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      },
      token: newToken,
      validationMethod: "Bearer token + Email/Password"
    });

  } catch (err) {
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: "Invalid Bearer token" });
    }
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ message: "Bearer token expired" });
    }
    res.status(500).json({ error: err.message });
  }
};

// ✅ Get All Users - No token required (public endpoint)
exports.getAllUsers = async (req, res) => {
  try {
    const [users] = await userModel.getAllUsers();
    res.status(200).json({
      message: "Users fetched successfully",
      users
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};