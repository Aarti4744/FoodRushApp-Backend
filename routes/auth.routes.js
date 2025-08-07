// routes/auth.routes.js
const express = require('express');
const router = express.Router();
const authController = require('../controllers/auth.controller');
const authenticateToken = require('../middleware/auth.middleware'); // ✅ Import middleware

// ✅ Public routes (no token required)
router.post('/send-otp', authController.sendOtp);
router.post('/verify-otp', authController.verifyOtp);
router.post('/register', authController.register);
router.post('/login', authController.login);
router.get('/users', authController.getAllUsers); // ✅ Public endpoint

// ✅ Protected routes (token required) - Example for future use
// router.get('/profile', authenticateToken, authController.getProfile);
// router.put('/profile', authenticateToken, authController.updateProfile);

module.exports = router;