const transporter = require('../config/email.config');
const generateOtp = require('../utils/generateOtp');
const otpModel = require('../models/otp.model');

// ✅ POST /auth/send-otp
exports.sendOtp = async (req, res) => {
  const { email } = req.body || {}; // ⛑ Safe destructuring

  if (!email) {
    return res.status(400).json({ message: "Email is required" });
  }

  const otp = generateOtp();
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

  try {
    await otpModel.saveOtp(email, otp, expiresAt);

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP Code',
      text: `Your OTP is ${otp}. It is valid for 5 minutes.`
    };

    await transporter.sendMail(mailOptions);

    res.status(200).json({
      message: 'OTP sent successfully',
      email
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// ✅ POST /auth/verify-otp
exports.verifyOtp = async (req, res) => {
  const { email, otp } = req.body || {};

  if (!email || !otp) {
    return res.status(400).json({ message: "Email and OTP required" });
  }

  try {
    const results = await otpModel.verifyOtp(email, otp);

    if (results.length === 0) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    await otpModel.markOtpUsed(results[0].id);

    res.status(200).json({
      message: 'OTP verified successfully',
      verifiedEmail: email
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
