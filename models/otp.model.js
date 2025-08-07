//otp model

const db = require('../config/db.config');

// Save OTP
exports.saveOtp = async (email, otp, expiresAt) => {
  const sql = `INSERT INTO otp_store (email, otp, expires_at) VALUES (?, ?, ?)`;
  return db.query(sql, [email, otp, expiresAt]);
};

// Verify OTP
exports.verifyOtp = async (email, otp) => {
  const sql = `
    SELECT * FROM otp_store 
    WHERE email = ? AND otp = ? AND is_used = FALSE AND expires_at > NOW()
    ORDER BY id DESC LIMIT 1
  `;
  const [rows] = await db.query(sql, [email, otp]);
  return rows;
};


// Mark OTP as used
exports.markOtpUsed = async (id) => {
  const sql = `UPDATE otp_store SET is_used = TRUE WHERE id = ?`;
  return db.query(sql, [id]);
};
