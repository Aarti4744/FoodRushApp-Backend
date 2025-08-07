const db = require('../config/db.config');

// Create new user
exports.createUser = async (name, email, hashedPassword) => {
  const sql = `INSERT INTO users (name, email, password) VALUES (?, ?, ?)`;
  return db.query(sql, [name, email, hashedPassword]);
};

// Check if user exists
exports.userExists = async (email) => {
  const sql = `SELECT id FROM users WHERE email = ? LIMIT 1`;
  const [result] = await db.query(sql, [email]);
  return result.length > 0;
};

// ✅ Get user by email (without password)
exports.getUserByEmail = async (email) => {
  const sql = `SELECT id, name, email FROM users WHERE email = ? LIMIT 1`;
  return db.query(sql, [email]);
};

// ✅ Get user with password (for login)
exports.getUserWithPasswordByEmail = async (email) => {
  const sql = `SELECT id, name, email, password FROM users WHERE email = ? LIMIT 1`;
  return db.query(sql, [email]);
};

// ✅ Get all users (excluding passwords)
exports.getAllUsers = async () => {
  const sql = `SELECT id, name, email FROM users`;
  return db.query(sql);
};
