// models/userModel.js
const mysql = require('mysql2/promise');
require('dotenv').config();

// Create a promise‐based pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
});

module.exports = {
  // Insert a new user
  createUser: async ({ unique_id, first_name, last_name, email, password_hash, phone, date_of_birth, address, travel_interests }) => {
    const sql = `
      INSERT INTO users 
        (unique_id, first_name, last_name, email, password_hash, phone, date_of_birth, address, travel_interests)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const params = [unique_id, first_name, last_name, email, password_hash, phone, date_of_birth, address, travel_interests];
    const [result] = await pool.execute(sql, params);
    return result.insertId; // returns the new user’s AUTO_INCREMENT id
  },

  // Find user by email
  findByEmail: async (email) => {
    const sql = `SELECT * FROM users WHERE email = ? LIMIT 1`;
    const [rows] = await pool.execute(sql, [email]);
    return rows[0]; // undefined if not found
  },

  // Find user by unique_id (for email verification)
  findByUniqueId: async (unique_id) => {
    const sql = `SELECT * FROM users WHERE unique_id = ? LIMIT 1`;
    const [rows] = await pool.execute(sql, [unique_id]);
    return rows[0];
  },

  // Mark user as verified
  verifyUser: async (unique_id) => {
    const sql = `UPDATE users SET is_verified = TRUE WHERE unique_id = ?`;
    await pool.execute(sql, [unique_id]);
    return;
  },

  // (Optional) Additional user methods can go here...
};
