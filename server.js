// server.js
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const userModel = require('./models/userModel');

const app = express();
const port = process.env.PORT || 5000;

// Enable CORS for requests from the React frontend
app.use(cors({ origin: 'http://localhost:3000' }));

// Parse incoming JSON bodies
app.use(express.json());

/**
 * Create a MySQL connection pool just for testing the connection.
 * (The userModel uses its own promise-based pool internally.)
 */
const dbTest = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
});

// Test the database connection on startup
dbTest.getConnection((err, connection) => {
  if (err) {
    console.error('❌ MySQL connection failed:', err);
  } else {
    console.log('✅ Connected to MySQL as ID', connection.threadId);
    connection.release();
  }
});

// Simple root route to verify server is up
app.get('/', (req, res) => {
  res.send('Travel Planner backend is running!');
});

/**
 * POST /api/auth/register
 * Body: {
 *   first_name,
 *   last_name,
 *   email,
 *   password,
 *   phone,
 *   date_of_birth,
 *   address,
 *   travel_interests
 * }
 *
 * - Checks if email already exists
 * - Hashes the password with bcrypt
 * - Generates a UUID for unique_id
 * - Inserts the user into the MySQL `users` table with is_verified = false
 * - Sends a verification email containing a link to /api/auth/verify/:unique_id
 */
app.post('/api/auth/register', async (req, res) => {
  try {
    const {
      first_name,
      last_name,
      email,
      password,
      phone,
      date_of_birth,
      address,
      travel_interests,
    } = req.body;

    // Check if this email is already registered
    const existingUser = await userModel.findByEmail(email);
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered.' });
    }

    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);

    // Generate a unique_id (UUID)
    const unique_id = uuidv4();

    // Insert into the database
    await userModel.createUser({
      unique_id,
      first_name,
      last_name,
      email,
      password_hash,
      phone,
      date_of_birth,
      address,
      travel_interests,
    });

    // Configure nodemailer transporter
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      secure: false, // use true if port = 465
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    // Verification link points back to this API endpoint
    const verifyUrl = `http://localhost:${port}/api/auth/verify/${unique_id}`;
    const mailOptions = {
      from: `"Travel Planner" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Please verify your Travel Planner account',
      html: `
        <p>Hi ${first_name},</p>
        <p>Thank you for registering! Please <a href="${verifyUrl}">click here to verify your email</a>.</p>
        <p>If you did not register, ignore this email.</p>
      `,
    };

    await transporter.sendMail(mailOptions);

    return res.status(201).json({ message: 'Registration successful. Check your email to verify.' });
  } catch (err) {
    console.error('❌ Registration error:', err);
    return res.status(500).json({ error: 'Server error during registration.' });
  }
});

/**
 * GET /api/auth/verify/:unique_id
 *
 * - Finds the user by their unique_id
 * - If found and not yet verified, sets is_verified = true
 * - Returns a simple HTML response indicating success or failure
 */
app.get('/api/auth/verify/:unique_id', async (req, res) => {
  try {
    const { unique_id } = req.params;
    const user = await userModel.findByUniqueId(unique_id);
    if (!user) {
      return res.status(404).send('<h1>Invalid verification link.</h1>');
    }
    if (user.is_verified) {
      return res.send('<h1>Your email is already verified.</h1>');
    }

    await userModel.verifyUser(unique_id);
    return res.send('<h1>Thank you! Your email has been verified.</h1>');
  } catch (err) {
    console.error('❌ Verification error:', err);
    return res.status(500).send('<h1>Server error during verification.</h1>');
  }
});

/**
 * POST /api/auth/login
 * Body: { email, password }
 *
 * - Finds the user by email
 * - Ensures the user is verified
 * - Compares the provided password with the stored bcrypt hash
 * - If valid, issues a signed JWT with a 24-hour expiration
 */
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await userModel.findByEmail(email);
    if (!user) {
      return res.status(400).json({ error: 'Invalid email or password.' });
    }

    // Ensure the user has verified their email
    if (!user.is_verified) {
      return res.status(403).json({ error: 'Please verify your email before logging in.' });
    }

    // Compare the password
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid email or password.' });
    }

    // Create JWT payload
    const payload = {
      id: user.id,
      email: user.email,
      first_name: user.first_name,
      last_name: user.last_name,
    };

    // Sign the token (expires in 24 hours)
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '24h' });

    return res.json({ token, message: 'Login successful.' });
  } catch (err) {
    console.error('❌ Login error:', err);
    return res.status(500).json({ error: 'Server error during login.' });
  }
});

// Start listening for incoming requests
app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
});
