require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcrypt');
const app = express();
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const PORT = process.env.PORT || 8080;
const dbPath = path.resolve(__dirname, 'database.db');
const db = new sqlite3.Database(dbPath);

app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const transporter = nodemailer.createTransport({
  service : 'gmail',
  auth : {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Signup endpoint
app.post('/ownerSignup', async (req, res) => {
  const { ownerName, ownerContact, ownerEmail, ownerPassword } = req.body;

  // Validate input
  if (!ownerName || !ownerContact || !ownerEmail || !ownerPassword) {
    return res.status(400).send('All fields are required');
  }

  try {
    // Check if the email already exists
    db.get(
      'SELECT ownerEmail FROM owners WHERE ownerEmail = ?',
      [ownerEmail],
      async (err, row) => {
        if (err) {
          console.error('Database error:', err.message);
          return res.status(500).send('Internal Server Error');
        }
        if (row) {
          return res.status(409).send('Email already registered');
        }

        // Hash the password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(ownerPassword, saltRounds);

        // Insert user into the database
        db.run(
          `INSERT INTO owners (ownerName, ownerContact, ownerEmail, ownerPassword) VALUES (?, ?, ?, ?)`,
          [ownerName, ownerContact, ownerEmail, hashedPassword],
          function (err) {
            if (err) {
              console.error('Database error:', err.message);
              return res.status(500).send('Internal Server Error');
            }

            // Generate email verification token
            const token = jwt.sign({ ownerEmail }, JWT_SECRET, { expiresIn: '1h' });

            // Send email verification link
            const verificationLink = `http://localhost:${PORT}/verify-email?token=${token}`;
            const mailOptions = {
              from: process.env.EMAIL_USER,
              to: ownerEmail,
              subject: 'Email Verification',
              text: `Welcome, ${ownerName}! Please verify your email by clicking on the link: ${verificationLink}`,
              html: `<p>Welcome, ${ownerName}!</p><p>Please verify your email by clicking on the link below:</p><a href="${verificationLink}">Verify Email</a>`,
            };

            transporter.sendMail(mailOptions, (error, info) => {
              if (error) {
                console.error('Email error:', error.message);
                return res.status(500).send('Failed to send verification email');
              }
              res.status(201).json({ message: 'User created successfully. Check your email for verification.' });
            });
          }
        );
      }
    );
  } catch (err) {
    console.error('Error during signup:', err.message);
    res.status(500).send('Internal Server Error');
  }
});

// Email verification endpoint
app.get('/verify-email', (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.status(400).send('Verification token is missing');
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { ownerEmail } = decoded;

    // Mark email as verified in the database
    db.run(`UPDATE owners SET isVerified = 1 WHERE ownerEmail = ?`, [ownerEmail], function (err) {
      if (err) {
        console.error('Database error:', err.message);
        return res.status(500).send('Internal Server Error');
      }

      res.send('Email successfully verified! You can now log in.');
    });
  } catch (err) {
    console.error('Invalid or expired token:', err.message);
    res.status(400).send('Invalid or expired token');
  }
});

//endpoint for owner login
app.post('/ownerLogin', async (req, res) => {
  const { ownerEmail, ownerPassword } = req.body;

  // Validate input
  if (!ownerEmail || !ownerPassword) {
    return res.status(400).send('All fields are required');
  }

  try {
    // Retrieve owner from the database
    db.get(`SELECT * FROM owners WHERE ownerEmail = ?`, [ownerEmail], async (err, owner) => {
      if (err) {
        console.error('Database error:', err.message);
        return res.status(500).send('Internal Server Error');
      }

      if (!owner) {
        return res.status(404).send('Owner not found');
      }

      // Check if the email is verified
      if (!owner.isVerified) {
        return res.status(403).send('Please verify your email before logging in');
      }

      // Validate password
      const isValidPassword = await bcrypt.compare(ownerPassword, owner.ownerPassword);

      if (!isValidPassword) {
        return res.status(401).send('Invalid password');
      }

      // Authentication successful, generate JWT token
      const token = jwt.sign(
        { ownerId: owner.id, ownerEmail: owner.ownerEmail },
        JWT_SECRET,
        { expiresIn: '1h' } // Token expires in 1 hour
      );

      // Respond with token and user details
      res.status(200).json({
        message: 'Login successful',
        token,
        ownerName: owner.ownerName,
        ownerEmail: owner.ownerEmail,
      });
    });
  } catch (err) {
    console.error('Error during login:', err.message);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/createKota', (req, res) => {
  const { owner_id, kota_name, chips, russians, viennas, polony, cheese, lettuce, cucumber, eggs, toasted, price } = req.body;

  // Validate the input
  if (!owner_id || !kota_name || !price) {
      return res.status(400).send('Owner ID, Kota name, and price are required');
  }

  // Insert the Kota customization into the database
  const query = `
      INSERT INTO kota_contents (owner_id, kota_name, chips, russians, viennas, polony, cheese, lettuce, cucumber, eggs, toasted, price)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.run(query, [owner_id, kota_name, chips, russians, viennas, polony, cheese, lettuce, cucumber, eggs, toasted, price], function (err) {
      if (err) {
          console.error('Error creating Kota:', err.message);
          return res.status(500).send('Internal Server Error');
      }
      res.status(201).json({ message: 'Kota created successfully', kota_id: this.lastID });
  });
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});