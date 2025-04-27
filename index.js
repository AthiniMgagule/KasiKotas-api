require('dotenv').config();
console.log('> DATABASE_URL =', process.env.DATABASE_URL);
const express = require('express');
const { Pool } = require('pg'); // Changed: Using PostgreSQL driver
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const fs = require('fs'); // still used for other reasons
const path = require('path'); // Still needed for path operations
const app = express();
const PORT = process.env.PORT || 2025;

// Create a PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // Required for some PostgreSQL hosting services like Heroku or Neon
});

app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// 📦 Cloudinary configuration:
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// 📦 Updated multer setup using CloudinaryStorage:
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'shops', // All uploads will go into "shops" folder in Cloudinary
    allowed_formats: ['jpg', 'jpeg', 'png', 'gif'],
    transformation: [
      { width: 500, height: 500, crop: 'limit', quality: 'auto', fetch_format: 'auto' }
    ],
  },
});

const upload = multer({ storage: storage });

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Unauthorized, missing or invalid token' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    console.error('Token verification error:', err);
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};

// Test DB connection route
app.get('/test-db', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT NOW()');
    res.status(200).json({ message: 'DB connected successfully', time: rows[0].now });
  } catch (err) {
    console.error('DB Connection Error:', err.message);
    res.status(500).json({ message: 'DB connection failed' });
  }
});

// Endpoint for owner signup
app.post('/signup', async (req, res) => {
  const { name, contact, email, password, usertype } = req.body;
  console.log("API request body: ", req.body);

  // Validate input presence
  if (!name || !contact || !email || !password || !usertype) {
    return res.status(400).send('All fields are required');
  }

  //validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).send('please input email in correct format');
  }

  //validate password strength
  const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/;
  if (!passwordRegex.test(password)) {
    return res.status(400).send('password must be atleast 12 characters long, with at least one upper case letter, one number and one special character');
  }

  //prevent password from being the same as the name or email
  if (password.toLowerCase().includes(name.toLowerCase()) || password.toLowerCase().includes(email.toLowerCase())) {
    return res.status(400).send('Password cannot contain your name or email');
  }

  //validate phone number(only digits and length 10)
  const phoneRegex = /^\d{10}$/;
  if (!phoneRegex.test(contact)) {
    return res.status(400).send('invalid phone number. It must contain exactly 10 digits')
  }

  //check if the userTypes are the required ones
  const userTypes = ['owner', 'customer', 'admin'];

  if (!userTypes.includes(usertype)) {
    return res.status(400).send('Valid user type required');
  }

  try {
    // Check if the email already exists
    const existingUser = await pool.query('SELECT email FROM users WHERE email = $1', [email]);
    
    console.log('database query result: ', existingUser.rows);
    if (existingUser.rows.length > 0) {
      console.log('existing user already found: ', existingUser.rows[0]);
      return res.status(409).send('Email already registered');
    }

    // Hash the password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insert user into the database
    const result = await pool.query(
      `INSERT INTO users (name, contact, email, password, usertype) 
       VALUES ($1, $2, $3, $4, $5) RETURNING id`,
      [name, contact, email, hashedPassword, usertype]
    );
    
    const userId = result.rows[0].id;

    // Generate email verification token
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });

    // Send email verification link
    const verificationLink = `https://kasikotas.netlify.app/owner/verify-email?token=${token}`;
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Email Verification',
      text: `Welcome, ${name}! Please verify your email by clicking on the link: ${verificationLink}`,
      html: `<p>Welcome, ${name}!</p><p>Please verify your email by clicking on the link below:</p><a href="${verificationLink}">Verify Email</a>`,
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('email sent: ', info.response);
    res.status(201).json({ message: 'User created successfully. Check your email for verification.' });
    
  } catch (err) {
    console.error('Error during signup:', err.message);
    res.status(500).send('Internal Server Error');
  }
});

// Endpoint for email verification
app.get('/verify-email', async (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.status(400).send('Verification token is missing');
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { email } = decoded;

    // Mark email as verified in the database
    const result = await pool.query(
      'UPDATE users SET isverified = true WHERE email = $1',
      [email]
    );

    if (result.rowCount === 0) {
      return res.status(404).send('User not found');
    }
    
    res.send('Email successfully verified! You can now log in.');
  } catch (err) {
    console.error('Invalid or expired token:', err.message);
    res.status(400).send('Invalid or expired token');
  }
});

// Endpoint for user login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Validate input
  if (!email || !password) {
    return res.status(400).send('All fields are required');
  }

  try {
    // Retrieve user from the database
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) {
      return res.status(404).send('User not found');
    }

    // Check if the email is verified
    if (!user.isverified) {
      return res.status(403).send('Please verify your email before logging in');
    }

    // Validate password
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).send('Invalid password');
    }

    // Authentication successful, generate JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '1h' } // Token expires in 1 hour
    );

    // Respond with token and user details
    res.status(200).json({
      message: 'Login successful',
      token,
      name: user.name,
      email: user.email,
      id: user.id
    });
  } catch (err) {
    console.error('Error during login:', err);
    res.status(500).send('Internal Server Error');
  }
});

// Endpoint to get users
app.get('/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users');
    res.status(200).json(result.rows);
  } catch (err) {
    console.error('Error retrieving users:', err.message);
    res.status(500).send('Internal Server Error');
  }
});

// Endpoint to update users
app.put('/updateUsers/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  const updates = req.body;

  try {
    // Check if user exists and has permission
    const userResult = await pool.query('SELECT id FROM users WHERE id = $1', [id]);
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = userResult.rows[0];
    if (user.id != req.user.id && req.user.usertype !== 'admin') {
      return res.status(403).json({ message: 'Not authorized to update this user' });
    }

    // Build the SQL query based on provided fields
    const allowedFields = ['name', 'contact', 'email', 'password', 'isshopregistered'];
    
    const fieldsToUpdate = [];
    const valuesToUpdate = [];
    const values = [];
    let paramIndex = 1;
    
    Object.keys(updates).forEach(field => {
      if (allowedFields.includes(field.toLowerCase())) {
        fieldsToUpdate.push(`${field.toLowerCase()} = $${paramIndex}`);
        
        // Handle boolean values
        if (typeof updates[field] === 'boolean') {
          values.push(updates[field]);
        } else {
          values.push(updates[field]);
        }
        paramIndex++;
      }
    });
    
    // If no valid fields to update
    if (fieldsToUpdate.length === 0) {
      return res.status(400).json({ message: 'No valid fields to update' });
    }
    
    // Add user id to values
    values.push(id);
    
    // Construct and execute the update query
    const query = `UPDATE users SET ${fieldsToUpdate.join(', ')} WHERE id = $${paramIndex}`;
    
    const result = await pool.query(query, values);
    
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.status(200).json({ 
      message: 'User updated successfully',
      updatedFields: Object.keys(updates).filter(field => allowedFields.includes(field.toLowerCase()))
        .reduce((obj, key) => {
          obj[key] = updates[key];
          return obj;
        }, {})
    });
  } catch (err) {
    console.error('Database error:', err.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Endpoint to get user by email
app.get('/users/:email', async (req, res) => {
  const { email } = req.params;

  if (!email) {
    return res.status(400).send('Email parameter is required');
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    
    if (result.rows.length === 0) {
      return res.status(404).send('User not found');
    }

    res.status(200).json(result.rows[0]);
  } catch (err) {
    console.error('Error retrieving user:', err.message);
    res.status(500).send('Internal Server Error');
  }
});

// Endpoint to update profile
app.put('/updateProfile/:id', async (req, res) => {
  const { id } = req.params;
  const { name, contact } = req.body;

  if (!id || !name || !contact) {
    return res.status(400).send('All fields are required');
  }

  const phoneRegex = /^\d{10}$/;
  if (!phoneRegex.test(contact)) {
    return res.status(400).send('Invalid phone number, it must contain 10 digits');
  }

  try {
    const result = await pool.query(
      'UPDATE users SET name = $1, contact = $2 WHERE id = $3',
      [name, contact, id]
    );

    if (result.rowCount === 0) {
      return res.status(404).send('User not found');
    }

    res.status(200).json({ message: 'User profile updated successfully' });
  } catch (err) {
    console.error('Error updating user:', err.message);
    res.status(500).send('Internal server error');
  }
});

// Endpoint to reset password
app.post('/resetPassword', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).send('Email is required');
  }

  try {
    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000; // Token valid for 1 hour

    // Update database with reset token
    const result = await pool.query(
      'UPDATE users SET resettoken = $1, resettokenexpiry = $2 WHERE email = $3',
      [resetToken, resetTokenExpiry, email]
    );

    if (result.rowCount === 0) {
      return res.status(404).send('Email not found');
    }

    // Send reset password email
    const resetLink = `http://localhost:2025/reset-password?token=${resetToken}`;
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset Request',
      text: `Click the following link to reset your password: ${resetLink}`,
      html: `<p>Click the following link to reset your password:</p><a href="${resetLink}">Reset Password</a>`
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'Password reset email sent' });
  } catch (err) {
    console.error('Error in password reset:', err.message);
    res.status(500).send('Internal Server Error');
  }
});

// Endpoint to confirm password reset
app.post('/confirmReset', async (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res.status(400).send('Token and new password are required');
  }

  // Validate password strength
  const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/;
  if (!passwordRegex.test(newPassword)) {
    return res.status(400).send('Password must be at least 12 characters long, with at least one upper case letter, one number and one special character');
  }

  try {
    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password and clear reset token
    const result = await pool.query(
      'UPDATE users SET password = $1, resettoken = NULL, resettokenexpiry = NULL WHERE resettoken = $2 AND resettokenexpiry > $3',
      [hashedPassword, token, Date.now()]
    );

    if (result.rowCount === 0) {
      return res.status(400).send('Invalid or expired reset token');
    }

    res.status(200).json({ message: 'Password reset successful' });
  } catch (err) {
    console.error('Error in password reset confirmation:', err.message);
    res.status(500).send('Internal Server Error');
  }
});

// Endpoint for shop registration
app.post('/registerShop', verifyToken, upload.single('logo'), async (req, res) => {
  const {
    ownerid,
    shopname,
    shopaddress,
    shopcity,
    shoppostalcode,
    shopdescription,
    openingtime,
    closingtime,
    shopcategory,
    deliveryradius
  } = req.body;

  // Validate required fields
  if (!ownerid || !shopname || !shopaddress || !shopcity || !shoppostalcode ||
    !shopdescription || !openingtime || !closingtime || !shopcategory || !deliveryradius) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  // Check if file was uploaded
  if (!req.file) {
    return res.status(400).json({ message: 'Shop logo is required' });
  }

  // Use the Cloudinary URL for logo
  const logoPath = req.file.path;

  try {
    // Check if owner has already registered a shop
    const existingShop = await pool.query(
      'SELECT * FROM shops WHERE ownerid = $1',
      [ownerId]
    );

    if (existingShop.rows.length > 0) {
      return res.status(400).json({ message: 'You have already registered a shop' });
    }

    // Insert the shop into the database
    const isapproved = false; // Initial value, awaiting admin approval
    const createdat = new Date().toISOString();

    const shopResult = await pool.query(
      `INSERT INTO shops (
        ownerid,
        shopname,
        shopaddress,
        shopcity,
        shoppostalcode,
        shopdescription,
        openingtime,
        closingtime,
        shopcategory,
        deliveryradius,
        logourl,
        isapproved,
        createdat
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING shopid`,
      [
        ownerid,
        shopname,
        shopaddress,
        shopcity,
        shoppostalcode,
        shopdescription,
        openingtime,
        closingtime,
        shopcategory,
        deliveryradius,
        logoPath,
        isapproved,
        createdat
      ]
    );

    const shopid = shopResult.rows[0].shopid;

    // Create a notification for the admin
    const adminid = 1;
    const notificationmessage = `New shop registration from ${shopName} is awaiting approval`;
    const notificationtype = 'shop_registration';
    const notificationtime = new Date().toISOString();

    await pool.query(
      `INSERT INTO notifications (
        owner_id,
        message,
        notification_type,
        created_at,
        is_read
      ) VALUES ($1, $2, $3, $4, $5)`,
      [adminid, notificationmessage, notificationtype, notificationtime, false]
    );

    // Update the user's profile to mark shop as registered
    await pool.query(
      'UPDATE users SET isshopregistered = true WHERE id = $1',
      [ownerId]
    );

    res.status(201).json({
      message: 'Shop registration submitted successfully. Awaiting admin approval.',
      shopid: shopid
    });
  } catch (err) {
    console.error('Error registering shop:', err.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Endpoint to get shops
app.get('/shops', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM shops');
    res.status(200).json(result.rows);
  } catch (err) {
    console.error('Error retrieving shops:', err.message);
    res.status(500).send('Internal Server Error');
  }
});

// Endpoint to get shop details
app.get('/shops/:ownerid', async (req, res) => {
  const { ownerid } = req.params;
  
  try {
    const result = await pool.query(
      'SELECT * FROM shops WHERE ownerid = $1',
      [ownerid]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Shop not found' });
    }

    res.status(200).json(result.rows[0]);
  } catch (err) {
    console.error('Database error:', err.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Endpoint to update a shop
app.put('/shops/:shopid', verifyToken, async (req, res) => {
  const { shopid } = req.params;
  const updates = req.body;

  try {
    // Check if shop exists and user has permission
    const shopResult = await pool.query(
      'SELECT ownerid FROM shops WHERE shopid = $1',
      [shopid]
    );

    if (shopResult.rows.length === 0) {
      return res.status(404).json({ message: 'Shop not found' });
    }

    const shop = shopResult.rows[0];
    if (shop.ownerid != req.user.id && req.user.usertype !== 'admin') {
      return res.status(403).json({ message: 'Not authorized to update this shop' });
    }

    // Build the SQL query based on provided fields
    const allowedFields = ['shopname', 'shopaddress', 'shopcity', 'shoppostalcode',
      'shopdescription', 'openingtime', 'closingtime',
      'shopcategory', 'deliveryradius', 'isapproved',
      'rejectionreason', 'shopstatus'];
    
    const fieldsToUpdate = [];
    const values = [];
    let paramIndex = 1;
    
    Object.keys(updates).forEach(field => {
      if (allowedFields.includes(field.toLowerCase())) {
        fieldsToUpdate.push(`${field.toLowerCase()} = $${paramIndex}`);
        
        // Handle boolean values
        if (typeof updates[field] === 'boolean') {
          values.push(updates[field]);
        } else {
          values.push(updates[field]);
        }
        paramIndex++;
      }
    });
    
    // If no valid fields to update
    if (fieldsToUpdate.length === 0) {
      return res.status(400).json({ message: 'No valid fields to update' });
    }
    
    // Add shopId to values
    values.push(shopid);
    
    // Construct and execute the update query
    const query = `UPDATE shops SET ${fieldsToUpdate.join(', ')} WHERE shopid = $${paramIndex}`;
    
    const result = await pool.query(query, values);
    
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Shop not found' });
    }
    
    res.status(200).json({ 
      message: 'Shop updated successfully',
      updatedFields: Object.keys(updates).filter(field => allowedFields.includes(field.toLowerCase()))
        .reduce((obj, key) => {
          obj[key] = updates[key];
          return obj;
        }, {})
    });
  } catch (err) {
    console.error('Database error:', err.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Endpoint for admin to approve/reject a shop
app.put('/approveShop/:shopid', verifyToken, async (req, res) => {
  const { shopid } = req.params;
  const { isapproved, rejectionreason } = req.body;

  // Check if user is admin
  if (req.user.usertype !== 'admin') {
    return res.status(403).json({ message: 'Only admin can approve or reject shops' });
  }

  try {
    // Get shop information
    const shopResult = await pool.query(
      'SELECT ownerid, shopname FROM shops WHERE shopid = $1',
      [shopid]
    );

    if (shopResult.rows.length === 0) {
      return res.status(404).json({ message: 'Shop not found' });
    }

    const shop = shopResult.rows[0];

    // Update shop approval status
    await pool.query(
      'UPDATE shops SET isapproved = $1, rejectionreason = $2 WHERE shopid = $3',
      [isapproved, rejectionreason || null, shopid]
    );

    // Create notification for the shop owner
    const notificationType = isapproved ? 'shop_approved' : 'shop_rejected';
    const notificationMessage = isapproved
      ? `Your shop ${shop.shopname} has been approved!`
      : `Your shop ${shop.shopname} registration was not approved. Reason: ${rejectionreason}`;

    await pool.query(
      `INSERT INTO notifications (owner_id, message, notification_type, created_at, is_read)
       VALUES ($1, $2, $3, $4, $5)`,
      [shop.ownerid, notificationMessage, notificationType, new Date().toISOString(), false]
    );

    res.status(200).json({
      message: isapproved ? 'Shop approved successfully' : 'Shop rejected successfully'
    });
  } catch (err) {
    console.error('Error updating shop approval:', err.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});

//continue from this point

// Endpoint to create a new kota
app.post('/createKota', async (req, res) => {
  const { ownerId, kotaName, chips, russians, viennas, polony, cheese, lettuce, cucumber, eggs, toasted, price } = req.body;

  // Validate the input
  if (!ownerId || !kotaName || !price) {
    return res.status(400).send('Owner ID, Kota name, and price are required');
  }

  try {
    // Insert the Kota customization into the database
    const result = await pool.query(
      `INSERT INTO kotacontents (ownerid, kotaname, chips, russians, viennas, polony, cheese, lettuce, cucumber, eggs, toasted, price)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING kotaid`,
      [ownerId, kotaName, chips, russians, viennas, polony, cheese, lettuce, cucumber, eggs, toasted, price]
    );

    res.status(201).json({ message: 'Kota created successfully', kotaId: result.rows[0].kotaid });
  } catch (err) {
    console.error('Error creating Kota:', err.message);
    res.status(500).send('Internal Server Error');
  }
});

// Get kotas endpoint
app.get('/kotaContents', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM kotacontents');
    res.status(200).json(result.rows);
  } catch (err) {
    console.error('Error retrieving kotas:', err.message);
    res.status(500).send('Internal Server Error');
  }
});

// Get each owner's kota by id endpoint
app.get('/kotaContents/:ownerId', async (req, res) => {
  const { ownerId } = req.params;

  if (!ownerId) {
    return res.status(400).send('ID parameter is required');
  }

  try {
    const result = await pool.query(
      'SELECT * FROM kotacontents WHERE ownerid = $1',
      [ownerId]
    );

    if (result.rows.length === 0) {
      return res.status(404).send('Kota not found');
    }

    res.status(200).json(result.rows);
  } catch (err) {
    console.error('Error retrieving kota:', err.message);
    res.status(500).send('Internal Server Error');
  }
});

// Endpoint to update kota contents
app.put('/updateKota/:kotaId', async (req, res) => {
  const kotaId = req.params.kotaId;
  const updates = req.body;

  if (!kotaId) {
    return res.status(400).json({ error: 'Kota Id is required' });
  }

  try {
    // Get the current kota data first
    const currentKotaResult = await pool.query('SELECT * FROM kotacontents WHERE kotaid = $1', [kotaId]);
    
    if (currentKotaResult.rows.length === 0) {
      return res.status(404).json({ error: 'Kota not found' });
    }

    const currentKota = currentKotaResult.rows[0];

    // Define allowed fields
    const validFields = ['kotaname', 'chips', 'russians', 'viennas', 'polony', 
                        'cheese', 'lettuce', 'cucumber', 'eggs', 'toasted', 'price'];

    // Filter updates to only valid fields
    const updateFields = [];
    const updateValues = [];
    let paramIndex = 1;

    Object.keys(updates).forEach(field => {
      if (validFields.includes(field.toLowerCase()) && updates[field] !== undefined) {
        const newValue = updates[field];

        // Skip update if value hasn't changed
        if (currentKota[field.toLowerCase()] == newValue) return;

        updateFields.push(`${field.toLowerCase()} = $${paramIndex}`);
        updateValues.push(newValue);
        paramIndex++;
      }
    });

    // If no valid fields were provided or no changes detected
    if (updateFields.length === 0) {
      return res.status(400).json({ error: 'No valid changes to update' });
    }

    // Add kotaId to values for WHERE clause
    updateValues.push(kotaId);

    const query = `UPDATE kotacontents SET ${updateFields.join(', ')} WHERE kotaid = $${paramIndex}`;

    const result = await pool.query(query, updateValues);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Kota not updated. Ensure the ID is correct.' });
    }
    
    // Fetch updated data for verification
    const updatedKotaResult = await pool.query('SELECT * FROM kotacontents WHERE kotaid = $1', [kotaId]);
    
    res.status(200).json({
      message: 'Kota updated successfully',
      updatedKota: updatedKotaResult.rows[0]
    });
  } catch (err) {
    console.error('Error updating kota:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint to delete kota
app.delete('/deleteKota/:kotaId', async (req, res) => {
  const { kotaId } = req.params;

  if (!kotaId) {
    return res.status(400).send('Kota Id is required');
  }

  try {
    const result = await pool.query('DELETE FROM kotacontents WHERE kotaid = $1', [kotaId]);
    
    if (result.rowCount === 0) {
      return res.status(404).send('Kota not found');
    }
    
    res.status(200).json({ message: 'Kota deleted successfully' });
  } catch (err) {
    console.error('Error deleting kota:', err.message);
    res.status(500).send('Internal server error');
  }
});

// Create new order endpoint
app.post('/createOrder', async (req, res) => {
  const { 
    ownerId,
    customerName,
    customerContact,
    kotaId,
    quantity,
    totalPrice,
    specialInstructions
  } = req.body;

  if (!ownerId || !customerName || !customerContact || !kotaId || !quantity || !totalPrice) {
    return res.status(400).send('Required fields are missing');
  }

  const orderStatus = 'pending'; // Initial status
  const orderDate = new Date().toISOString();

  try {
    // First create the order
    const orderResult = await pool.query(
      `INSERT INTO orders (
        ownerid,
        customername,
        customercontact,
        kotaid,
        quantity,
        totalprice,
        specialinstructions,
        orderstatus,
        orderdate
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING orderid`,
      [ownerId, customerName, customerContact, kotaId, quantity, totalPrice, 
       specialInstructions, orderStatus, orderDate]
    );

    const orderId = orderResult.rows[0].orderid;

    // Create notification for the owner
    const notificationMessage = `New order received from ${customerName}`;
    const notificationType = 'new_order';
    const currentTime = new Date().toISOString();

    const notificationResult = await pool.query(
      `INSERT INTO notifications (
        owner_id,
        order_id,
        message,
        notification_type,
        created_at,
        is_read
      ) VALUES ($1, $2, $3, $4, $5, $6) RETURNING notification_id`,
      [ownerId, orderId, notificationMessage, notificationType, currentTime, false]
    );

    res.status(201).json({ 
      message: 'Order created successfully',
      orderId: orderId,
      notificationId: notificationResult.rows[0].notification_id
    });
  } catch (err) {
    console.error('Error creating order:', err.message);
    res.status(500).send('Internal Server Error');
  }
});

// Get all orders for an owner
app.get('/ownerOrders/:ownerId', async (req, res) => {
  const { ownerId } = req.params;
  const { status } = req.query; // Optional status filter

  if (!ownerId) {
    return res.status(400).send('Owner ID is required');
  }

  try {
    let query = `
      SELECT o.*, k.kotaname 
      FROM orders o
      LEFT JOIN kotacontents k ON o.kotaid = k.kotaid
      WHERE o.ownerid = $1
    `;

    const queryParams = [ownerId];
    let paramIndex = 2;

    if (status) {
      query += ` AND o.orderstatus = $${paramIndex}`;
      queryParams.push(status);
      paramIndex++;
    }

    query += ' ORDER BY o.orderdate DESC';

    const result = await pool.query(query, queryParams);
    res.status(200).json(result.rows);
  } catch (err) {
    console.error('Error retrieving orders:', err.message);
    res.status(500).send('Internal Server Error');
  }
});

// Get specific order by ID
app.get('/orders/:orderId', async (req, res) => {
  const { orderId } = req.params;

  if (!orderId) {
    return res.status(400).send('Order ID is required');
  }

  try {
    const query = `
      SELECT o.*, k.kotaname 
      FROM orders o
      LEFT JOIN kotacontents k ON o.kotaid = k.kotaid
      WHERE o.orderid = $1
    `;

    const result = await pool.query(query, [orderId]);

    if (result.rows.length === 0) {
      return res.status(404).send('Order not found');
    }

    res.status(200).json(result.rows[0]);
  } catch (err) {
    console.error('Error retrieving order:', err.message);
    res.status(500).send('Internal Server Error');
  }
});

// Update order status
app.put('/updateOrderStatus/:orderId', async (req, res) => {
  const { orderId } = req.params;
  const { orderStatus } = req.body;

  if (!orderId || !orderStatus) {
    return res.status(400).send('Order ID and status are required');
  }

  // Validate status
  const validStatuses = ['pending', 'preparing', 'ready', 'delivered', 'cancelled'];
  if (!validStatuses.includes(orderStatus)) {
    return res.status(400).send('Invalid order status');
  }

  try {
    // Get order details
    const orderResult = await pool.query(
      'SELECT ownerid, customername FROM orders WHERE orderid = $1',
      [orderId]
    );

    if (orderResult.rows.length === 0) {
      return res.status(404).send('Order not found');
    }

    const order = orderResult.rows[0];

    // Update order status
    await pool.query(
      'UPDATE orders SET orderstatus = $1 WHERE orderid = $2',
      [orderStatus, orderId]
    );

    // Create notification
    const notificationData = {
      owner_id: order.ownerid,
      order_id: orderId,
      notification_type: orderStatus === 'cancelled' ? 'order_cancelled' : 'order_update',
      message: orderStatus === 'cancelled' ?
        `Order #${orderId} from ${order.customername} has been cancelled` :
        `Order #${orderId} status updated to ${orderStatus}`,
      created_at: new Date().toISOString(),
      is_read: false
    };

    // Insert notification
    await pool.query(
      `INSERT INTO notifications 
        (owner_id, order_id, message, notification_type, created_at, is_read) 
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        notificationData.owner_id, 
        notificationData.order_id, 
        notificationData.message, 
        notificationData.notification_type,
        notificationData.created_at,
        notificationData.is_read
      ]
    );

    res.status(200).json({ message: 'Order status updated successfully' });
  } catch (err) {
    console.error('Error updating order status:', err.message);
    res.status(500).send('Internal Server Error');
  }
});

// Endpoint to post notification
app.post('/notifications', verifyToken, async (req, res) => {
  const { userId, userName, userType, title, message, notificationType, isRead, isDismissed } = req.body;

  if (!userId || !userName || !userType || !title || !message || !notificationType) {
    return res.status(400).send('userId, userName, userType, title, message and notificationType are required');
  }

  try {
    const result = await pool.query(
      `INSERT INTO notifications 
        (user_id, user_name, user_type, title, message, notification_type, is_read, is_dismissed, created_at) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING notification_id`,
      [
        userId, userName, userType, title, message, notificationType, 
        isRead || false, isDismissed || false, new Date().toISOString()
      ]
    );

    res.status(201).json({ 
      message: 'Notification created successfully', 
      notificationId: result.rows[0].notification_id 
    });
  } catch (err) {
    console.error('Error creating notification:', err.message);
    res.status(500).send('Internal Server Error');
  }
});

// Get all notifications for an owner
app.get('/ownerNotifications/:ownerId', async (req, res) => {
  const { ownerId } = req.params;

  if (!ownerId) {
    return res.status(400).send('Owner ID is required');
  }

  try {
    const result = await pool.query(
      `SELECT * FROM notifications 
       WHERE user_id = $1 
       ORDER BY created_at DESC`,
      [ownerId]
    );

    res.status(200).json(result.rows);
  } catch (err) {
    console.error('Error retrieving notifications:', err.message);
    res.status(500).send('Internal Server Error');
  }
});

// Mark notification as read
app.put('/markNotificationRead/:notificationId', async (req, res) => {
  const { notificationId } = req.params;

  if (!notificationId) {
    return res.status(400).send('Notification ID is required');
  }

  try {
    const result = await pool.query(
      'UPDATE notifications SET is_read = true WHERE notification_id = $1',
      [notificationId]
    );

    if (result.rowCount === 0) {
      return res.status(404).send('Notification not found');
    }

    res.status(200).json({ message: 'Notification marked as read' });
  } catch (err) {
    console.error('Error marking notification as read:', err.message);
    res.status(500).send('Internal Server Error');
  }
});

// Delete notification
app.delete('/deleteNotification/:notificationId', async (req, res) => {
  const { notificationId } = req.params;

  if (!notificationId) {
    return res.status(400).send('Notification ID is required');
  }

  try {
    const result = await pool.query(
      'DELETE FROM notifications WHERE notification_id = $1',
      [notificationId]
    );

    if (result.rowCount === 0) {
      return res.status(404).send('Notification not found');
    }

    res.status(200).json({ message: 'Notification deleted successfully' });
  } catch (err) {
    console.error('Error deleting notification:', err.message);
    res.status(500).send('Internal Server Error');
  }
});
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});