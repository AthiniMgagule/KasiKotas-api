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
const PORT = process.env.PORT || 2025;
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

// Endpoint for owner signup
app.post('/ownerSignup', async (req, res) => {
  const { ownerName, ownerContact, ownerEmail, ownerPassword } = req.body;
  console.log('signup attempt: ', {ownerName, ownerEmail});

  // Validate input presence
  if (!ownerName || !ownerContact || !ownerEmail || !ownerPassword) {
    return res.status(400).send('All fields are required');
  }

  //validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(ownerEmail)){
    return res.status(400).send('please input email in correct format');
  }

  //validate password strength
  const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/;
  if(!passwordRegex.test(ownerPassword)){
    return res.status(400).send('password must be atleast 12 characters long, with at least one upper case letter, one number and one special character');
  }

  //prevent password from being the same as the name or email
  if(ownerPassword.toLowerCase().includes(ownerName.toLowerCase()) || ownerPassword.toLowerCase().includes(ownerEmail.toLowerCase())) {
    return res.status(400).send('Password cannot contain your name or email');
  }

  //validate phone number(only digits and length 10)
  const phoneRegex = /^\d{10}$/;
  if(!phoneRegex.test(ownerContact)){
    return res.status(400).send('invalid phone number. It must contain exactly 10 digits')
  }

  try {
    // Check if the email already exists
    db.get(
      'SELECT ownerEmail FROM owners WHERE ownerEmail = ?',
      [ownerEmail],
      async (err, row) => {
        console.log('database query  result: ', {err, row});
        if (err) {
          console.error('Database error:', err.message);
          return res.status(500).send('Internal Server Error');
        }
        if (row) {
          console.log('existing user already found: ', row);
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
            const verificationLink = `https://kasikotas.netlify.app/owner/verify-email?token=${token}`; 
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

// Endpoint for email verification
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

//Endpoint for owner login
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

// Endpoint to get owners
app.get('/owners', (req, res) => {
  db.all(`SELECT * FROM owners`, [], (err, rows) => {
    if (err) {
      console.error('Error retrieving owners:', err.message);
      res.status(500).send('Internal Server Error');
    } else {
      res.status(200).json(rows);
    }
  });
});

// Endpoint to get owner by email
app.get('/owners/:ownerEmail', (req, res) => {
  const { ownerEmail } = req.params;

  if (!ownerEmail) {
    return res.status(400).send('Email parameter is required');
  }

  const query = 'SELECT * FROM owners WHERE ownerEmail = ?';
  db.get(query, [ownerEmail], (err, row) => {
    if (err) {
      console.error('Error retrieving owner:', err.message);
      return res.status(500).send('Internal Server Error');
    }

    if (!row) {
      return res.status(404).send('User not found');
    }

    res.status(200).json(row);
  });
});

//Endpoint to update owner profile
app.put('/updateOwner/:ownerid', async (req, res) =>{
  const {ownerid} = req.params;
  const {ownerName, ownerContact} = req.body;

  if(!ownerid || !ownerName || !ownerContact){
    return res.status(400).send('all fields are required');
  }

  const phoneRegex = /^\d{10}$/;
  if(!phoneRegex.test(ownerContact)){
    return res.status(400).send('invalid phonenumber, it must contain 10 digits')
  }

  const query = `
    UPDATE owners
    SET ownerName = ?,
      ownerContact = ?
    WHERE ownerid = ?
  `;

  db.run(query, [ownerName, ownerContact, ownerid], function(err){
    if(err){
      console.error('error updating owner:', err.message);
      return res.status(500).send('internal server error');
    }
    if(this.change === 0){
      return res.status(404).send('owner not found');
    }
    res.status(200).json({message: 'onwer profile updated successfully'});
  });
});

// Endpoint to reset password
app.post('/resetPassword', async (req, res) => {
  const { ownerEmail } = req.body;

  if (!ownerEmail) {
    return res.status(400).send('Email is required');
  }

  try {
    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000; // Token valid for 1 hour

    // Update database with reset token
    const query = `
      UPDATE owners 
      SET resetToken = ?,
          resetTokenExpiry = ?
      WHERE ownerEmail = ?
    `;

    db.run(query, [resetToken, resetTokenExpiry, ownerEmail], function(err) {
      if (err) {
        console.error('Database error:', err.message);
        return res.status(500).send('Internal Server Error');
      }

      if (this.changes === 0) {
        return res.status(404).send('Email not found');
      }

      // Send reset password email
      const resetLink = `https://kasikotas.netlify.app/reset-password?token=${resetToken}`;
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: ownerEmail,
        subject: 'Password Reset Request',
        text: `Click the following link to reset your password: ${resetLink}`,
        html: `<p>Click the following link to reset your password:</p><a href="${resetLink}">Reset Password</a>`
      };

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error('Email error:', error.message);
          return res.status(500).send('Failed to send reset email');
        }
        res.status(200).json({ message: 'Password reset email sent' });
      });
    });
  } catch (err) {
    console.error('Error in password reset:', err.message);
    res.status(500).send('Internal Server Error');
  }
});

// Endpoint to Confirm password reset
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
    const query = `
      UPDATE owners 
      SET ownerPassword = ?,
          resetToken = NULL,
          resetTokenExpiry = NULL 
      WHERE resetToken = ? AND resetTokenExpiry > ?
    `;

    db.run(query, [hashedPassword, token, Date.now()], function(err) {
      if (err) {
        console.error('Database error:', err.message);
        return res.status(500).send('Internal Server Error');
      }

      if (this.changes === 0) {
        return res.status(400).send('Invalid or expired reset token');
      }

      res.status(200).json({ message: 'Password reset successful' });
    });
  } catch (err) {
    console.error('Error in password reset confirmation:', err.message);
    res.status(500).send('Internal Server Error');
  }
});

//Endpoint to create a new kota
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

// Get kotas endpoint
app.get('/kotaContents', (req, res) => {
  db.all(`SELECT * FROM kota_contents`, [], (err, rows) => {
    if (err) {
      console.error('Error retrieving kotas:', err.message);
      res.status(500).send('Internal Server Error');
    } else {
      res.status(200).json(rows);
    }
  });
});

// Get each kota by id endpoint
app.get('/kotaContents/:kota_id', (req, res) => {
  const { kota_id } = req.params;

  if (!kota_id) {
    return res.status(400).send('ID parameter is required');
  }

  const query = 'SELECT * FROM kota_contents WHERE kota_id = ?';
  db.get(query, [kota_id], (err, row) => {
    if (err) {
      console.error('Error retrieving kota:', err.message);
      return res.status(500).send('Internal Server Error');
    }

    if (!row) {
      return res.status(404).send('kota not found');
    }

    res.status(200).json(row);
  });
});

//Endpoint to update kota contents
app.put('/updateKota/:kota_id', (req, res) => {
  const kota_id = Number(req.params.kota_id); // Ensure it's a valid number
  const updates = req.body;

  if (!kota_id) {
    return res.status(400).json({ error: 'Kota Id is required and must be a number' });
  }

  // Get the current kota data first
  db.get('SELECT * FROM kota_contents WHERE kota_id = ?', [kota_id], (err, currentKota) => {
    if (err) {
      console.error('Error fetching kota:', err.message);
      return res.status(500).json({ error: 'Internal server error' });
    }

    if (!currentKota) {
      return res.status(404).json({ error: 'Kota not found' });
    }

    // Define allowed fields
    const validFields = ['kota_name', 'chips', 'russians', 'viennas', 'polony', 
                         'cheese', 'lettuce', 'cucumber', 'eggs', 'toasted', 'price'];

    // Filter updates to only valid fields
    const updateFields = [];
    const updateValues = [];

    Object.keys(updates).forEach(field => {
      if (validFields.includes(field) && updates[field] !== undefined) {
        const newValue = updates[field];

        // Skip update if value hasn't changed
        if (currentKota[field] == newValue) return;

        updateFields.push(`${field} = ?`);
        updateValues.push(typeof newValue === 'number' ? newValue : String(newValue)); 
      }
    });

    // If no valid fields were provided or no changes detected
    if (updateFields.length === 0) {
      return res.status(400).json({ error: 'No valid changes to update' });
    }

    // Add kota_id to values for WHERE clause
    updateValues.push(kota_id);

    const query = `UPDATE kota_contents SET ${updateFields.join(', ')} WHERE kota_id = ?`;

    db.run(query, updateValues, function(err) {
      if (err) {
        console.error('Error updating kota:', err.message);
        return res.status(500).json({ error: 'Internal server error' });
      }

      if (this.changes === 0) {
        return res.status(404).json({ error: 'Kota not updated. Ensure the ID is correct.' });
      }

      // Fetch updated data for verification
      db.get('SELECT * FROM kota_contents WHERE kota_id = ?', [kota_id], (err, updatedKota) => {
        if (err) {
          console.error('Error fetching updated kota:', err.message);
          return res.status(500).json({ error: 'Update successful, but could not fetch new data' });
        }
        res.status(200).json({
          message: 'Kota updated successfully',
          updatedKota
        });
      });
    });
  });
});

//Endpoint to delete kota
app.delete('/deleteKota/:kota_id', (req,res) =>{
  const {kota_id} = req.params;

  if(!kota_id){
    return res.status(400).send('Kota Id is required');
  }

  const query = 'DELETE FROM kota_contents WHERE  kota_id =?';
  db.run(query, [kota_id], function(err){
    if(err){
      console.error('error deleting kota:', err.message);
      return res.status(500).send('internal server error');
    }
    if(this.change === 0){
      return res.status(404).send('kota not found');
    }
    res.status(200).json({message: 'kota deleted successfully'});
  });
});

// Create new order endpoint
app.post('/createOrder', (req, res) => {
  const { 
    owner_id,
    customer_name,
    customer_contact,
    kota_id,
    quantity,
    total_price,
    special_instructions
  } = req.body;

  if (!owner_id || !customer_name || !customer_contact || !kota_id || !quantity || !total_price) {
    return res.status(400).send('Required fields are missing');
  }

  const orderStatus = 'pending'; // Initial status

  // First create the order
  const orderQuery = `
    INSERT INTO orders (
      owner_id,
      customer_name,
      customer_contact,
      kota_id,
      quantity,
      total_price,
      special_instructions,
      order_status,
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.run(orderQuery, 
    [owner_id, customer_name, customer_contact, kota_id, quantity, total_price, 
     special_instructions, orderStatus],
    function(err) {
      if (err) {
        console.error('Error creating order:', err.message);
        return res.status(500).send('Internal Server Error');
      }

      const order_id = this.lastID;

      // Create notification for the owner
      const notificationQuery = `
        INSERT INTO notifications (
          owner_id,
          order_id,
          message,
          notification_type,
          created_at,
          is_read
        ) VALUES (?, ?, ?, ?, ?, ?)
      `;

      const notificationMessage = `New order received from ${customer_name}`;
      const notificationType = 'new_order';
      const currentTime = new Date().toISOString();

      db.run(notificationQuery,
        [owner_id, order_id, notificationMessage, notificationType, currentTime, 0],
        function(err) {
          if (err) {
            console.error('Error creating notification:', err.message);
            return res.status(500).send('Internal Server Error');
          }

          res.status(201).json({ 
            message: 'Order created successfully',
            order_id: order_id,
            notification_id: this.lastID
          });
        }
      );
    }
  );
});

// Get all orders for an owner
app.get('/ownerOrders/:owner_id', (req, res) => {
  const { owner_id } = req.params;
  const { status } = req.query; // Optional status filter

  if (!owner_id) {
    return res.status(400).send('Owner ID is required');
  }

  let query = `
    SELECT o.*, k.kota_name 
    FROM orders o
    LEFT JOIN kota_contents k ON o.kota_id = k.kota_id
    WHERE o.owner_id = ?
  `;

  const queryParams = [owner_id];

  if (status) {
    query += ' AND o.order_status = ?';
    queryParams.push(status);
  }

  query += ' ORDER BY o.order_date DESC';

  db.all(query, queryParams, (err, rows) => {
    if (err) {
      console.error('Error retrieving orders:', err.message);
      return res.status(500).send('Internal Server Error');
    }
    res.status(200).json(rows);
  });
});

// Get specific order by ID
app.get('/orders/:order_id', (req, res) => {
  const { order_id } = req.params;

  if (!order_id) {
    return res.status(400).send('Order ID is required');
  }

  const query = `
    SELECT o.*, k.kota_name 
    FROM orders o
    LEFT JOIN kota_contents k ON o.kota_id = k.kota_id
    WHERE o.order_id = ?
  `;

  db.get(query, [order_id], (err, row) => {
    if (err) {
      console.error('Error retrieving order:', err.message);
      return res.status(500).send('Internal Server Error');
    }

    if (!row) {
      return res.status(404).send('Order not found');
    }

    res.status(200).json(row);
  });
});

// Update order status
app.put('/updateOrderStatus/:order_id', (req, res) => {
  const { order_id } = req.params;
  const { order_status } = req.body;

  if (!order_id || !order_status) {
    return res.status(400).send('Order ID and status are required');
  }

  // Validate status
  const validStatuses = ['pending', 'preparing', 'ready', 'delivered', 'cancelled'];
  if (!validStatuses.includes(order_status)) {
    return res.status(400).send('Invalid order status');
  }

  db.get('SELECT owner_id, customer_name FROM orders WHERE order_id=?',
    [order_id],
    (err, order) =>{
      if (err) return res.status(500).send('internal server error');
      if (order) return resolveSoa.status(404).send('order not found');

      db.run('UPDATE  orders SET order_status = ? WHERE order_id = ?', [order_status, order_id], function(err){
        if (err) return res.status(500).send('internal servor error');

        const notificationData = {
          owner_id : order.owner_id,
          order_id : order_id,
          notification_type : order_status === 'cancelled' ? 'order_cancelled' : 'order_update',
          message: order_status === 'cancelled'?
          `Order #${order_id} from ${order.customer_name} has been cancelled` :
          `Oder #${order_id} status updateed to ${order_status}`
        };

        //insert notification
        db.run(`INSERT INTO notifications (owner_id, order_id, message, notification_type) VALUES (?,?,?,?)`,
          [notificationData.owner_id, notificationData.order_id, notificationData.message, notificationData.notification_type]);

          res.status(200).json({message: 'order status updated successfully'});
        }
      );
    }
  );
});

// Get all notifications for an owner
app.get('/ownerNotifications/:owner_id', (req, res) => {
  const { owner_id } = req.params;

  if (!owner_id) {
    return res.status(400).send('Owner ID is required');
  }

  const query = `
    SELECT * FROM notifications 
    WHERE owner_id = ? 
    ORDER BY created_at DESC
  `;

  db.all(query, [owner_id], (err, rows) => {
    if (err) {
      console.error('Error retrieving notifications:', err.message);
      return res.status(500).send('Internal Server Error');
    }
    res.status(200).json(rows);
  });
});

// Mark notification as read
app.put('/markNotificationRead/:notification_id', (req, res) => {
  const { notification_id } = req.params;

  if (!notification_id) {
    return res.status(400).send('Notification ID is required');
  }

  const query = `
    UPDATE notifications 
    SET is_read = 1 
    WHERE notification_id = ?
  `;

  db.run(query, [notification_id], function(err) {
    if (err) {
      console.error('Error marking notification as read:', err.message);
      return res.status(500).send('Internal Server Error');
    }

    if (this.changes === 0) {
      return res.status(404).send('Notification not found');
    }

    res.status(200).json({ message: 'Notification marked as read' });
  });
});

// Delete notification
app.delete('/deleteNotification/:notification_id', (req, res) => {
  const { notification_id } = req.params;

  if (!notification_id) {
    return res.status(400).send('Notification ID is required');
  }

  const query = 'DELETE FROM notifications WHERE notification_id = ?';

  db.run(query, [notification_id], function(err) {
    if (err) {
      console.error('Error deleting notification:', err.message);
      return res.status(500).send('Internal Server Error');
    }

    if (this.changes === 0) {
      return res.status(404).send('Notification not found');
    }

    res.status(200).json({ message: 'Notification deleted successfully' });
  });
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});