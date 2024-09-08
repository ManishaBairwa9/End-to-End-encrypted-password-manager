const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../config/db');
const checkIpAddress = require('../middlewares/checkIpAddress'); // Import the middleware

const router = express.Router();
const secret = 'goldenheart';  // Use a secure key management in production

// Register
router.post('/register', async (req, res) => {
    const { email, password } = req.body;
    ipAddress = req.body.ip;

    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user into the users table
        await db.query('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashedPassword]);

        // Retrieve user ID by querying the user by email
        const [userResult] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
        const userId = userResult[0]?.id;

        if (!userId) {
            throw new Error('User ID not found');
        }

        // Insert IP address into the ip_address table
        await db.query('INSERT INTO ip_address (user_id, ip) VALUES (?, ?)', [userId, ipAddress]);

        res.status(201).send('User registered');
    } catch (error) {
        res.status(500).send('Error registering user');
    }
});


// Login with IP Address Check
router.post('/login', checkIpAddress, async (req, res) => {
    const { email, password} = req.body;
    try {
        const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) return res.status(400).send('User not found');
        
        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).send('Invalid credentials');
        
        const token = jwt.sign({ id: user.id }, secret, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).send('Error logging in');
    }
});

module.exports = router;
