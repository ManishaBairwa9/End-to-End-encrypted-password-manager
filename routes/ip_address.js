const express = require('express');
const db = require('../config/db');

const router = express.Router();
const authenticateToken = require('../middlewares/authenticateToken'); // Import the middleware

// Insert IP Address
router.post('/',authenticateToken, async (req, res) => {
    const { ip } = req.body;
    const user_id = req.user.id;

    try {
        await db.query('INSERT INTO ip_address (ip, user_id) VALUES (?, ?)', [ip, user_id]);
        res.status(201).send('IP address added successfully');
    } catch (error) {
        res.status(500).send('Error inserting IP address');
    }
});

// Delete IP Address
router.delete('/:id',authenticateToken, async (req, res) => {
    const { id } = req.params;

    try {
        const result = await db.query('DELETE FROM ip_address WHERE id = ?', [id]);
        if (result.affectedRows === 0) {
            return res.status(404).send('IP address not found');
        }
        res.send('IP address deleted successfully');
    } catch (error) {
        res.status(500).send('Error deleting IP address');
    }
});

// Get IP Addresses for a User
router.get('/',authenticateToken, async (req, res) => {
    const user_id = req.user.id;

    try {
        const [rows] = await db.query('SELECT * FROM ip_address WHERE user_id = ?', [user_id]);
        if (rows.length === 0) {
            return res.send([]);
        }

        res.json(rows);
    } catch (error) {
        res.status(500).send('Error fetching IP addresses');
    }
});


router.post('/ipcheck', authenticateToken, async (req, res) => {
    const user_id = req.user.id;
    const { check } = req.body;

    // Check if the 'check' value is valid (must be either 0 or 1)
    if (check !== 0 && check !== 1) {
        return res.status(400).json({ message: 'Invalid value for check. Must be 0 or 1.' });
    }

    try {
        // Use backticks around 'check' to avoid SQL syntax errors
        const [result] = await db.query('UPDATE users SET `ipchecks` = ? WHERE id = ?', [check, user_id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'User not found.' });
        }

        res.json({ message: 'Check value updated successfully.' });
    } catch (error) {
        console.error('Error updating check value:', error);
        res.status(500).json({ message: 'Error updating check value.' });
    }
});

module.exports = router;
