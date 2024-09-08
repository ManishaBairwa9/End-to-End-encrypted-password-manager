const express = require('express');
const db = require('../config/db');
const authenticateToken = require('../middlewares/authenticateToken'); // Authentication middleware
const checkAdmin = require('../middlewares/checkAdmin'); // Import the admin check middleware

const router = express.Router();

// Delete a user (Admin Only)
router.delete('/:id', authenticateToken, checkAdmin, async (req, res) => {
    const { id } = req.params;

    try {
        const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [id]);
        if (rows.length === 0) return res.status(404).send('User not found');

        await db.query('DELETE FROM users WHERE id = ?', [id]);
        res.send('User deleted successfully');
    } catch (error) {
        res.status(500).send('Error deleting user');
    }
});

// Get users with pagination(Admin Only)
router.get('', authenticateToken, checkAdmin, async (req, res) => {
    const { page = 1, limit = 10 } = req.query; // Default to page 1 and limit 10 if not specified

    // Convert to integers
    const pageNumber = parseInt(page, 10);
    const pageSize = parseInt(limit, 10);

    if (isNaN(pageNumber) || pageNumber < 1 || isNaN(pageSize) || pageSize < 1) {
        return res.status(400).send('Invalid pagination parameters');
    }

    const offset = (pageNumber - 1) * pageSize;

    try {
        // Get paginated users
        const [rows] = await db.query('SELECT id, email FROM users LIMIT ? OFFSET ?', [pageSize, offset]);
        res.json(rows);
    } catch (error) {
        res.status(500).send('Error retrieving users');
    }
});

module.exports = router;
