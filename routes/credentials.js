const express = require('express');
const db = require('../config/db');
const { encrypt, decrypt } = require('../utils/encryption');

const router = express.Router();

const authenticateToken = require('../middlewares/authenticateToken'); // Import the middleware

// Post credentials
router.post('/', authenticateToken, async (req, res) => {
    const { name, link, password } = req.body;
    const userId = req.user.id;
    try {
        const encryptedName = encrypt(name);
        const encryptedLink = encrypt(link);
        const encryptedPassword = encrypt(password);
        await db.query('INSERT INTO credentials (name, link, password, user_id) VALUES (?, ?, ?, ?)', [encryptedName, encryptedLink, encryptedPassword, userId]);
        res.status(201).send('Credentials added');
    } catch (error) {
        res.status(500).send('Error adding credentials');
    }
});

// Get credentials
router.get('/', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    try {
        const [rows] = await db.query('SELECT * FROM credentials WHERE user_id = ?', [userId]);
        const decryptedRows = rows.map(row => ({
            id: row.id,
            name: decrypt(row.name),
            link: decrypt(row.link),
            password: decrypt(row.password)
        }));
        res.json(decryptedRows);
    } catch (error) {
        console.error('Error retrieving credentials:', error); // Add detailed logging
        res.status(500).send('Error retrieving credentials');
    }
});


// Edit (Update) credentials
router.put('/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { name, link, password } = req.body;
    const userId = req.user.id;
    try {
        const encryptedName = encrypt(name);
        const encryptedLink = encrypt(link);
        const encryptedPassword = encrypt(password);

        const result = await db.query(
            'UPDATE credentials SET name = ?, link = ?, password = ? WHERE id = ? AND user_id = ?',
            [encryptedName, encryptedLink, encryptedPassword, id, userId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).send('Credential not found or unauthorized');
        }

        res.send('Credential updated successfully');
    } catch (error) {
        res.status(500).send('Error updating credentials');
    }
});

// Delete credentials
router.delete('/:id',authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;
    try {
        const result = await db.query('DELETE FROM credentials WHERE id = ? AND user_id = ?', [id, userId]);

        if (result.affectedRows === 0) {
            return res.status(404).send('Credential not found or unauthorized');
        }

        res.send('Credential deleted successfully');
    } catch (error) {
        res.status(500).send('Error deleting credential');
    }
});

module.exports = router;
