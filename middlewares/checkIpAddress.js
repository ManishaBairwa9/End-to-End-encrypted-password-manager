const db = require('../config/db');

const checkIpAddress = async (req, res, next) => {
    const { email } = req.body;
    const userIp = req.body.ip; // Get the user's IP address

    try {
        // Check if the user exists and get the user's id and ipcheck value
        const [user] = await db.query('SELECT id, ipchecks FROM users WHERE email = ?', [email]);
        if (user.length === 0) return res.status(400).send('User not found');
        
        const userId = user[0].id;
        const ipCheckEnabled = user[0].ipchecks;

        // If ipchecks is 0, skip IP address validation
        if (ipCheckEnabled === 0) {
            return next(); // Proceed to the next middleware or login logic
        }

        // If ipchecks is 1, validate the IP address
        const [ipExists] = await db.query('SELECT * FROM ip_address WHERE user_id = ? AND ip = ?', [userId, userIp]);

        if (ipExists.length === 0) {
            // If IP doesn't exist, block login
            return res.status(403).send('Access denied: IP address not recognized');
        }

        next(); // Proceed to the login logic if IP exists

    } catch (error) {
        console.error(error);
        res.status(500).send('Error checking IP address');
    }
};

module.exports = checkIpAddress;
