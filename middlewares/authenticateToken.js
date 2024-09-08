const jwt = require('jsonwebtoken');
const secret = 'goldenheart'; // Use a secure key management in production

// Middleware to verify token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Extract the token from the Authorization header
    
    if (token == null) {
        return res.sendStatus(401); // If no token, return Unauthorized status
    }
    
    jwt.verify(token, secret, (err, user) => {
        if (err) {
            return res.sendStatus(403); // If token is invalid, return Forbidden status
        }
        req.user = user; // Attach the decoded token to req.user
        next(); // Call next to proceed to the next middleware/route handler
    });
};

module.exports = authenticateToken; // Export the middleware
