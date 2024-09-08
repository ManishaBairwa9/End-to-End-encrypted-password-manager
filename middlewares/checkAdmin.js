const checkAdmin = (req, res, next) => {
    const userId = req.user.id;  // Assuming req.user is populated by authentication middleware (like JWT)
    
    if (userId === 1) {
        next(); // If user is admin, proceed to the next middleware or route handler
    } else {
        return res.status(403).send('Access denied. Only admin users are allowed.');
    }
};

module.exports = checkAdmin;
