

const jwt = require('jsonwebtoken');
const SECRET_KEY = 'your-secret-key';

function generateToken(user) {
    return jwt.sign({ username: user }, SECRET_KEY, { expiresIn: '24h' });
}

function authenticateJWT(req, res, next) {
    const token = req.headers.authorization;

    if (token) {
        jwt.verify(token, SECRET_KEY, (err, user) => {
            if (err) {
                return res.status(403).json({ error: 'Invalid token' });
            }
            req.user = user.username;
            next();
        });
    } else {
        res.status(401).json({ error: 'Token required' });
    }
}

module.exports = { generateToken, authenticateJWT };