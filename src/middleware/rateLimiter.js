const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 5,
    message: { message: 'Too many login attempts. Try again later.' },
});

module.exports = {
    loginLimiter,
};