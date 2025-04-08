const { body, validationResult } = require('express-validator');
const requestIp = require('request-ip');

// Email and password validation rules
const validateUserInput = [
    body('username')
        .notEmpty()
        .withMessage('Username is required')
        .matches(/[a-zA-Z0-9_-]+/)
        .withMessage(
            'Username can only contain letters, numbers, dashes, and underscores'
        ),

    body('password')
        .notEmpty()
        .withMessage('Password is required')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters long')
        .matches(/(?=.*[a-z])/)
        .withMessage('Password must contain at least one lowercase letter')
        .matches(/(?=.*[A-Z])/)
        .withMessage('Password must contain at least one uppercase letter')
        .matches(/(?=.*\d)/)
        .withMessage('Password must contain at least one digit')
        .matches(/(?=.*[@$!%*?&])/)
        .withMessage(
            'Password must contain at least one special character (@$!%*?&)'
        ),

    body('confirmPassword')
        .notEmpty()
        .withMessage('Password confirmation is required')
        .custom((value, { req }) => value === req.body.password)
        .withMessage('Passwords must match'),

    body('email')
        .isEmail()
        .withMessage('Invalid email format')
        .normalizeEmail(),
];

const validateLoginInput = [
    body('loginData').notEmpty().withMessage('Username or email is required'),

    body('password').notEmpty().withMessage('Password is required'),
];

const loginAttempts = new Map(); // IP -> {count, lastAttempt}
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000;

const checkRateLimit = (req, res, next) => {
    // Get client IP
    const clientIp = requestIp.getClientIp(req);
    const now = Date.now();

    // Get attempts for current IP
    const attempts = loginAttempts.get(clientIp) || {
        count: 0,
        lastAttempt: now,
    };

    // Reset counter
    if (
        attempts.count >= MAX_LOGIN_ATTEMPTS &&
        now - attempts.lastAttempt > LOCKOUT_TIME
    ) {
        loginAttempts.set(clientIp, { count: 1, lastAttempt: now });
        return next();
    }

    // Check if too many attempts
    if (attempts.count >= MAX_LOGIN_ATTEMPTS) {
        // Calculate time remaining in lockout
        const remainingTime = Math.ceil(
            ((LOCKOUT_TIME - (now - attempts.lastAttempt)) / 60) * 1000
        );

        return res.status(429).json({
            msg: `Too many login attempts. Please try again in ${remainingTime} minutes.`,
        });
    }

    // Update attempts counter
    loginAttempts.set(clientIp, {
        count: attempts.count + 1,
        lastAttempt: now,
    });

    next();
};

const resetLoginAttempts = (ip) => {
    loginAttempts.delete(ip);
};

const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const errorMsgs = errors.array().map((err) => err.msg);

        return res.status(400).json({ errors: errorMsgs });
    }
    next();
};

module.exports = {
    validateUserInput,
    validateLoginInput,
    checkRateLimit,
    resetLoginAttempts,
    handleValidationErrors,
};
