const { body, validationResult } = require('express-validator');
const requestIp = require('request-ip');
const jwt = require('jsonwebtoken');

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

// Login validation
const validateLoginInput = [
    body('loginData').notEmpty().withMessage('Username or email is required'),

    body('password').notEmpty().withMessage('Password is required'),
];

/**
 * handleValidationErrors
 *
 * Purpose:
 *   Checks for validation errors in the request. If any errors are present,
 *   it sends a 400 response with an array of error messages.
 *
 * Description:
 *   This middleware uses express-validator's `validationResult` to gather errors
 *   from the request object. If errors exist, it maps them to an array of messages
 *   and returns an HTTP 400 response with the error details. If no errors are found,
 *   it calls `next()` to pass control to the next middleware in the chain.
 *
 * Parameters:
 *   @param {object} req - Express request object, which should contain the result of previous validations.
 *   @param {object} res - Express response object.
 *   @param {function} next - Callback to pass control to the next middleware.
 *
 * Returns:
 *   If validation errors are present, sends a JSON response with status 400.
 *   Otherwise, calls `next()` to continue processing the request.
 */
const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const errorMsgs = errors.array().map((err) => err.msg);

        return res.status(400).json({ errors: errorMsgs });
    }
    next();
};

const loginAttempts = new Map(); // IP -> {count, lastAttempt}
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes

/**
 * Middleware: checkRateLimit
 *
 * Purpose:
 *   Prevent brute-force attacks by limiting the number of login attempts from a single IP.
 *
 * Description:
 *   This middleware checks whether the number of login attempts coming from the client's IP
 *   has exceeded a defined threshold (MAX_LOGIN_ATTEMPTS) within a given period (LOCKOUT_TIME).
 *   If the client exceeds the limit, the middleware responds with a 429 status code and an error message.
 *   Otherwise, it increments the attempt counter and allows the request to proceed.
 *
 * Parameters:
 *   @param {object} req - Express request object. Expects to contain the client's IP.
 *   @param {object} res - Express response object.
 *   @param {function} next - Express next middleware function.
 *
 * Side Effects:
 *   - The middleware updates an in-memory Map (loginAttempts) to track the number of attempts
 *     and the timestamp of the last attempt.
 *   - On exceeding the limit, it sends a response and does not call next().
 *
 * Usage:
 *   app.post('/login', checkRateLimit, loginUser);
 */
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
            (LOCKOUT_TIME - (now - attempts.lastAttempt)) / 60000
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

/**
 * resetLoginAttempts
 *
 * Purpose:
 *   Resets the login attempt counter for a given IP address.
 *
 * Description:
 *   This function deletes the entry for the specified IP address from the
 *   in-memory loginAttempts Map. This is typically called upon a successful
 *   login to clear any previous failed login attempts associated with that IP.
 *
 * Parameters:
 *   @param {string} ip - The IP address whose login attempts should be cleared.
 *
 * Returns:
 *   Nothing; it simply removes the record.
 */
const resetLoginAttempts = (ip) => {
    loginAttempts.delete(ip);
};

/**
 * Middleware that verifies authentication by validating a JWT from either the
 * Authorization header (Bearer token) or from an httpOnly cookie.
 *
 * @param {object} req - Express request object.
 * @param {object} res - Express response object.
 * @param {function} next - Function to pass control to the next middleware.
 *
 * @returns {object|undefined} Returns a 401 error if no valid token is provided, otherwise calls next().
 */
const requireAuth = (req, res, next) => {
    // Get token from Authorization header or cookie
    let token;
    if (
        req.headers.authorization &&
        req.headers.authorization.startsWith('Bearer')
    ) {
        token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.accessToken) {
        token = req.cookies.accessToken;
    }

    // If no token, unauthorized
    if (!token) {
        return res
            .status(401)
            .json({ error: 'Unauthorized: No token provided' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);

        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Unauthorized: Invalid token' });
    }
};

/**
 * Middleware factory that returns a middleware function to restrict access based on user roles.
 *
 * @param {Array<string>} allowedRoles - An array of roles allowed to access the route.
 * @returns {function} Middleware function that checks the authenticated user's role.
 *
 * @example
 * // Use the middleware in a route:
 * router.post('/protected-admin', requireAuth, requireRole(['ADMIN', 'SUPER_ADMIN']), adminHandler);
 */
const requireRole = (allowedRoles) => (req, res, next) => {
    if (!allowedRoles || !Array.isArray(allowedRoles)) {
        // If no allowed roles defined, proceed without restriction
        return next();
    }
    if (!allowedRoles.includes(req.user.role)) {
        return res
            .status(403)
            .json({ error: 'Forbidden: insufficient privileges' });
    }

    next();
};

module.exports = {
    validateUserInput,
    validateLoginInput,
    handleValidationErrors,
    checkRateLimit,
    resetLoginAttempts,
    requireAuth,
    requireRole,
};
