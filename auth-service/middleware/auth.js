const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const { isValidPhoneNumber } = require('libphonenumber-js');

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
        .optional()
        .isEmail()
        .withMessage('Invalid email format')
        .normalizeEmail(),

    body('phoneNumber')
        .optional()
        .custom((value) => {
            if (!isValidPhoneNumber(value)) {
                throw new Error(
                    'Invalid phone number format. Example: +12XXXXXXXXX'
                );
            }
            return true;
        }),

    body().custom((_, { req }) => {
        if (!req.body.email && !req.body.phoneNumber) {
            throw new Error('At least email or phone number is required');
        }
        return true;
    }),
];

// Login validation
const validateLoginInput = [
    body('loginData')
        .notEmpty()
        .withMessage('Username, phone number or email is required'),

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
    requireAuth,
    requireRole,
};
