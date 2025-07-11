const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const { isValidPhoneNumber } = require('libphonenumber-js');

/**
 * Validation rules for user registration.
 *
 * WHY: Ensures incoming registration data is robust and secure before reaching
 * database or hashing logic. Prevents common injection, weak passwords,
 * and ensures at least one contact method is present.
 */
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

    // Ensure at least one contact method is provided (email or phone)
    body().custom((_, { req }) => {
        if (!req.body.email && !req.body.phoneNumber) {
            throw new Error('At least email or phone number is required');
        }
        return true;
    }),
];

/**
 * Validation rules for login.
 *
 * WHY: Keeps login flows simple but still checks for non-empty fields.
 * Supports login by username/email/phone.
 */
const validateLoginInput = [
    body('loginData')
        .notEmpty()
        .withMessage('Username, phone number or email is required'),

    body('password').notEmpty().withMessage('Password is required'),
];

/**
 * handleValidationErrors
 *
 * WHY: Ensures that if any express-validator checks fail,
 * we stop the request early and respond with a 400, avoiding
 * hitting DB or business logic with invalid data.
 *
 * SIDE EFFECT: Returns immediately with JSON list of errors if invalid.
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
 * requireAuth
 *
 * WHY: Enforces authentication by requiring a valid JWT
 * either from an Authorization header (Bearer token) or
 * from an httpOnly cookie.
 *
 * SECURITY: Protects downstream handlers from unauthenticated access.
 */
const requireAuth = (req, res, next) => {
    let token;
    // Try to pull JWT from Authorization header or from cookies
    if (
        req.headers.authorization &&
        req.headers.authorization.startsWith('Bearer')
    ) {
        token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.accessToken) {
        token = req.cookies.accessToken;
    }

    if (!token) {
        return res
            .status(401)
            .json({ error: 'Unauthorized: No token provided' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
        req.user = decoded; // Attach decoded payload (e.g. { id, role })
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Unauthorized: Invalid token' });
    }
};

/**
 * requireRole
 *
 * WHY: Enforces role-based access control (RBAC) on routes.
 * Only users with roles listed in `allowedRoles` can proceed.
 *
 * USAGE:
 *   router.post('/admin-only', requireAuth, requireRole(['ADMIN']), handler);
 */
const requireRole = (allowedRoles) => (req, res, next) => {
    // If no roles configured, allow by default (open access)
    if (!allowedRoles || !Array.isArray(allowedRoles)) {
        return next();
    }

    // Reject if user's role isn't among allowed roles
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
