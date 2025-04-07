const { body, validationResult } = require('express-validator');
const prismaClient = require('../db/prismaClient');

// Email and password validation rules
const validateUserInput = [
    body('username').notEmpty().withMessage('Username is required'),

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

const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const errorMsgs = errors.array().map((err) => err.msg);

        return res.status(400).json({ errors: errorMsgs });
    }
    next();
};

const checkUserExistence = async (email, username) => {
    // Query both email and username in one query using OR condition
    const existingUser = await prismaClient.user.findFirst({
        where: {
            OR: [{ email }, { username }],
        },
    });

    // If user already exists, return the appropriate error message
    if (existingUser) {
        if (existingUser.email === email) {
            return 'Email is already taken';
        }
        if (existingUser.username === username) {
            return 'Username is already taken';
        }
    }

    // Return null if no issues found
    return null;
};

module.exports = {
    validateUserInput,
    handleValidationErrors,
    checkUserExistence,
};
