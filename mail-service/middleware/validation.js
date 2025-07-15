const { body, validationResult } = require('express-validator');

/**
 * validateSendMailInput
 *
 * WHAT: Ensures required fields for sending emails are valid.
 * WHY: Prevents malformed email addresses or unsupported channels
 * from reaching the SMTP layer.
 */
const validateSendMailInput = [
    body('via')
        .optional()
        .isIn(['email', 'phone'])
        .withMessage('`via` must be either email or phone'),
    body('to')
        .if(body('via').equals('phone'))
        .isMobilePhone('any') // or specify locales
        .withMessage('Valid recipient phone required')
        .bail()
        .if(body('via').not().equals('phone'))
        .isEmail()
        .withMessage('Valid recipient email required'),
];

/**
 * handleValidationErrors
 *
 * WHAT: Collects express-validator errors and responds with 400 if any.
 */
const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const messages = errors.array().map((err) => err.msg);
        return res.status(400).json({ errors: messages });
    }
    next();
};

module.exports = { validateSendMailInput, handleValidationErrors };
