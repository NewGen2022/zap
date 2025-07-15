const express = require('express');
const {
    sendResetPasswordLink,
    sendVerificationLink,
} = require('../controllers/mail');
const {
    validateSendMailInput,
    handleValidationErrors,
} = require('../middleware/validation');

const router = express.Router();

/**
 * POST /send-reset-link
 *
 * WHAT:
 *   - Endpoint to trigger sending a password reset link by email (SMS support planned).
 *
 * WHY:
 *   - Keeps email-specific API routes separate from core authentication or user logic.
 *   - Makes it easy to extend with other mail endpoints (verification, alerts).
 *
 * SECURITY:
 *   - Responds generically regardless of whether the user exists to prevent data leaks or enumeration.
 */
router.post(
    '/send-reset-link',
    validateSendMailInput,
    handleValidationErrors,
    sendResetPasswordLink
);

/**
 * POST /send-verification-link
 *
 * WHAT:
 *   - Endpoint to trigger sending an account verification email to confirm ownership.
 *
 * WHY:
 *   - Keeps email-specific API routes separate from core authentication or user logic.
 *
 * SECURITY:
 *   - Responds generically to avoid leaking whether an email is registered.
 */
router.post(
    '/send-verification-link',
    validateSendMailInput,
    handleValidationErrors,
    sendVerificationLink
);

module.exports = router;
