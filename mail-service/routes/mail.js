const express = require('express');
const { sendResetPasswordLink } = require('../controllers/mail');

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
router.post('/send-reset-link', sendResetPasswordLink);

module.exports = router;
