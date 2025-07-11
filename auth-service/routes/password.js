const express = require('express');
const router = express.Router();

const { forgotPassword, resetPassword } = require('../controllers/password');

/**
 * Sends password reset link via email (or phone in future).
 *
 * WHY:
 *   - Initiates forgot password flow by generating and storing a hashed token.
 *   - Never reveals whether account exists (for privacy).
 */
router.post('/forgot-password', forgotPassword);

/**
 * Resets user password using a one-time token.
 *
 * WHY:
 *   - Validates token from email, ensures it's unused & unexpired before resetting password.
 *   - Marks token as used immediately to prevent reuse.
 */
router.post('/reset-password', resetPassword);

module.exports = router;
