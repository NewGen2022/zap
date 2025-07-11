const express = require('express');
const {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    forgotPassword,
    resetPassword,
} = require('../controllers/auth');
const {
    validateUserInput,
    handleValidationErrors,
    validateLoginInput,
} = require('../middleware/auth');
const { checkRateLimit } = require('../middleware/rateLimit');

const router = express.Router();

/**
 * Registers a new user.
 *
 * WHY:
 *   - Ensures user data is validated (username, email/phone, password strength).
 *   - Protects against malformed input before reaching DB layer.
 * FLOW:
 *   -> validate input -> handleValidationErrors stops if errors -> registerUser saves user.
 */
router.post(
    '/register',
    validateUserInput,
    handleValidationErrors,
    registerUser
);

/**
 * Logs user in, applies brute-force rate limiting.
 *
 * WHY:
 *   - Throttles login attempts by IP (via checkRateLimit) to block brute-force attacks.
 *   - Ensures payload is valid before comparing hashed passwords.
 */
router.post(
    '/login',
    validateLoginInput,
    handleValidationErrors,
    checkRateLimit,
    loginUser
);

/**
 * Logs user out by clearing cookies.
 *
 * WHY:
 *   - Invalidates client session by removing JWT cookies. Stateless logout.
 */
router.post('/logout', logoutUser);

/**
 * Issues a new access token using a refresh token.
 *
 * WHY:
 *   - Keeps short-lived access tokens fresh without forcing user to re-login.
 *   - Ensures secure httpOnly cookie usage for refresh tokens.
 */
router.post('/refresh', refreshAccessToken);

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
