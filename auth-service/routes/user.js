const express = require('express');
const router = express.Router();

const {
    registerUser,
    loginUser,
    logoutUser,
    verifyAccount,
} = require('../controllers/user');
const {
    validateUserInput,
    handleValidationErrors,
    validateLoginInput,
} = require('../middleware/auth');
const { checkRateLimit } = require('../middleware/rateLimit');

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
 * POST /verify-account
 *
 * WHAT:
 *   - Endpoint that completes user account verification by consuming a token.
 *
 * WHY:
 *   - Confirms ownership of email (or phone in future), marks user as verified.
 *   - Keeps verification logic separate from password resets and login flows.
 */
router.post('/verify-account', verifyAccount);

module.exports = router;
