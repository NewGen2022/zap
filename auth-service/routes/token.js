const express = require('express');
const router = express.Router();

const { refreshAccessToken } = require('../controllers/token');

/**
 * Issues a new access token using a refresh token.
 *
 * WHY:
 *   - Keeps short-lived access tokens fresh without forcing user to re-login.
 *   - Ensures secure httpOnly cookie usage for refresh tokens.
 */
router.post('/refresh', refreshAccessToken);

module.exports = router;
