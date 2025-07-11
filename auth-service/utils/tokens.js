const jwt = require('jsonwebtoken');
const { createHash, randomBytes } = require('crypto');

/**
 * createAccessToken
 *
 * WHY:
 *   Generates a short-lived JWT containing user ID and role for authorization checks.
 *
 * SECURITY:
 *   - Uses separate secret from refresh tokens to compartmentalize risk.
 *   - 1 hour expiry limits impact if stolen.
 *
 * @param {object} user - User object with at least { id, role }
 * @returns {string} JWT access token
 */
const createAccessToken = async (user) => {
    return jwt.sign(
        {
            userId: user.id,
            role: user.role,
        },
        process.env.JWT_ACCESS_SECRET,
        { expiresIn: '1h', algorithm: 'HS256' }
    );
};

/**
 * createRefreshToken
 *
 * WHY:
 *   Issues a longer-lived JWT for re-authentication without forcing user to log in again.
 *
 * SECURITY:
 *   - Separate secret ensures compromise doesn't break access token space.
 *   - Longer 3 day expiry, stored httpOnly cookie.
 *
 * @param {object} user - User object with at least { id, username }
 * @returns {string} JWT refresh token
 */
const createRefreshToken = async (user) => {
    return jwt.sign(
        { userId: user.id, username: user.username },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: '3d', algorithm: 'HS256' }
    );
};

/**
 * createToken
 *
 * WHY:
 *   Generates a secure random string (token) for email verification or password reset,
 *   plus a SHA-256 hash to store in DB. Keeps DB secure even if it leaks.
 *
 * DESIGN:
 *   - Plain token is sent to user (via email/SMS), hashed version stored.
 *   - Verification later hashes provided token and compares to DB.
 *
 * @returns {object} { plainToken, tokenHash }
 */
const createToken = () => {
    const plainToken = randomBytes(32).toString('hex');
    const tokenHash = createHash('sha256').update(plainToken).digest('hex');

    return { plainToken, tokenHash };
};

module.exports = { createAccessToken, createRefreshToken, createToken };
