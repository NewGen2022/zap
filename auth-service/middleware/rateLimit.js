const requestIp = require('request-ip');

const loginAttempts = new Map(); // Maps IP -> { count, lastAttempt }
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes

/**
 * checkRateLimit
 *
 * WHY:
 *   Protects login endpoints from brute-force attacks by rate limiting based on IP.
 *
 * DESCRIPTION:
 *   Tracks failed login attempts in-memory by IP address. If an IP exceeds
 *   MAX_LOGIN_ATTEMPTS within LOCKOUT_TIME, blocks further attempts
 *   until lockout period expires.
 *
 * SECURITY NOTE:
 *   This is in-memory; resets on server restart. For distributed systems,
 *   you'd move this to Redis or similar.
 *
 * SIDE EFFECT:
 *   Updates internal `loginAttempts` map for tracking.
 *
 * @param {object} req - Express request object
 * @param {object} res - Express response object
 * @param {function} next - Calls next middleware if under limit
 */
const checkRateLimit = (req, res, next) => {
    const clientIp = requestIp.getClientIp(req);
    const now = Date.now();

    // Get current record or initialize
    const attempts = loginAttempts.get(clientIp) || {
        count: 0,
        lastAttempt: now,
    };

    // Reset counter if lockout expired
    if (
        attempts.count >= MAX_LOGIN_ATTEMPTS &&
        now - attempts.lastAttempt > LOCKOUT_TIME
    ) {
        loginAttempts.set(clientIp, { count: 1, lastAttempt: now });
        return next();
    }

    // If too many attempts and still in lockout period, block request
    if (attempts.count >= MAX_LOGIN_ATTEMPTS) {
        const remainingTime = Math.ceil(
            (LOCKOUT_TIME - (now - attempts.lastAttempt)) / 60000
        );

        return res.status(429).json({
            msg: `Too many login attempts. Please try again in ${remainingTime} minutes.`,
        });
    }

    // Otherwise increment attempt count
    loginAttempts.set(clientIp, {
        count: attempts.count + 1,
        lastAttempt: now,
    });

    next();
};

/**
 * resetLoginAttempts
 *
 * WHY:
 *   Clears failed login attempts for an IP after successful authentication,
 *   so legit users aren't stuck waiting out lockouts.
 *
 * SIDE EFFECT:
 *   Removes IP entry from the internal attempts map.
 *
 * @param {string} ip - IP address to clear attempts for
 */
const resetLoginAttempts = (ip) => {
    loginAttempts.delete(ip);
};

module.exports = { checkRateLimit, resetLoginAttempts };
