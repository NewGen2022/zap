const requestIp = require('request-ip');
const loginAttempts = new Map(); // IP -> {count, lastAttempt}
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes

/**
 * Middleware: checkRateLimit
 *
 * Purpose:
 *   Prevent brute-force attacks by limiting the number of login attempts from a single IP.
 *
 * Description:
 *   This middleware checks whether the number of login attempts coming from the client's IP
 *   has exceeded a defined threshold (MAX_LOGIN_ATTEMPTS) within a given period (LOCKOUT_TIME).
 *   If the client exceeds the limit, the middleware responds with a 429 status code and an error message.
 *   Otherwise, it increments the attempt counter and allows the request to proceed.
 *
 * Parameters:
 *   @param {object} req - Express request object. Expects to contain the client's IP.
 *   @param {object} res - Express response object.
 *   @param {function} next - Express next middleware function.
 *
 * Side Effects:
 *   - The middleware updates an in-memory Map (loginAttempts) to track the number of attempts
 *     and the timestamp of the last attempt.
 *   - On exceeding the limit, it sends a response and does not call next().
 *
 * Usage:
 *   app.post('/login', checkRateLimit, loginUser);
 */
const checkRateLimit = (req, res, next) => {
    // Get client IP
    const clientIp = requestIp.getClientIp(req);
    const now = Date.now();

    // Get attempts for current IP
    const attempts = loginAttempts.get(clientIp) || {
        count: 0,
        lastAttempt: now,
    };

    // Reset counter
    if (
        attempts.count >= MAX_LOGIN_ATTEMPTS &&
        now - attempts.lastAttempt > LOCKOUT_TIME
    ) {
        loginAttempts.set(clientIp, { count: 1, lastAttempt: now });
        return next();
    }

    // Check if too many attempts
    if (attempts.count >= MAX_LOGIN_ATTEMPTS) {
        // Calculate time remaining in lockout
        const remainingTime = Math.ceil(
            (LOCKOUT_TIME - (now - attempts.lastAttempt)) / 60000
        );

        return res.status(429).json({
            msg: `Too many login attempts. Please try again in ${remainingTime} minutes.`,
        });
    }

    // Update attempts counter
    loginAttempts.set(clientIp, {
        count: attempts.count + 1,
        lastAttempt: now,
    });

    next();
};

/**
 * resetLoginAttempts
 *
 * Purpose:
 *   Resets the login attempt counter for a given IP address.
 *
 * Description:
 *   This function deletes the entry for the specified IP address from the
 *   in-memory loginAttempts Map. This is typically called upon a successful
 *   login to clear any previous failed login attempts associated with that IP.
 *
 * Parameters:
 *   @param {string} ip - The IP address whose login attempts should be cleared.
 *
 * Returns:
 *   Nothing; it simply removes the record.
 */
const resetLoginAttempts = (ip) => {
    loginAttempts.delete(ip);
};

module.exports = { checkRateLimit, resetLoginAttempts };
