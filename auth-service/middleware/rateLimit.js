require('dotenv').config();
const requestIp = require('request-ip');
const Redis = require('redis');

const redisClient = Redis.createClient({
    url: process.env.AUTH_REDIS_SERVER_URL,
});
redisClient.on('error', (err) => console.log('Redis Client Error', err));
const connectRedis = async () => {
    try {
        await redisClient.connect();
        console.log('Connected to Redis');
    } catch (err) {
        console.error('Redis connection failed:', err);
    }
};

connectRedis();

const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60; // 15 minutes
const AUTH_REDIS_PREFIX = 'auth_srvc:rate_limit:login:';

/**
 * checkRateLimit
 *
 * WHY:
 *   Protects login endpoints from brute-force attacks by rate limiting based on IP.
 *
 * DESCRIPTION:
 *   Tracks failed login attempts in Redis using per-IP keys with TTL.
 *   If an IP exceeds MAX_LOGIN_ATTEMPTS, blocks requests for LOCKOUT_TIME.
 *
 * SECURITY NOTE:
 *   Uses Redis for cross-process/session persistence.
 *
 *
 * @param {object} req - Express request object
 * @param {object} res - Express response object
 * @param {function} next - Calls next middleware if under limit
 */
const checkRateLimit = async (req, res, next) => {
    try {
        const clientIp = requestIp.getClientIp(req);
        const clientKey = `${AUTH_REDIS_PREFIX}${clientIp}`;

        // Get current record and increment it by 1 or initialize
        let attemptCount = await redisClient.incr(clientKey);
        if (attemptCount === 1) {
            await redisClient.expire(clientKey, LOCKOUT_TIME);
        }

        // If too many attempts and still in lockout period, block request
        if (attemptCount >= MAX_LOGIN_ATTEMPTS) {
            const ttl = await redisClient.ttl(clientKey);
            const remainingTime = ttl > 0 ? Math.ceil(ttl / 60) : 0;

            return res.status(429).json({
                msg: `Too many login attempts. Please try again in ${remainingTime} minutes.`,
            });
        }

        next();
    } catch (err) {
        console.error('Rate limit middleware error:', err);
        return res.status(500).json({ msg: 'Internal rate limiter error' });
    }
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
 * @param {string} clientIp - IP address to clear attempts for
 */
const resetLoginAttempts = async (clientIp) => {
    try {
        await redisClient.del(`${AUTH_REDIS_PREFIX}${clientIp}`);
    } catch (err) {
        // Do not block a user, just a log
        console.error('Failed to reset login attempts for', clientIp, err);
    }
};

module.exports = { checkRateLimit, resetLoginAttempts };
