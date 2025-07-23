const jwt = require('jsonwebtoken');
const { createAccessToken } = require('../utils/tokens');
const { getUserById } = require('../db/queries/userQueries');
const logAction = require('../utils/logAction');

const refreshAccessToken = async (req, res) => {
    const start = Date.now();

    try {
        const refreshToken = req.cookies.refreshToken;
        if (!refreshToken) {
            logAction('warn', 'No refresh token cookie', {
                req,
                action: 'refresh-access-token',
                status: 401,
            });
            return res.status(401).json({ msg: 'Refresh token not found' });
        }

        // Verify refresh token integrity + decode payload
        let decoded;
        try {
            decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        } catch (err) {
            logAction('warn', 'Invalid refresh token', {
                req,
                action: 'refresh-access-token',
                error: err.message,
                stack: err.stack,
                status: 401,
            });
            return res
                .status(401)
                .json({ msg: 'Invalid or expired refresh token' });
        }

        // Ensure user from token still exists (could be deleted/banned)
        const user = await getUserById(decoded.userId);
        if (!user) {
            logAction('warn', 'User from refresh token not found', {
                req,
                action: 'refresh-access-token',
                userId: decoded.userId,
                status: 401,
            });
            return res.status(401).json({ msg: 'User not found' });
        }

        // Issue new short-lived access token and set it in cookie
        const accessToken = await createAccessToken(user);
        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'prod',
            maxAge: 3600000,
            sameSite: 'Strict',
            path: '/',
        });

        return res.status(200).json({ msg: 'Token refreshed successfully' });
    } catch (err) {
        logAction('error', 'Token refresh error', {
            req,
            action: 'refresh-access-token',
            error: err.message,
            stack: err.stack,
            status: 401,
            durationMs: Date.now() - start,
        });
        return res
            .status(401)
            .json({ msg: 'Invalid or expired refresh token' });
    }
};

module.exports = {
    refreshAccessToken,
};
