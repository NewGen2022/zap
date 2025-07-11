const jwt = require('jsonwebtoken');
const { createAccessToken } = require('../utils/tokens');
const { getUserById } = require('../db/queries/userQueries');

const refreshAccessToken = async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;
        if (!refreshToken) {
            return res.status(401).json({ msg: 'Refresh token not found' });
        }

        // Verify refresh token integrity + decode payload
        const decoded = jwt.verify(
            refreshToken,
            process.env.JWT_REFRESH_SECRET
        );

        // Ensure user from token still exists (could be deleted/banned)
        const user = await getUserById(decoded.userId);
        if (!user) {
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
        console.error('Token refresh error:', err);
        return res
            .status(401)
            .json({ msg: 'Invalid or expired refresh token' });
    }
};

module.exports = {
    refreshAccessToken,
};
