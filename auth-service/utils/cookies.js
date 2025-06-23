/**
 * setAuthCookies
 *
 * Sets the authentication cookies on the response.
 *
 * @param {object} res - Express response object.
 * @param {string} accessToken - The JWT access token.
 * @param {string} [refreshToken] - (Optional) The JWT refresh token.
 */
const setAuthCookies = (res, accessToken, refreshToken) => {
    // Set access token cookie (always set)
    res.cookie('accessToken', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'prod', // Ensure cookies are only sent over HTTPS in production
        maxAge: 3600000, // 1 hour in milliseconds
        sameSite: 'Strict',
        path: '/',
    });

    // Set refresh token cookie if provided
    if (refreshToken) {
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'prod',
            maxAge: 259200000, // 3 days in milliseconds
            sameSite: 'Strict',
            path: '/api/refresh', // Only send refresh token with requests to /api/refresh
        });
    }
};

/**
 * clearAuthCookies
 *
 * Clears the access token cookie and, optionally, the refresh token cookie from the response.
 *
 * @param {object} res - The Express response object.
 * @param {boolean} [clearRefresh=true] - If true, clear both access and refresh tokens.
 *                                          If false, only the access token will be cleared.
 */
const clearAuthCookies = (res) => {
    // Clear the access token cookie
    res.clearCookie('accessToken', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'prod',
        sameSite: 'Strict',
        path: '/',
    });

    // Clear the refresh token cookie, if desired
    res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'prod',
        sameSite: 'Strict',
        path: '/api/refresh',
    });
};

module.exports = { setAuthCookies, clearAuthCookies };
