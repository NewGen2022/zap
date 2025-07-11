/**
 * setAuthCookies
 *
 * WHY:
 *   Sets secure HTTP-only cookies for JWT tokens, preventing JavaScript access
 *   and ensuring tokens are only sent over secure channels in production.
 *
 * DESIGN NOTES:
 *   - `accessToken` always set, short-lived, for most API requests.
 *   - `refreshToken` is optional, longer-lived, only sent on specific endpoint (`/api/refresh`).
 *
 * SECURITY:
 *   - `httpOnly` ensures cookies are not accessible to JavaScript (protects against XSS).
 *   - `secure` ensures cookies only sent over HTTPS in production.
 *   - `sameSite: Strict` mitigates CSRF by blocking cross-origin sending.
 *
 * @param {object} res - Express response object.
 * @param {string} accessToken - Short-lived access JWT.
 * @param {string} [refreshToken] - Optional long-lived refresh JWT.
 */
const setAuthCookies = (res, accessToken, refreshToken) => {
    res.cookie('accessToken', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'prod',
        maxAge: 3600000, // 1 hour
        sameSite: 'Strict',
        path: '/',
    });

    if (refreshToken) {
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'prod',
            maxAge: 259200000, // 3 days
            sameSite: 'Strict',
            path: '/api/refresh', // Limits CSRF surface by scoping
        });
    }
};

/**
 * clearAuthCookies
 *
 * WHY:
 *   Explicitly clears authentication cookies on logout or when invalidating a session.
 *   Clears both access and refresh tokens to fully sign out user.
 *
 * SECURITY:
 *   Uses same options as when setting cookies to ensure proper deletion.
 *
 * @param {object} res - Express response object.
 */
const clearAuthCookies = (res) => {
    res.clearCookie('accessToken', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'prod',
        sameSite: 'Strict',
        path: '/',
    });

    res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'prod',
        sameSite: 'Strict',
        path: '/api/refresh',
    });
};

module.exports = { setAuthCookies, clearAuthCookies };
