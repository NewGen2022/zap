const axios = require('axios');
const logger = require('./logger');

/**
 * sendToMail
 *
 * WHY:
 *   Delegates sending password reset or verification links to an external mail (or SMS) service.
 *   Keeps core authentication server decoupled from actual message delivery logic.
 *
 * USAGE:
 *   - Typically used to send reset links or verification links.
 *
 * SIDE EFFECT:
 *   - Makes an HTTP POST to an external service, which may fail or timeout.
 *
 * SECURITY / RELIABILITY:
 *   - Logs errors on failure but does not throw further,
 *     leaving it up to caller to handle a missing response.
 *
 * @param {string} to - Email or phone number destination.
 * @param {string} link - Reset or verification link to be sent.
 * @param {string} route - Full URL of the mail service endpoint.
 * @param {boolean} [email=true] - If false, marks the channel as 'phone'.
 *
 * @returns {Promise<object|undefined>} Returns axios response or undefined if request fails.
 */
const sendToMail = async (to, link, route, email = true, ctx = {}) => {
    const { req, action = 'send-mail' } = ctx;
    const requestId = req?.requestId;

    try {
        const response = await axios.post(
            route,
            {
                to,
                link,
                via: email ? 'email' : 'phone',
            },
            {
                timeout: 10_000, // на всяк випадок
            }
        );

        logger.info('Mail service responded', {
            action,
            requestId,
            to,
            route,
            status: response.status,
        });

        return response;
    } catch (err) {
        logger.error('Mail service call failed', {
            action,
            requestId,
            to,
            route,
            channel: email ? 'email' : 'phone',
            error: err.message,
            code: err.code,
            status: err.response?.status,
            data: err.response?.data,
            stack: err.stack,
        });

        // Повертаємо undefined, бо так задумано у твоєму коді
        return undefined;
    }
};

module.exports = {
    sendToMail,
};
