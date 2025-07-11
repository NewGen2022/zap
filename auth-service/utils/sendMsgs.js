const axios = require('axios');

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
const sendToMail = async (to, link, route, email = true) => {
    try {
        return await axios.post(route, {
            to,
            link,
            via: email ? 'email' : 'phone',
        });
    } catch (err) {
        console.error('Error calling mail-service:', err);
    }
};

module.exports = {
    sendToMail,
};
