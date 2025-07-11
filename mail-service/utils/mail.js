const nodeMailer = require('nodemailer');
require('dotenv').config();

// Create reusable SMTP transporter.
// WHY:
//   - Centralizes email sending configuration.
//   - Uses environment variables for service, user, and password.
// NOTES:
//   - Supports providers like Gmail, Mailgun, etc., depending on SMTP_SERVICE.
const transporter = nodeMailer.createTransport({
    service: process.env.SMTP_SERVICE,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
});

/**
 * sendEmailMsg
 *
 * WHAT:
 *   Sends an email with both plaintext and HTML content using nodemailer.
 *
 * WHY:
 *   Allows the app to send password resets, verification emails, alerts, etc.
 *
 * SIDE EFFECTS:
 *   - Opens SMTP connection, performs authentication, sends email.
 *   - Throws on failure (caller must handle).
 *
 * @param {string} email - Recipient's email address.
 * @param {string} subject - Subject line for the email.
 * @param {string} text - Plaintext body (fallback for non-HTML clients).
 * @param {string} html - HTML body (for rich email clients).
 */
const sendEmailMsg = async (email, subject, text, html) => {
    await transporter.sendMail({
        from: process.env.SMTP_USER,
        to: email,
        subject,
        text,
        html,
    });
};

module.exports = { sendEmailMsg };
