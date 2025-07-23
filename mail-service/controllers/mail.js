const { sendEmailMsg } = require('../utils/mail');
const logAction = require('../utils/logAction');

/**
 * sendResetPasswordLink
 *
 * WHAT:
 *   Handles HTTP request to send a password reset email to the user.
 *
 * WHY:
 *   Keeps email generation and transport logic separate — controller builds the message,
 *   delegates actual SMTP sending to the mail utility.
 *
 * SECURITY / PRIVACY:
 *   - Email content avoids exposing internal data (no usernames, IPs, or direct token hashes).
 *   - Generic language instructs ignoring the email if not expected, to prevent confusion or phishing misuse.
 *
 * SIDE EFFECTS:
 *   - Sends an email using configured SMTP (via sendEmailMsg).
 *   - Logs errors server-side but responds generically to avoid revealing internals.
 *
 * DESIGN:
 *   - Currently only handles 'email' channel; structured to add SMS later under the same endpoint.
 *
 * @param {object} req - Express request object, expects body with { to, link, via }
 * @param {object} res - Express response object
 */
const sendResetPasswordLink = async (req, res) => {
    const start = Date.now();
    const { to, link, via } = req.body;

    if (via === 'email') {
        const subject = '🔐 Password Reset';

        const text = `Hello,

We received a request to reset your account password. You can securely reset it by clicking the link below:

${link}

If you did not request a password reset, please ignore this email — your account will remain secure.

Thank you,
The Support Team`;

        const html = `
            <div style="
                background-color: #f9f9f9;
                padding: 40px;
                font-family: 'Jost', sans-serif, Arial;
                color: #333;
                line-height: 1.8;
                font-size: 16px;
            ">
                <div style="max-width: 600px; margin: auto; background: white; padding: 30px; border-radius: 8px;">
                    <div style="text-align: center; margin-bottom: 30px;">
                        <img src="https://yourdomain.com/logo.png" alt="Your Brand Logo" style="height: 50px;">
                    </div>
                    <p>Hello,</p>
                    <p>We received a request to reset your account password. You can securely reset it by clicking the button below:</p>
                    <p style="text-align: center; margin: 30px;">
                        <a href="${link}" style="
                            background-color: #007BFF;
                            color: white;
                            padding: 10px 25px;
                            text-decoration: none;
                            border-radius: 5px;
                            display: inline-block;
                            font-size: 16px;
                        ">
                            Reset My Password
                        </a>
                    </p>
                    <p>If you did not request a password reset, please ignore this email — your account remains secure.</p>
                    <p style="margin-top: 40px;">Thank you,<br/>The Support Team</p>
                </div>
            </div>
        `;

        try {
            await sendEmailMsg(to, subject, text, html);

            logAction('info', 'Reset email sent', {
                req,
                action: 'send-reset-link',
                to,
                status: 200,
                durationMs: Date.now() - start,
            });

            return res.status(200).json({ msg: 'Message sent successfully' });
        } catch (err) {
            logAction('error', 'Error sending reset email', {
                req,
                action: 'send-reset-link',
                to,
                status: 500,
                error: err.message,
                stack: err.stack,
                durationMs: Date.now() - start,
            });

            return res.status(500).json({
                msg: 'Failed to send reset email',
                error: err.message,
            });
        }
    } else if (via === 'phone') {
        // TODO: implement SMS reset message in the future
    } else {
        logAction('warn', 'Unsupported channel for reset', {
            req,
            action: 'send-reset-link',
            to,
            status: 400,
            channel: via,
        });
        return res.status(400).json({ msg: 'Unsupported channel' });
    }
};

/**
 * sendVerificationLink
 *
 * WHAT:
 *   Handles HTTP request to send an email/phone verification link to the user.
 *
 * WHY:
 *   Keeps email message generation separate from SMTP sending logic.
 *   Makes it easy to reuse / swap transport (Mailgun, SES, etc).
 *
 * SECURITY / PRIVACY:
 *   - Message is generic, does not expose sensitive data.
 *   - Encourages ignoring if not requested to reduce phishing confusion.
 *
 * SIDE EFFECTS:
 *   - Sends an email via SMTP (sendEmailMsg).
 *   - Logs server-side errors but responds generically to client.
 *
 * DESIGN:
 *   - Currently only handles 'email'; structured to allow adding SMS later.
 *
 * @param {object} req - Express request, expects body with { to, link, via }
 * @param {object} res - Express response
 */
const sendVerificationLink = async (req, res) => {
    const { to, link, via } = req.body;

    if (via === 'email') {
        const subject = '✅ Verify Your Email Address';

        const text = `Hello,

Thank you for joining us. Please verify your email address by clicking the link below:

${link}

If you did not sign up, please ignore this message.

Thank you,
The Support Team`;

        const html = `
            <div style="
                background-color: #f9f9f9;
                padding: 40px;
                font-family: 'Jost', sans-serif, Arial;
                color: #333;
                line-height: 1.8;
                font-size: 16px;
            ">
                <div style="max-width: 600px; margin: auto; background: white; padding: 30px; border-radius: 8px;">
                    <div style="text-align: center; margin-bottom: 30px;">
                        <img src="https://yourdomain.com/logo.png" alt="Your Brand Logo" style="height: 50px;">
                    </div>
                    <p>Hello,</p>
                    <p>Thank you for joining account. Please confirm your email address by clicking the button below:</p>
                    <p style="text-align: center; margin: 30px;">
                        <a href="${link}" style="
                            background-color: #007BFF;
                            color: white;
                            padding: 10px 25px;
                            text-decoration: none;
                            border-radius: 5px;
                            display: inline-block;
                            font-size: 16px;
                        ">
                            Verify My Email
                        </a>
                    </p>
                    <p>If you did not create this account, please ignore this email.</p>
                    <p style="margin-top: 40px;">Thank you,<br/>The Support Team</p>
                </div>
            </div>
        `;

        try {
            await sendEmailMsg(to, subject, text, html);

            logAction('info', 'Verification email sent', {
                req,
                action: 'send-verification-link',
                to,
                status: 200,
                durationMs: Date.now() - start,
            });

            return res
                .status(200)
                .json({ msg: 'Verification email sent successfully' });
        } catch (err) {
            logAction('error', 'Error sending verification email', {
                req,
                action: 'send-verification-link',
                to,
                status: 500,
                error: err.message,
                stack: err.stack,
                durationMs: Date.now() - start,
            });

            return res.status(500).json({
                msg: 'Failed to send verification email',
                error: err.message,
            });
        }
    } else if (via === 'phone') {
        // TODO: implement SMS verification message in the future
    } else {
        logAction('warn', 'Unsupported channel for verification', {
            req,
            action: 'send-verification-link',
            to,
            status: 400,
            channel: via,
        });
        return res.status(400).json({ msg: 'Unsupported channel' });
    }
};

module.exports = { sendResetPasswordLink, sendVerificationLink };
