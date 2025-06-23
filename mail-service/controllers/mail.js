const { sendEmailMsg } = require('../utils/mail');
require('dotenv').config();

const sendResetPasswordLink = async (req, res) => {
    const { to, link, via } = req.body;

    if (via === 'email') {
        const subject = '🔐 Secure Password Reset Request';
        const text = `You recently requested to reset your password. To proceed, please click the following link: ${link}\n\nIf you did not request this, please ignore this message.`;
        const html = `
        <p>Hello,</p>
        <p>You recently requested to reset your account password. To continue, please click the link below:</p>
        <p><a href="${link}">Reset My Password</a></p>
        <p>If you did not request a password reset, no further action is required.</p>
        <p>— The Support Team</p>
        `;

        try {
            await sendEmailMsg(to, subject, text, html);
            return res.status(200).json({ msg: 'Message sent successfully' });
        } catch (err) {
            console.error('Error sending message via email:', err);
            return res.status(500).json({
                msg: 'Failed to send reset email',
                error: err.message,
            });
        }
    } else if (via === 'phone') {
        // will be implemented when will have money, for now no money :(
    }
};

module.exports = { sendResetPasswordLink };
