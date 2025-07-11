const bcrypt = require('bcryptjs');
const { createHash } = require('crypto');
const { sendToMail } = require('../utils/sendMsgs');
const {
    addToken,
    getByVerificationToken,
    updateVerificationToken,
} = require('../db/queries/tokenQueries');
const { createToken } = require('../utils/tokens');
const {
    getUserByEmailDB,
    getUserByPhoneNumberDB,
    updatePassword,
} = require('../db/queries/userQueries');

const forgotPassword = async (req, res) => {
    const { email: rawEmail, phoneNumber: rawPhone } = req.body;
    const email = rawEmail?.trim().toLowerCase();
    const phoneNumber = rawPhone?.trim();

    if (!email && !phoneNumber) {
        return res.status(400).json({
            msg: 'You must provide either an email or phone number',
        });
    }

    try {
        // Try to find the user by email or phone, but don't reveal if not found
        const user = email
            ? await getUserByEmailDB(email)
            : await getUserByPhoneNumberDB(phoneNumber);

        if (!user) {
            return res.status(200).json({
                msg: 'If an account with that identifier exists, you’ll receive a reset link shortly.',
            });
        }

        const { plainToken, tokenHash } = createToken();
        await addToken(user.id, tokenHash);

        const resetLink = `${process.env.RESET_PASSWORD_URL_FRONT}/reset-password?token=${plainToken}`;
        const MAIL_ROUTE = `${process.env.MAIL_SERVICE_URL_BACK}/send-reset-link`;

        if (email) {
            // Try sending the email; if fails, escalate as 500
            const response = await sendToMail(
                email,
                resetLink,
                MAIL_ROUTE,
                true
            );
            if (
                !response ||
                (response.status !== 200 && response.status !== '200')
            ) {
                throw new Error('Error getting a response from mail server');
            }
        } else if (phoneNumber) {
            // Placeholder: could integrate SMS service here later
        }

        return res.status(200).json({
            msg: 'If an account with that identifier exists, you’ll receive a reset link shortly.',
        });
    } catch (err) {
        console.error('/forgot-password error:', err);
        return res.status(500).json({
            msg: 'Unexpected auth/mail server error',
        });
    }
};

const resetPassword = async (req, res) => {
    let { token, newPassword, confirmPassword } = req.body;

    if (!token) {
        console.error('Missing token in password reset request');
        return res
            .status(400)
            .json({ msg: 'No valid verification token provided' });
    }

    newPassword = newPassword.trim();
    confirmPassword = confirmPassword.trim();

    if (newPassword !== confirmPassword) {
        console.error('Passwords do not match in reset attempt');
        return res.status(400).json({ msg: 'Passwords do not match' });
    }

    // Hash token for DB lookup
    const tokenHash = createHash('sha256').update(token).digest('hex');

    let tokenRecord;
    let userId;
    const now = new Date();

    try {
        tokenRecord = await getByVerificationToken(tokenHash);

        // Unified check for non-existent, already used, or expired token
        if (!tokenRecord || tokenRecord.isUsed || tokenRecord.expiresAt < now) {
            console.warn(
                `Invalid password reset attempt for token: ${tokenHash}`,
                {
                    found: !!tokenRecord,
                    isUsed: tokenRecord?.isUsed,
                    expiresAt: tokenRecord?.expiresAt,
                    now,
                }
            );
            return res.status(400).json({
                msg: 'Invalid or expired token. Please request a new password reset.',
            });
        }

        userId = tokenRecord.userId;
    } catch (err) {
        console.error('Error fetching user by token:', err);
        return res.status(500).json({ msg: 'Internal server error' });
    }

    // Mark token as used to prevent reuse
    await updateVerificationToken(tokenRecord.id);

    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        const updatedUser = await updatePassword(userId, hashedPassword);

        return res.status(200).json({
            msg: 'Password updated successfully',
            userId: updatedUser.id,
        });
    } catch (err) {
        console.error('Error updating password:', err);
        return res.status(500).json({
            msg: 'Could not update password. Try again later.',
        });
    }
};

module.exports = {
    forgotPassword,
    resetPassword,
};
