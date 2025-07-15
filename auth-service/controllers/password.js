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

/**
 * Handles forgot-password flow by generating a reset token and triggering an email.
 *
 * WHAT:
 *   - Accepts email or phone, creates a reset token, and sends it to the user.
 *
 * WHY:
 *   - Allows users to securely initiate a password reset without logging in.
 *
 * SECURITY:
 *   - Does not reveal if the email/phone exists (generic response).
 *   - Token is time-limited and stored hashed in DB.
 *
 * SIDE EFFECTS:
 *   - Writes a new verification token to DB.
 *   - Sends an email (via mail microservice).
 */
const forgotPassword = async (req, res) => {
    const { email: rawEmail, phoneNumber: rawPhone } = req.body;

    // Clean input: trim + lowercase email for consistency
    const email = rawEmail?.trim().toLowerCase();
    const phoneNumber = rawPhone?.trim();

    if (!email && !phoneNumber) {
        return res.status(400).json({
            msg: 'You must provide either an email or phone number',
        });
    }

    try {
        // Attempt to find user, but intentionally respond the same whether found or not
        const user = email
            ? await getUserByEmailDB(email)
            : await getUserByPhoneNumberDB(phoneNumber);

        if (!user) {
            return res.status(200).json({
                msg: 'If an account with that identifier exists, you’ll receive a reset link shortly.',
            });
        }

        // Create reset token & store hashed version
        const { plainToken, tokenHash } = createToken();
        await addToken(user.id, tokenHash, (tokenType = 'PASSWORD_RESET'));

        if (email) {
            const resetLink = `${process.env.RESET_PASSWORD_URL_FRONT}/reset-password?token=${plainToken}`;
            const MAIL_ROUTE = `${process.env.MAIL_SERVICE_URL_BACK}/send-reset-link`;

            // Call mail microservice to send reset email
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
                throw new Error(
                    'Error getting a response from mail server. Error resetting password through email'
                );
            }
        } else if (phoneNumber) {
            // Placeholder for future SMS password resets
        }

        // Generic response regardless of user found or mail sent
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

/**
 * Handles final password reset step by consuming token and storing new password.
 *
 * WHAT:
 *   - Validates reset token, marks it used, hashes and saves new password.
 *
 * WHY:
 *   - Lets users securely update their password after proving ownership.
 *
 * SECURITY:
 *   - Checks token expiry & usage.
 *   - Marks token as used to prevent replay attacks.
 *
 * SIDE EFFECTS:
 *   - Updates password hash in DB.
 *   - Updates token record to mark it consumed.
 */
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

    // Simple local check for password confirmation mismatch
    if (newPassword !== confirmPassword) {
        console.error('Passwords do not match in reset attempt');
        return res.status(400).json({ msg: 'Passwords do not match' });
    }

    // Hash the plain token for secure DB lookup
    const tokenHash = createHash('sha256').update(token).digest('hex');

    let tokenRecord;
    let userId;
    const now = new Date();

    try {
        tokenRecord = await getByVerificationToken(tokenHash);

        // Defensive check: token must exist, not be used, and not be expired
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

    // Mark the token as used immediately so it can't be replayed
    await updateVerificationToken(tokenRecord.id);

    try {
        // Hash new password before storing
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
