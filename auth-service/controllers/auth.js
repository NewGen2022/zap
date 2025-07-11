const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const requestIp = require('request-ip');
require('dotenv').config();
const {
    getUserByUsernameDB,
    getUserByEmailDB,
    getUserByPhoneNumberDB,
    getUserById,
    createUser,
    updatePassword,
} = require('../db/queries/userQueries');
const { resetLoginAttempts } = require('../middleware/rateLimit');
const {
    createAccessToken,
    createRefreshToken,
    createToken,
} = require('../utils/tokens');
const { normalizePhoneNumber } = require('../utils/phoneNumber');
const { setAuthCookies, clearAuthCookies } = require('../utils/cookies');
const {
    addToken,
    getByVerificationToken,
    updateVerificationToken,
} = require('../db/queries/tokenQueries');
const { sendToMail } = require('../utils/sendMsgs');
const { createHash } = require('crypto');

const registerUser = async (req, res) => {
    const { username, password, confirmPassword, email, phoneNumber } =
        req.body;

    if (email) {
        // Defensive uniqueness check for email to avoid duplicate accounts
        const existingEmail = await getUserByEmailDB(email);
        if (existingEmail) {
            return res.status(400).json({ msg: 'Email is already taken' });
        }
    }

    if (phoneNumber) {
        // Defensive uniqueness check for phone numbers for same reason
        const existingPhoneNumber = await getUserByPhoneNumberDB(phoneNumber);
        if (existingPhoneNumber) {
            return res.status(400).json({ msg: 'Wrong phone number' });
        }
    }

    // Prevent duplicate usernames
    const existingUser = await getUserByUsernameDB(username);
    if (existingUser) {
        return res.status(400).json({ msg: 'Username is already taken' });
    }

    // Always hash passwords before storing to protect against DB leaks
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        let normalizedPhoneNumber;
        if (phoneNumber) {
            // Normalize to E.164 format so we store consistent phone data
            normalizedPhoneNumber = normalizePhoneNumber(phoneNumber);
        }

        const newUser = await createUser(
            username,
            email,
            normalizedPhoneNumber,
            hashedPassword
        );

        // Exclude password from returned user object
        const { password: _, ...userResponse } = newUser;

        return res.status(201).json({
            message: 'User registered successfully',
            user: userResponse,
        });
    } catch (err) {
        console.error('Register error:', err);
        return res.status(500).json({
            error: 'Internal Server Error during user registration',
        });
    }
};

const loginUser = async (req, res) => {
    try {
        const { loginData, password } = req.body;

        // Capture client IP and user agent for rate limiting + security logging
        const clientInfo = {
            ip: requestIp.getClientIp(req),
            userAgent: req.headers['user-agent'] || 'null',
        };

        // Decide whether user input is email or username
        const isEmail = loginData.includes('@');

        let user;
        if (isEmail) {
            user = await getUserByEmailDB(loginData);
        } else {
            user = await getUserByUsernameDB(loginData);
        }

        // Always use same generic error message to avoid leaking if user exists
        const invalidCredentialsMsg = 'Invalid credentials. Please try again.';
        if (!user) {
            return res.status(401).json({ msg: invalidCredentialsMsg });
        }

        // Validate provided password against stored bcrypt hash
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ msg: invalidCredentialsMsg });
        }

        // Successful login -> reset rate limiting attempts to prevent lockouts
        resetLoginAttempts(clientInfo.ip);

        // Security audit log for successful login attempts
        console.log(`User "${user.username}" logged in successfully`, {
            userId: user.id,
            userRole: user.role, // optional: may not exist
            timestamp: new Date().toISOString(),
            ...clientInfo,
        });

        // Issue JWT tokens + store refresh securely in HTTP-only cookie
        const accessToken = await createAccessToken(user);
        const refreshToken = await createRefreshToken(user);
        setAuthCookies(res, accessToken, refreshToken);

        // Harden response with common secure headers
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-XSS-Protection', '1; mode=block');

        return res.status(200).json({
            message: 'Login successful',
            accessToken,
        });
    } catch (err) {
        console.error('Login error:', err);
        return res.status(500).json({
            error: 'An error occurred during login',
        });
    }
};

const logoutUser = async (req, res) => {
    try {
        // Clear JWT cookies to invalidate session on client side
        clearAuthCookies(res);
        return res.status(200).json({ message: 'Logout successful' });
    } catch (err) {
        console.error('Logout error:', err);
        return res
            .status(500)
            .json({ error: 'An error occurred during logout' });
    }
};

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
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    forgotPassword,
    resetPassword,
};
