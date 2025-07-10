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
        // Check if the email already exists
        const existingEmail = await getUserByEmailDB(email);
        if (existingEmail) {
            return res.status(400).json({ msg: 'Email is already taken' });
        }
    }

    if (phoneNumber) {
        // Check if the phone number already exists
        const existingPhoneNumber = await getUserByPhoneNumberDB(phoneNumber);
        if (existingPhoneNumber) {
            return res.status(400).json({ msg: 'Wrong phone number' });
        }
    }

    // Check if the username already exists
    const existingUser = await getUserByUsernameDB(username);
    if (existingUser) {
        return res.status(400).json({ msg: 'Username is already taken' });
    }

    // Hash the password before saving to the database
    const hashedPassword = await bcrypt.hash(password, 10); // Use bcrypt for hashing

    // Create the new user in the database
    try {
        let normalizedPhoneNumber = undefined;
        if (phoneNumber) {
            // Normalize phone number to E.164 format
            normalizedPhoneNumber = normalizePhoneNumber(phoneNumber);
        }

        const newUser = await createUser(
            username,
            email,
            normalizedPhoneNumber,
            hashedPassword
        );

        // Respond with the created user data (except the password)
        const { password: _, ...userResponse } = newUser;
        res.status(201).json({
            message: 'User registered successfully',
            user: userResponse,
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({
            error: 'Internal Server Error during user registration',
        });
    }
};

const loginUser = async (req, res) => {
    try {
        // loginData is - username or email
        const { loginData, password } = req.body;

        const clientInfo = {
            ip: requestIp.getClientIp(req),
            userAgent: req.headers['user-agent'] || 'null',
        };

        const isEmail = loginData.includes('@');

        let user;
        if (isEmail) {
            user = await getUserByEmailDB(loginData);
        } else {
            user = await getUserByUsernameDB(loginData);
        }

        const invalidCredentialsMsg = 'Invalid credentials. Please try again.';
        if (!user) {
            return res.status(401).json({
                msg: invalidCredentialsMsg,
            });
        }

        // Compare the password with the hashed password stored in the database
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({
                msg: invalidCredentialsMsg,
            });
        }

        // If login successful, reset rate limit counter
        resetLoginAttempts(clientInfo.ip);

        // Log successful login for security monitoring
        console.log(`User "${user.username}" logged in successfully`, {
            userId: user.id,
            userRole: user.role,
            timestamp: new Date().toISOString(),
            ...clientInfo,
        });

        // Create the access token (short-lived)
        const accessToken = await createAccessToken(user);
        // Create the refresh token (long-lived)
        const refreshToken = await createRefreshToken(user);
        setAuthCookies(res, accessToken, refreshToken);

        // Set security headers
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-XSS-Protection', '1; mode=block');

        return res.status(200).json({
            message: 'Login successful',
            accessToken: accessToken,
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
        clearAuthCookies(res);
        res.status(200).json({ message: 'Logout successful' });
    } catch (err) {
        console.error('Logout error:', err);
        res.status(500).json({ error: 'An error occurred during logout' });
    }
};

const refreshAccessToken = async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;
        if (!refreshToken) {
            return res.status(401).json({ msg: 'Refresh token not found' });
        }

        // Verify refresh token
        const decoded = jwt.verify(
            refreshToken,
            process.env.JWT_REFRESH_SECRET
        );

        // Get user from database
        const user = await getUserById(decoded.userId);
        if (!user) {
            return res.status(401).json({ msg: 'User not found' });
        }

        // Create the access token (short-lived)
        const accessToken = await createAccessToken(user);
        // Store token in httpOnly cookies
        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'prod',
            maxAge: 3600000, // 1 hour
            sameSite: 'Strict',
            path: '/',
        });

        res.status(200).json({ msg: 'Token refreshed successfully' });
    } catch (err) {
        console.error('Token refresh error:', err);
        res.status(401).json({ msg: 'Invalid or expired refresh token' });
    }
};

const forgotPassword = async (req, res) => {
    const { email: rawEmail, phoneNumber: rawPhone } = req.body;

    const email = rawEmail?.trim().toLowerCase();
    const phoneNumber = rawPhone?.trim();

    if (!email && !phoneNumber) {
        return res
            .status(400)
            .json({ msg: 'You must provide either an email or phone number' });
    }

    try {
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

        const resetLink =
            process.env.RESET_PASSWORD_URL_FRONT +
            '/reset-password?token=' +
            plainToken;
        const MAIL_ROUTE = `${process.env.MAIL_SERVICE_URL_BACK}/send-reset-link`;

        // need to return link to email/phone number with token
        if (email) {
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
            // will be implemented when will have money, for now no money :(
        }

        res.status(200).json({
            msg: 'If an account with that identifier exists, you’ll receive a reset link shortly.',
        });
    } catch (err) {
        console.error('/forgot-password error:', err);
        return res
            .status(500)
            .json({ msg: 'Unexpected auth/mail server error' });
    }
};

const resetPassword = async (req, res) => {
    let { token, newPassword, confirmPassword } = req.body;

    if (!token) {
        console.error('No valid token for password resetting is provided');
        return res
            .status(400)
            .json({ msg: 'No valid verification token provided' });
    }

    newPassword = newPassword.trim();
    confirmPassword = confirmPassword.trim();

    if (newPassword !== confirmPassword) {
        console.error('Passwords do not match');
        return res.status(400).json({ msg: 'Passwords do not match' });
    }

    const tokenHash = createHash('sha256').update(token).digest('hex');

    let tokenRecord;
    let userId;
    const now = new Date();

    try {
        tokenRecord = await getByVerificationToken(tokenHash);
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
        return res
            .status(500)
            .json({ msg: 'Could not update password. Try again later.' });
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
