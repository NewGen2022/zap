const bcrypt = require('bcryptjs');
const requestIp = require('request-ip');
require('dotenv').config();
const {
    getUserByUsernameDB,
    getUserByEmailDB,
    getUserByPhoneNumberDB,
    createUser,
    updateEmailVerification,
} = require('../db/queries/userQueries');
const { resetLoginAttempts } = require('../middleware/rateLimit');
const {
    createAccessToken,
    createRefreshToken,
    createToken,
} = require('../utils/tokens');
const { normalizePhoneNumber } = require('../utils/phoneNumber');
const { setAuthCookies, clearAuthCookies } = require('../utils/cookies');
const { sendToMail } = require('../utils/sendMsgs');
const {
    addToken,
    getByVerificationToken,
    updateVerificationToken,
} = require('../db/queries/tokenQueries');
const { createHash } = require('crypto');

/**
 * Registers a new user in the system.
 *
 * WHAT:
 *   Creates a user record, hashes the password, normalizes phone numbers,
 *   stores a verification token, and sends a verification email.
 *
 * WHY:
 *   Handles the entire signup flow with security checks and initial notifications.
 *
 * SECURITY:
 *   - Hashes passwords before storing.
 *   - Checks for duplicate usernames, emails, phone numbers.
 *   - Does not leak sensitive DB errors to client.
 *
 * SIDE EFFECTS:
 *   - Writes new user + token records to DB.
 *   - Sends HTTP request to mail service to trigger verification email.
 */
const registerUser = async (req, res) => {
    const { username, password, confirmPassword, email, phoneNumber } =
        req.body;

    // Defensive uniqueness checks to avoid race conditions or duplicate accounts
    if (email) {
        const existingEmail = await getUserByEmailDB(email);
        if (existingEmail) {
            return res.status(400).json({ msg: 'Email is already taken' });
        }
    }

    if (phoneNumber) {
        const existingPhoneNumber = await getUserByPhoneNumberDB(phoneNumber);
        if (existingPhoneNumber) {
            return res.status(400).json({ msg: 'Wrong phone number' });
        }
    }

    const existingUser = await getUserByUsernameDB(username);
    if (existingUser) {
        return res.status(400).json({ msg: 'Username is already taken' });
    }

    // Always hash password to secure against plain text storage or DB leaks
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        let normalizedPhoneNumber;
        if (phoneNumber) {
            // Convert to E.164 format so all numbers in DB are consistent
            normalizedPhoneNumber = normalizePhoneNumber(phoneNumber);
        }

        // Generate verification token for email validation flow
        const { plainToken, tokenHash } = createToken();

        // Actually create the user in the database
        const newUser = await createUser(
            username,
            email,
            normalizedPhoneNumber,
            hashedPassword
        );

        // Use destructuring to exclude the password from what we send back
        const { password: _, ...userResponse } = newUser;

        // Store the verification token in DB for later confirmation
        await addToken(userResponse.id, tokenHash, 'EMAIL');

        // If user signed up with email, send verification link
        if (email) {
            const resetLink = `${process.env.RESET_PASSWORD_URL_FRONT}/reset-password?token=${plainToken}`;
            const MAIL_ROUTE = `${process.env.MAIL_SERVICE_URL_BACK}/send-verification-link`;

            // Make HTTP request to mail microservice
            const response = await sendToMail(
                email,
                resetLink,
                MAIL_ROUTE,
                true
            );
            // Defensive: handle case where mail service is down
            if (
                !response ||
                (response.status !== 200 && response.status !== '200')
            ) {
                throw new Error(
                    'Error getting a response from mail server. Error during email verification through email'
                );
            }
        }

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

/**
 * Logs a user in by verifying credentials, issuing tokens, and setting cookies.
 *
 * WHAT:
 *   Checks login data, validates password, resets rate limits, sets JWT cookies.
 *
 * WHY:
 *   Provides secure authentication and session management.
 *
 * SECURITY:
 *   - Uses generic errors to avoid leaking if user exists.
 *   - Logs IP and user agent for auditing.
 *
 * SIDE EFFECTS:
 *   - Resets IP rate limit count.
 *   - Writes secure cookies to client.
 */
const loginUser = async (req, res) => {
    try {
        const { loginData, password } = req.body;

        // Capture IP + user agent for rate limiting and audit logging
        const clientInfo = {
            ip: requestIp.getClientIp(req),
            userAgent: req.headers['user-agent'] || 'null',
        };

        // Determine if user used email or username
        const isEmail = loginData.includes('@');

        let user;
        if (isEmail) {
            user = await getUserByEmailDB(loginData);
        } else {
            user = await getUserByUsernameDB(loginData);
        }

        // Always use generic message to avoid revealing if user exists or not
        const invalidCredentialsMsg = 'Invalid credentials. Please try again.';
        if (!user) {
            return res.status(401).json({ msg: invalidCredentialsMsg });
        }

        // Verify supplied password against stored bcrypt hash
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ msg: invalidCredentialsMsg });
        }

        // Successful login -> reset brute-force attempts for this IP
        resetLoginAttempts(clientInfo.ip);

        // Security logging of successful login event
        console.log(`User "${user.username}" logged in successfully`, {
            userId: user.id,
            userRole: user.role,
            timestamp: new Date().toISOString(),
            ...clientInfo,
        });

        // Generate JWTs for session management
        const accessToken = await createAccessToken(user);
        const refreshToken = await createRefreshToken(user);
        setAuthCookies(res, accessToken, refreshToken);

        // Harden headers against common web attacks
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

/**
 * Logs user out by clearing authentication cookies.
 *
 * WHAT:
 *   - Removes the access and refresh JWT cookies from the client.
 *
 * WHY:
 *   - Implements stateless logout: invalidates session by deleting client tokens.
 *
 * SIDE EFFECTS:
 *   - Client will have to re-login; cookies are deleted immediately.
 */
const logoutUser = async (req, res) => {
    try {
        // Clear JWT cookies to invalidate session on client side
        clearAuthCookies(res);

        // Respond with success to inform client they are logged out
        return res.status(200).json({ message: 'Logout successful' });
    } catch (err) {
        console.error('Logout error:', err);
        return res
            .status(500)
            .json({ error: 'An error occurred during logout' });
    }
};

/**
 * Verifies a user account using a token (email or phone).
 *
 * WHAT:
 *   - Confirms a user-provided token, sets their email or phone as verified.
 *
 * WHY:
 *   - Part of signup flows to prove ownership of contact info.
 *
 * SECURITY:
 *   - Marks tokens as used to prevent reuse.
 *   - Responds generically to avoid leaking internal errors.
 *
 * SIDE EFFECTS:
 *   - Updates user verification status in DB.
 *   - Updates token record to prevent it being reused.
 */
const verifyAccount = async (req, res) => {
    let { token } = req.body;

    if (!token) {
        console.error('Missing token in account verification request');
        return res
            .status(400)
            .json({ msg: 'No valid verification token provided' });
    }

    // Hash token for DB lookup; avoids storing plain tokens in DB
    const tokenHash = createHash('sha256').update(token).digest('hex');

    let tokenRecord;
    let userId;
    const now = new Date();

    try {
        tokenRecord = await getByVerificationToken(tokenHash);

        // Check if token exists and hasn't been used already
        if (!tokenRecord || tokenRecord.isUsed || tokenRecord.expiresAt < now) {
            console.warn(
                `Invalid account verification attempt for token: ${tokenHash}`,
                {
                    found: !!tokenRecord,
                    isUsed: tokenRecord?.isUsed,
                    expiresAt: tokenRecord?.expiresAt,
                }
            );
            return res.status(400).json({
                msg: 'Invalid or expired token. Please request a new verification link.',
            });
        }

        userId = tokenRecord.userId;
    } catch (err) {
        console.error('Error fetching user by token:', err);
        return res.status(500).json({ msg: 'Internal server error' });
    }

    // Mark this token as used so it can't be reused for verification
    await updateVerificationToken(tokenRecord.id);

    try {
        let updatedUser;

        // Update specific verification type (currently only email implemented)
        if (tokenRecord.type === 'EMAIL') {
            updatedUser = await updateEmailVerification(userId);
        } else if (tokenRecord.type === 'PHONE') {
            // Placeholder for future SMS verification implementation
        }

        return res.status(200).json({
            msg: 'Email was verified successfully',
            userId: updatedUser.id,
        });
    } catch (err) {
        console.error('Error verifying email:', err);
        return res.status(500).json({
            msg: 'Could not verify email. Try again later.',
        });
    }
};

module.exports = {
    registerUser,
    loginUser,
    logoutUser,
    verifyAccount,
};
