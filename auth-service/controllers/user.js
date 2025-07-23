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
const logAction = require('../utils/logAction');

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
    const start = Date.now();
    const { username, password, confirmPassword, email, phoneNumber } =
        req.body;

    try {
        // Defensive uniqueness checks to avoid race conditions or duplicate accounts
        if (email) {
            const existingEmail = await getUserByEmailDB(email);
            if (existingEmail) {
                logAction('warn', 'Email already taken', {
                    req,
                    action: 'register',
                    email,
                    status: 400,
                });
                return res.status(400).json({ msg: 'Email is already taken' });
            }
        }

        if (phoneNumber) {
            const existingPhoneNumber = await getUserByPhoneNumberDB(
                phoneNumber
            );
            if (existingPhoneNumber) {
                logAction('warn', 'Phone already taken', {
                    req,
                    action: 'register',
                    phoneNumber,
                    status: 400,
                });
                return res.status(400).json({ msg: 'Wrong phone number' });
            }
        }

        const existingUser = await getUserByUsernameDB(username);
        if (existingUser) {
            logAction('warn', 'Username already taken', {
                req,
                action: 'register',
                status: 400,
            });
            return res.status(400).json({ msg: 'Username is already taken' });
        }

        // Always hash password to secure against plain text storage or DB leaks
        const hashedPassword = await bcrypt.hash(password, 10);

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
                true,
                {
                    req,
                    action: 'register-user',
                }
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

        logAction('info', 'User registered', {
            req,
            action: 'register',
            userId: userResponse.id,
            email,
            phoneNumber,
            status: 201,
            durationMs: Date.now() - start,
        });

        return res.status(201).json({
            message: 'User registered successfully',
            user: userResponse,
        });
    } catch (err) {
        logAction('error', 'Register error', {
            req,
            action: 'register',
            email,
            phoneNumber,
            error: err.message,
            stack: err.stack,
            status: 500,
            durationMs: Date.now() - start,
        });
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
    const start = Date.now();

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
            logAction('warn', 'Login: user not found / invalid creds', {
                req,
                action: 'login',
                status: 401,
                ...clientInfo,
            });
            return res.status(401).json({ msg: invalidCredentialsMsg });
        }

        // Verify supplied password against stored bcrypt hash
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            logAction('warn', 'Login: wrong password', {
                req,
                action: 'login',
                userId: user.id,
                status: 401,
                ...clientInfo,
            });
            return res.status(401).json({ msg: invalidCredentialsMsg });
        }

        // Successful login -> reset brute-force attempts for this IP
        await resetLoginAttempts(clientInfo.ip, req);

        // Security logging of successful login event
        logAction('info', 'Login success', {
            req,
            action: 'login',
            userId: user.id,
            role: user.role,
            status: 200,
            durationMs: Date.now() - start,
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
        logAction('error', 'Login error', {
            req,
            action: 'login',
            error: err.message,
            stack: err.stack,
            status: 500,
            durationMs: Date.now() - start,
        });
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

        logAction('info', 'Logout success', {
            req,
            action: 'logout',
            status: 200,
        });

        // Respond with success to inform client they are logged out
        return res.status(200).json({ message: 'Logout successful' });
    } catch (err) {
        logAction('error', 'Logout error', {
            req,
            action: 'logout',
            error: err.message,
            stack: err.stack,
            status: 500,
        });
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
    const start = Date.now();
    let { token } = req.body;

    if (!token) {
        logAction('warn', 'Missing token in verify request', {
            req,
            action: 'verify-account',
            status: 400,
        });
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
            logAction('warn', 'Invalid/expired verification token', {
                req,
                action: 'verify-account',
                tokenHash,
                found: !!tokenRecord,
                isUsed: tokenRecord?.isUsed,
                expiresAt: tokenRecord?.expiresAt,
                status: 400,
            });
            return res.status(400).json({
                msg: 'Invalid or expired token. Please request a new verification link.',
            });
        }

        userId = tokenRecord.userId;
    } catch (err) {
        logAction('error', 'DB error fetching token in verify', {
            req,
            action: 'verify-account',
            tokenHash,
            error: err.message,
            stack: err.stack,
            status: 500,
        });
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

        logAction('info', 'Account verified', {
            req,
            action: 'verify-account',
            userId,
            status: 200,
            durationMs: Date.now() - start,
        });

        return res.status(200).json({
            msg: 'Email was verified successfully',
            userId: updatedUser.id,
        });
    } catch (err) {
        logAction('error', 'Error verifying account', {
            req,
            action: 'verify-account',
            userId,
            error: err.message,
            stack: err.stack,
            status: 500,
            durationMs: Date.now() - start,
        });
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
