const bcrypt = require('bcryptjs');
const requestIp = require('request-ip');
require('dotenv').config();
const {
    getUserByUsernameDB,
    getUserByEmailDB,
    getUserByPhoneNumberDB,
    createUser,
} = require('../db/queries/userQueries');
const { resetLoginAttempts } = require('../middleware/rateLimit');
const { createAccessToken, createRefreshToken } = require('../utils/tokens');
const { normalizePhoneNumber } = require('../utils/phoneNumber');
const { setAuthCookies, clearAuthCookies } = require('../utils/cookies');

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

module.exports = {
    registerUser,
    loginUser,
    logoutUser,
};
