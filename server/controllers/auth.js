const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const requestIp = require('request-ip');
require('dotenv').config();
const {
    getUserByUsernameDB,
    getUserByEmailDB,
    getUserById,
    createUser,
} = require('../db/queries/userQueries');
const { resetLoginAttempts } = require('../middleware/auth');
const { createAccessToken, createRefreshToken } = require('../utils/tokens');

const registerUser = async (req, res) => {
    const { username, password, confirmPassword, email } = req.body;

    // Check if the email already exists
    const existingEmail = await getUserByEmailDB(email);
    if (existingEmail) {
        return res.status(400).json({ msg: 'Email is already taken' });
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
        const newUser = await createUser(username, email, hashedPassword);

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

        const clientInfo = {
            ip: requestIp.getClientIp(req),
            userAgent: req.headers['user-agent'] || 'null',
        };

        // If login successful, reset rate limit counter
        resetLoginAttempts(clientInfo.ip);

        // Log successful login for security monitoring
        console.log(`User "${user.username}" logged in successfully`, {
            userId: user.id,
            timestamp: new Date().toISOString(),
            ...clientInfo,
        });

        // Create the access token (short-lived)
        const accessToken = createAccessToken(user);
        // Store token in httpOnly cookies
        res.cookie('access_token', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'prod',
            maxAge: 3600000, // 1 hour
            sameSite: 'Strict',
            path: '/',
        });

        // Create the refresh token (long-lived)
        const refreshToken = createRefreshToken(user);
        // Store token in httpOnly cookies
        res.cookie('refresh_token', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'prod',
            maxAge: 259200000, // 3 days
            sameSite: 'Strict',
            path: '/api/refresh',
        });

        // Set security headers
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-XSS-Protection', '1; mode=block');

        res.status(200).json({
            message: 'Login successful',
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({
            error: 'An error occurred during login',
        });
    }
};

const logoutUser = async (req, res) => {
    try {
        res.clearCookie('access_token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'prod',
            sameSite: 'Strict',
            path: '/',
        });

        res.clearCookie('refresh_token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'prod',
            sameSite: 'Strict',
            path: '/api/refresh',
        });

        res.status(200).json({ message: 'Logout successful' });
    } catch (err) {
        console.error('Logout error:', err);
        res.status(500).json({ error: 'An error occurred during logout' });
    }
};

const refreshAccessToken = async (req, res) => {
    try {
        const refreshToken = req.cookies.refresh_token;
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
        const accessToken = createAccessToken(user);
        // Store token in httpOnly cookies
        res.cookie('access_token', accessToken, {
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

module.exports = { registerUser, loginUser, logoutUser, refreshAccessToken };
