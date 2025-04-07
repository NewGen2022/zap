const prismaClient = require('../db/prismaClient');
const bcrypt = require('bcryptjs');
const { checkUserExistence } = require('../js/auth');

// Use validation middleware for the registration route
const registerUser = async (req, res) => {
    const { username, password, confirmPassword, email } = req.body;

    // Check if the email already exists (before password validation)
    const existingUser = await checkUserExistence(email, username);
    if (existingUser) {
        return res.status(400).json({ error: existingUser });
    }

    // Hash the password before saving to the database
    const hashedPassword = await bcrypt.hash(password, 10); // Use bcrypt for hashing

    // Create the new user in the database
    try {
        const newUser = await prismaClient.user.create({
            data: {
                username,
                email,
                password: hashedPassword,
            },
        });

        // Respond with the created user data (except the password)
        const { password: _, ...userResponse } = newUser; // Remove password from response
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

module.exports = { registerUser };
