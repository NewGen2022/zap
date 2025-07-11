const prismaClient = require('../prismaClient');

/**
 * Inserts a new user into the database.
 *
 * WHY: Used for user registration. Ensures username & password provided.
 * SIDE EFFECTS: Persists a new user row.
 *
 * GUARANTEES:
 *   - Converts absent email/phoneNumber to `null` so DB stays consistent.
 */
const createUser = async (username, email, phoneNumber, password) => {
    if (!username) throw new Error('No username provided');
    if (!password) throw new Error('No password provided');

    try {
        const newUser = await prismaClient.user.create({
            data: {
                username,
                email: email || null,
                phoneNumber: phoneNumber || null,
                password,
            },
            select: {
                username: true,
                email: true,
                phoneNumber: true,
            },
        });

        return newUser;
    } catch (err) {
        throw new Error('Error while adding user: ' + err.message);
    }
};

/**
 * Finds a user by username.
 *
 * WHY: Used for login or uniqueness checks.
 * SECURITY: Always fetches hashed password for login verification.
 */
const getUserByUsernameDB = async (username) => {
    if (!username) throw new Error('No username provided');

    try {
        const user = await prismaClient.user.findUnique({
            where: {
                username,
            },
            select: {
                id: true,
                username: true,
                password: true,
            },
        });

        return user;
    } catch (err) {
        throw new Error('Error while finding user by username: ' + err.message);
    }
};

/**
 * Finds a user by email, validating format first.
 *
 * WHY: Used for login, registration checks, password reset flows.
 *
 * EDGE CASE:
 *   - If email fails regex, short-circuits and returns null
 *     instead of doing unnecessary DB call.
 */
const getUserByEmailDB = async (email) => {
    if (!email) throw new Error('No email provided');

    const isEmail = /\S+@\S+\.\S+/.test(email);
    if (!isEmail) return null;

    try {
        const user = await prismaClient.user.findUnique({
            where: {
                email,
            },
            select: {
                id: true,
                email: true,
                password: true,
            },
        });

        return user;
    } catch (err) {
        throw new Error('Error while finding user by email: ' + err.message);
    }
};

/**
 * Finds a user by phone number.
 *
 * WHY: Used for login or uniqueness checks, especially when supporting phone auth.
 */
const getUserByPhoneNumberDB = async (phoneNumber) => {
    if (!phoneNumber) throw new Error('No phone number provided');

    try {
        const user = await prismaClient.user.findUnique({
            where: { phoneNumber },
            select: {
                id: true,
                phoneNumber: true,
            },
        });

        return user;
    } catch (err) {
        throw new Error(
            'Error while finding user by phone number: ' + err.message
        );
    }
};

/**
 * Looks up a user by their unique DB ID.
 *
 * WHY: Used for JWT refresh checks or user settings retrieval.
 */
const getUserById = async (userId) => {
    if (!userId) throw new Error('No "user id" is provided');

    try {
        const user = await prismaClient.user.findUnique({
            where: { id: userId },
            select: {
                id: true,
            },
        });

        return user;
    } catch (err) {
        throw new Error('Error while getting user by id: ' + err.message);
    }
};

/**
 * Updates a user's password to a new hashed value.
 *
 * WHY: Used by password reset flows.
 *
 * SIDE EFFECTS:
 *   - Persists the new hash, overwriting old password.
 */
const updatePassword = async (userId, newPassword) => {
    if (!userId) throw new Error('No user id is provided');
    if (!newPassword) throw new Error('No new password is provided');

    try {
        const userInfo = await prismaClient.user.update({
            where: { id: userId },
            data: {
                password: newPassword,
            },
            select: {
                id: true,
                password: true,
            },
        });

        return userInfo;
    } catch (err) {
        throw new Error("Error while updating user's password: " + err.message);
    }
};

module.exports = {
    createUser,
    getUserByUsernameDB,
    getUserByEmailDB,
    getUserByPhoneNumberDB,
    getUserById,
    updatePassword,
};
