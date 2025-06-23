const prismaClient = require('../prismaClient');

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
            },
        });

        return user;
    } catch (err) {
        throw new Error('Error while finding user by username: ' + err.message);
    }
};

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
            },
        });

        return user;
    } catch (err) {
        throw new Error('Error while finding user by email: ' + err.message);
    }
};

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

module.exports = {
    createUser,
    getUserByUsernameDB,
    getUserByEmailDB,
    getUserByPhoneNumberDB,
    getUserById,
};
