const prismaClient = require('../prismaClient');

const addToken = async (userId, hash) => {
    if (!userId) throw new Error('No user id is provided');
    if (!hash) throw new Error('No token hash is provided');

    try {
        const token = await prismaClient.verificationToken.create({
            data: {
                userId: userId,
                tokenHash: hash,
                type: 'PASSWORD_RESET',
                expiresAt: new Date(Date.now() + 3600000),
            },
        });

        return token;
    } catch (err) {
        throw new Error('Error while adding new token:', err);
    }
};

module.exports = { addToken };
