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
        throw new Error(`Error while adding new token: ${err}`);
    }
};

const getByVerificationToken = async (tokenHash) => {
    if (!tokenHash) throw new Error('No token is provided to get by');

    try {
        const userId = await prismaClient.verificationToken.findUnique({
            where: {
                tokenHash,
            },
            select: {
                id: true,
                userId: true,
                expiresAt: true,
                isUsed: true,
            },
        });

        return userId;
    } catch (err) {
        throw new Error(
            `Error while getting by verification token: ${err.message}`
        );
    }
};

// set it as USED
const updateVerificationToken = async (tokenId) => {
    if (!tokenId) throw new Error('No token id is provided');

    try {
        await prismaClient.verificationToken.update({
            where: {
                id: tokenId,
            },
            data: { isUsed: true },
        });
    } catch (err) {
        console.error(err);
        throw new Error(
            `Error while updating verification token: ${err.message}`
        );
    }
};

module.exports = {
    addToken,
    getByVerificationToken,
    updateVerificationToken,
};
