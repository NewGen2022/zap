const prismaClient = require('../prismaClient');

/**
 * Creates a new verification token for the given user ID.
 *
 * WHY: Used to issue password reset or similar verification flows.
 * The type is hardcoded as 'PASSWORD_RESET' here for simplicity,
 * and expiration is set to 1 hour from now.
 *
 * SIDE EFFECTS:
 *   - Inserts a new row in the verificationToken table.
 *
 * GUARANTEES:
 *   - Throws if userId or hash is missing to avoid silent errors.
 */
const addToken = async (userId, hash, tokenType = 'EMAIL') => {
    if (!userId) throw new Error('No user id is provided');
    if (!hash) throw new Error('No token hash is provided');

    try {
        const token = await prismaClient.verificationToken.create({
            data: {
                userId: userId,
                tokenHash: hash,
                type: tokenType,
                expiresAt: new Date(Date.now() + 3600000), // 1 hour
            },
        });

        return token;
    } catch (err) {
        throw new Error(`Error while adding new token: ${err}`);
    }
};

/**
 * Fetches a verification token by its hashed value.
 *
 * WHY: Used during password reset to look up and validate the token.
 *
 * SECURITY NOTE:
 *   - Only selects fields required to verify and process: id, userId, expiresAt, isUsed.
 *   - Throws early if tokenHash missing to avoid invalid lookups.
 */
const getByVerificationToken = async (tokenHash) => {
    if (!tokenHash) throw new Error('No token is provided to get by');

    try {
        const tokenInfo = await prismaClient.verificationToken.findUnique({
            where: {
                tokenHash,
            },
            select: {
                id: true,
                userId: true,
                expiresAt: true,
                isUsed: true,
                type: true,
            },
        });

        return tokenInfo;
    } catch (err) {
        throw new Error(
            `Error while getting by verification token: ${err.message}`
        );
    }
};

/**
 * Marks a verification token as used by setting isUsed=true.
 *
 * WHY: Ensures the same token cannot be reused after a successful reset.
 *
 * SIDE EFFECTS:
 *   - Updates the row in the database.
 *
 * EDGE CASE:
 *   - If tokenId does not exist, Prisma will throw (which is fine).
 */
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
        console.error(err); // keep full log for debug
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
