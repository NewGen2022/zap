const jwt = require('jsonwebtoken');
const { createHash, randomBytes } = require('crypto');

const createAccessToken = async (user) => {
    // Create the access token (short-lived)
    return jwt.sign(
        {
            userId: user.id,
            role: user.role,
        },
        process.env.JWT_ACCESS_SECRET,
        { expiresIn: '1h', algorithm: 'HS256' }
    );
};

const createRefreshToken = async (user) => {
    return jwt.sign(
        { userId: user.id, username: user.username },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: '3d', algorithm: 'HS256' }
    );
};

// creates random token (32-bit) and hashes it for credentials verification
const createToken = () => {
    const plainToken = randomBytes(32).toString('hex');
    const tokenHash = createHash('sha256').update(plainToken).digest('hex');

    return { plainToken, tokenHash };
};

module.exports = { createAccessToken, createRefreshToken, createToken };
