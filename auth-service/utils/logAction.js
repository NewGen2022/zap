const logger = require('./logger');

module.exports = (
    level,
    message,
    {
        req,
        action,
        userId,
        email,
        phoneNumber,
        status,
        durationMs,
        ...extra
    } = {}
) => {
    logger[level](message, {
        action,
        userId,
        email,
        phoneNumber,
        status,
        durationMs,
        requestId: req?.requestId,
        ip: req?.ip,
        userAgent: req?.headers['user-agent'],
        ...extra,
    });
};
