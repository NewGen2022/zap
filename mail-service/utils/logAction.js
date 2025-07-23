const logger = require('./logger');

function logAction(
    level,
    message,
    { req, action, to, status, durationMs, error, stack, ...extra } = {}
) {
    logger[level](message, {
        action,
        to,
        status,
        durationMs,
        error,
        stack,
        requestId: req?.requestId,
        ip: req?.ip,
        userAgent: req?.headers?.['user-agent'],
        ...extra,
    });
}

module.exports = logAction;
