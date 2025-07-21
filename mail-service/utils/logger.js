const fs = require('fs');
const path = require('path');
const { createLogger, format, transports } = require('winston');
const { combine, timestamp, printf, colorize, json } = format;

const logsDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir);
}

const logFormat = printf(({ timestamp, level, message, ...meta }) => {
    const metaInfo = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : '';
    return `[${timestamp}] ${level}: ${message}${metaInfo}`;
});

const logger = createLogger({
    level: 'info',
    defaultMeta: { service: 'mail-service' },
    format: combine(timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), logFormat),
    transports: [
        // Console: colorized string
        new transports.Console({
            format: combine(colorize(), logFormat),
        }),

        // Log files: full structured JSON
        new transports.File({
            filename: path.join(logsDir, 'info.log'),
            level: 'info',
        }),
        new transports.File({
            filename: path.join(logsDir, 'error.log'),
            level: 'error',
        }),
        new transports.File({ filename: path.join(logsDir, 'combined.log') }),
    ],
    exceptionHandlers: [
        new transports.File({ filename: path.join(logsDir, 'exceptions.log') }),
    ],
});
module.exports = logger;
