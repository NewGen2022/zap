const fs = require('fs');
const path = require('path');
const { createLogger, format, transports } = require('winston');
const { combine, timestamp, printf, colorize, json, errors } = format;

const logsDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir);

const consoleFormat = printf(({ timestamp, level, message, ...meta }) => {
    const metaStr = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : '';
    return `[${timestamp}] ${level}: ${message}${metaStr}`;
});

const fileJsonFormat = combine(
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    errors({ stack: true }),
    json()
);

const onlyLevel = (lvl) =>
    format((info) => (info.level === lvl ? info : false))();

const logger = createLogger({
    level: 'info',
    defaultMeta: { service: 'mail-service' },
    format: fileJsonFormat,
    transports: [
        new transports.Console({
            format: combine(
                colorize(),
                timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
                consoleFormat
            ),
        }),
        new transports.File({
            filename: path.join(logsDir, 'mail-error.log'),
            level: 'error',
            format: combine(onlyLevel('error'), fileJsonFormat),
        }),
        new transports.File({
            filename: path.join(logsDir, 'mail-info.log'),
            level: 'info',
            format: combine(onlyLevel('info'), fileJsonFormat),
        }),
        new transports.File({
            filename: path.join(logsDir, 'mail-combined.log'),
            format: fileJsonFormat,
        }),
    ],
    exceptionHandlers: [
        new transports.File({
            filename: path.join(logsDir, 'mail-exceptions.log'),
        }),
    ],
});

module.exports = logger;
