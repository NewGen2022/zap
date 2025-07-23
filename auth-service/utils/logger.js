// utils/logger.js
const fs = require('fs');
const path = require('path');
const { createLogger, format, transports } = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');

const { combine, timestamp, printf, colorize, json, errors } = format;

const logsDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir);

const consoleFormat = printf(({ timestamp, level, message, ...meta }) => {
    const rest = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : '';
    return `[${timestamp}] ${level}: ${message}${rest}`;
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
    defaultMeta: { service: 'auth-service' },
    format: fileJsonFormat,
    transports: [
        new transports.Console({
            format: combine(
                colorize(),
                timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
                consoleFormat
            ),
        }),

        new DailyRotateFile({
            filename: path.join(logsDir, 'auth-info-%DATE%.log'),
            datePattern: 'YYYY-MM-DD',
            level: 'info',
            zippedArchive: true,
            maxSize: '20m',
            maxFiles: '30d',
            format: combine(onlyLevel('info'), fileJsonFormat),
        }),

        new DailyRotateFile({
            filename: path.join(logsDir, 'auth-error-%DATE%.log'),
            datePattern: 'YYYY-MM-DD',
            level: 'error',
            zippedArchive: true,
            maxSize: '20m',
            maxFiles: '30d',
            format: combine(onlyLevel('error'), fileJsonFormat),
        }),

        new DailyRotateFile({
            filename: path.join(logsDir, 'auth-combined-%DATE%.log'),
            datePattern: 'YYYY-MM-DD',
            zippedArchive: true,
            maxSize: '50m',
            maxFiles: '30d',
            format: fileJsonFormat,
        }),
    ],
    exceptionHandlers: [
        new transports.File({
            filename: path.join(logsDir, 'auth-exceptions.log'),
        }),
    ],
    rejectionHandlers: [
        new transports.File({
            filename: path.join(logsDir, 'auth-rejections.log'),
        }),
    ],
});

module.exports = logger;
