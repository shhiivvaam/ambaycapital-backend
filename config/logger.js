const { createLogger, format, transports } = require('winston');
const { combine, timestamp, printf, colorize } = format;
const DailyRotateFile = require('winston-daily-rotate-file');

const customFormat = printf(({ level, message, timestamp }) => {
    return `${timestamp} [${level}]: ${message}`;
});

const logger = createLogger({
    // level: process.env.LOG_LEVEL || 'info',
    level: process.env.NODE_ENV === 'production' ? 'error' : 'debug',
    format: combine(
        timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        colorize(),
        customFormat
    ),
    transports: [
        new transports.Console(),
        new DailyRotateFile({
            filename: 'logs/%DATE%-app.log',
            datePattern: 'YYYY-MM-DD',
            zippedArchive: true,
            maxSize: '20m',
            maxFiles: '14d',
        }),
        new transports.File({ filename: 'logs/errors.log', level: 'error' }),
    ],
    exceptionHandlers: [
        new transports.File({ filename: 'logs/exceptions.log' })
    ],
    rejectionHandlers: [
        new transports.File({ filename: 'logs/rejections.log' })
    ],
});

module.exports = logger;
