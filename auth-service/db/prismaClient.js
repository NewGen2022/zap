const { PrismaClient } = require('@prisma/client');
const logger = require('../utils/logger');

// Create a single instance of PrismaClient to interact with the database
const prismaClient = new PrismaClient();

const checkDatabaseConnection = async () => {
    try {
        // Attempt to connect to the database
        await prismaClient.$connect();
        logger.info('Prisma connected to DB', { action: 'db-connect' });
    } catch (err) {
        logger.error('Error connecting to DB', {
            action: 'db-connect',
            error: err.message,
            stack: err.stack,
        });
        process.exit(1);
    }
};

checkDatabaseConnection();

// Gracefully handle application shutdown when receiving SIGINT (Ctrl + C)
// Gracefully handle application shutdown when receiving SIGTERM (Docker, PM2, etc.)
const shutdown = async (signal) => {
    try {
        await prismaClient.$disconnect();
        logger.info('Prisma disconnected', { action: 'db-disconnect', signal });
    } catch (err) {
        logger.error('Error during Prisma disconnect', {
            action: 'db-disconnect',
            signal,
            error: err.message,
            stack: err.stack,
        });
    } finally {
        process.exit(0);
    }
};

process.once('SIGINT', () => shutdown('SIGINT'));
process.once('SIGTERM', () => shutdown('SIGTERM'));

// Export the PrismaClient instance to use in other parts of the application
module.exports = prismaClient;
