const { PrismaClient } = require('@prisma/client');
const logger = require('../utils/logger');

// Create a single instance of PrismaClient to interact with the database
const prismaClient = new PrismaClient();

async function connectDB() {
    await prismaClient.$connect();
    logger.info('Prisma connected to DB', { action: 'db-connect' });
}

async function disconnectDB() {
    await prismaClient.$disconnect();
    logger.info('Prisma disconnected', { action: 'db-disconnect' });
}

module.exports = { prismaClient, connectDB, disconnectDB };
