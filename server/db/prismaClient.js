const { PrismaClient } = require('@prisma/client');

// Create a single instance of PrismaClient to interact with the database
const prismaClient = new PrismaClient();

// Gracefully handle application shutdown when receiving SIGINT (Ctrl + C)
process.on('SIGINT', async () => {
    try {
        // Disconnect from the database
        await prismaClient.$disconnect();
        console.log('Prisma Client disconnected due to SIGINT');
    } catch (error) {
        console.error('Error disconnecting Prisma Client:', error);
    } finally {
        process.exit(0); // Exit the process with success status
    }
});

// Gracefully handle application shutdown when receiving SIGTERM (Docker, PM2, etc.)
process.on('SIGTERM', async () => {
    try {
        // Disconnect from the database
        await prismaClient.$disconnect();
        console.log('Prisma Client disconnected due to SIGTERM');
    } catch (error) {
        console.error('Error disconnecting Prisma Client:', error);
    } finally {
        process.exit(0); // Exit the process with success status
    }
});

// Export the PrismaClient instance to use in other parts of the application
module.exports = prismaClient;
