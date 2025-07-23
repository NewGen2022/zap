const { connectDB, disconnectDB } = require('./prisma');
const { connectRedis, disconnectRedis } = require('./redis');
const logger = require('../utils/logger');

async function connectAllClients() {
    try {
        await Promise.all([connectDB(), connectRedis()]);
        logger.info('All clients connected', { action: 'boot-clients' });
    } catch (err) {
        logger.error('Client connect failed', {
            action: 'boot-clients',
            error: err.message,
            stack: err.stack,
        });
        throw err;
    }
}

async function disconnectAllClients() {
    const results = await Promise.allSettled([
        disconnectDB(),
        disconnectRedis(),
    ]);

    results.forEach((r, i) => {
        if (r.status === 'rejected') {
            const name = i === 0 ? 'db' : 'redis';
            logger.error('Client disconnect failed', {
                action: 'shutdown-clients',
                client: name,
                error: r.reason?.message,
                stack: r.reason?.stack,
            });
        }
    });

    logger.info('All clients disconnected (settled)', {
        action: 'shutdown-clients',
    });
}

module.exports = { connectAllClients, disconnectAllClients };
