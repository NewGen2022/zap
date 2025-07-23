const Redis = require('redis');
const logger = require('../utils/logger');

const redisClient = Redis.createClient({
    url: process.env.AUTH_REDIS_SERVER_URL,
});

redisClient.on('error', (err) =>
    logger.error('Redis client error', {
        action: 'redis',
        error: err.message,
        stack: err.stack,
    })
);

redisClient.on('ready', () => {
    logger.info('Redis ready', { action: 'redis' });
});

async function connectRedis() {
    await redisClient.connect();
    logger.info('Redis connected', { action: 'redis-connect' });
}

async function disconnectRedis() {
    await redisClient.quit();
    logger.info('Redis disconnected', { action: 'redis-disconnect' });
}

module.exports = { redisClient, connectRedis, disconnectRedis };
