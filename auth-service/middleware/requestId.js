const { v4: uuid } = require('uuid');

module.exports = (req, _res, next) => {
    req.requestId = uuid();
    next();
};
