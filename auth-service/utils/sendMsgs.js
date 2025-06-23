const axios = require('axios');

const sendToMail = async (to, link, route, email = true) => {
    try {
        return await axios.post(route, {
            to,
            link,
            via: email ? 'email' : 'phone',
        });
    } catch (err) {
        console.error('Error calling mail-service:', err);
    }
};

module.exports = {
    sendToMail,
};
