const { parsePhoneNumberFromString } = require('libphonenumber-js');

function normalizePhoneNumber(phoneNumber) {
    const parsed = parsePhoneNumberFromString(phoneNumber);
    if (!parsed || !parsed.isValid()) {
        throw new Error('Invalid phone number');
    }
    return parsed.number;
}

module.exports = { normalizePhoneNumber };
