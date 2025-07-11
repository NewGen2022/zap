const { parsePhoneNumberFromString } = require('libphonenumber-js');

/**
 * normalizePhoneNumber
 *
 * WHY:
 *   Converts phone numbers into E.164 international format (e.g. +1234567890).
 *   This ensures consistent storage in the database and avoids duplicate
 *   entries with local formats.
 *
 * SECURITY & DATA CONSISTENCY:
 *   - Always throws if the phone number is invalid so DB only sees clean data.
 *
 * EXAMPLE:
 *   "202-555-0191" -> "+12025550191"
 *
 * @param {string} phoneNumber - Raw user-provided phone number.
 * @returns {string} Normalized E.164 phone number.
 * @throws {Error} If the phone number is not valid.
 */
function normalizePhoneNumber(phoneNumber) {
    const parsed = parsePhoneNumberFromString(phoneNumber);
    if (!parsed || !parsed.isValid()) {
        throw new Error('Invalid phone number');
    }
    return parsed.number; // always returns +XXXXXXXXXX format
}

/**
 * checkPhoneNumber
 *
 * Placeholder for future usage.
 * Typically you'd use this to simply return true/false
 * instead of throwing, useful for conditional checks or form UIs.
 */
function checkPhoneNumber() {
    // TODO: Implement validation checker that doesn't throw, e.g. returns true/false
}

module.exports = { normalizePhoneNumber, checkPhoneNumber };
