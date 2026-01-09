const crypto = require('crypto');

/**
 * Verify ModelRiver webhook signature
 * @param {string} secret - The webhook secret
 * @param {string} timestamp - The timestamp from X-ModelRiver-Timestamp header
 * @param {Object} data - The data field from the request body
 * @param {string} signature - The signature from X-ModelRiver-Signature header
 * @returns {boolean} - Whether the signature is valid
 */
function verifySignature(secret, timestamp, data, signature) {
    if (!secret || !timestamp || !signature) {
        return null; // Cannot verify without all components
    }

    try {
        // Create the signed payload: timestamp.data_json
        const signedPayload = `${timestamp}.${JSON.stringify(data)}`;

        // Generate expected signature
        const expectedSignature = crypto
            .createHmac('sha256', secret)
            .update(signedPayload)
            .digest('hex');

        // Constant-time comparison to prevent timing attacks
        return crypto.timingSafeEqual(
            Buffer.from(signature),
            Buffer.from(expectedSignature)
        );
    } catch (error) {
        console.error('Signature verification error:', error.message);
        return false;
    }
}

module.exports = { verifySignature };
