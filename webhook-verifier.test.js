const { verifySignature } = require('./webhook-verifier');
const crypto = require('crypto');

describe('WebhookVerifier', () => {
    const secret = 'test-secret-key-12345';
    const timestamp = '1704825600';
    const data = { status: 'success', name: 'Test User' };

    // Helper to generate signature
    function generateSignature(payload, secretKey, ts) {
        const signedPayload = `${ts}.${JSON.stringify(payload)}`;
        return crypto
            .createHmac('sha256', secretKey)
            .update(signedPayload)
            .digest('hex');
    }

    describe('verifySignature', () => {
        it('should return true for valid signatures', () => {
            const signature = generateSignature(data, secret, timestamp);
            const isValid = verifySignature(secret, timestamp, data, signature);

            expect(isValid).toBe(true);
        });

        it('should return false for tampered data', () => {
            const signature = generateSignature(data, secret, timestamp);
            const tamperedData = { ...data, name: 'Hacker' };
            const isValid = verifySignature(secret, timestamp, tamperedData, signature);

            expect(isValid).toBe(false);
        });

        it('should return false for wrong secret', () => {
            const signature = generateSignature(data, secret, timestamp);
            const isValid = verifySignature('wrong-secret', timestamp, data, signature);

            expect(isValid).toBe(false);
        });

        it('should return false for wrong timestamp', () => {
            const signature = generateSignature(data, secret, timestamp);
            const isValid = verifySignature(secret, 'wrong-timestamp', data, signature);

            expect(isValid).toBe(false);
        });

        it('should return null if parameters are missing', () => {
            const signature = generateSignature(data, secret, timestamp);

            expect(verifySignature(null, timestamp, data, signature)).toBe(null);
            expect(verifySignature(secret, null, data, signature)).toBe(null);
            expect(verifySignature(secret, timestamp, data, null)).toBe(null);
        });
    });
});
