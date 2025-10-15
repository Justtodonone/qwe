import crypto from 'crypto';

class SimpleTOTP {
    constructor() {
        this.stepSize = 30;
        this.codeLength = 6;
    }

    generateTOTP(secret, timeOffset = 0) {
        const time = Math.floor(Date.now() / 1000 / this.stepSize) + timeOffset;
        const timeBuffer = Buffer.alloc(8);
        timeBuffer.writeBigInt64BE(BigInt(time), 0);
        
        const hmac = crypto.createHmac('sha1', secret);
        hmac.update(timeBuffer);
        const hmacResult = hmac.digest();
        
        const offset = hmacResult[hmacResult.length - 1] & 0xf;
        const code = (
            ((hmacResult[offset] & 0x7f) << 24) |
            ((hmacResult[offset + 1] & 0xff) << 16) |
            ((hmacResult[offset + 2] & 0xff) << 8) |
            (hmacResult[offset + 3] & 0xff)
        ) % Math.pow(10, this.codeLength);
        
        return code.toString().padStart(this.codeLength, '0');
    }

    verifyTOTP(secret, code) {
        // Check current time window and ±1 window (90 seconds total)
        for (let i = -1; i <= 1; i++) {
            const generatedCode = this.generateTOTP(secret, i);
            if (generatedCode === code) {
                return true;
            }
        }
        return false;
    }
}

const totpSystem = new SimpleTOTP();

// Simple in-memory storage for attempts (per instance)
const attemptStore = new Map();

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const { username, code, token } = req.body;
        
        if (!username || !code) {
            return res.status(400).json({ error: 'Username and code are required' });
        }

        if (!token) {
            return res.status(400).json({ error: 'Verification token is missing. Please request a new code.' });
        }

        // Decode the token
        let tokenData;
        try {
            const decoded = Buffer.from(token, 'base64url').toString('utf8');
            tokenData = JSON.parse(decoded);
        } catch (error) {
            return res.status(400).json({ error: 'Invalid token. Please request a new code.' });
        }

        // Verify token data
        if (tokenData.username !== username) {
            return res.status(400).json({ error: 'Token mismatch. Please request a new code.' });
        }

        // Check if expired (90 seconds with drift tolerance)
        if (Date.now() - tokenData.timestamp > 90000) {
            return res.status(400).json({ error: 'TOTP code expired. Please request a new code.' });
        }

        // Check attempts (per username in this instance)
        const attemptKey = `${username}_${tokenData.timestamp}`;
        const attempts = attemptStore.get(attemptKey) || 0;
        
        if (attempts >= 5) {
            return res.status(400).json({ error: 'Too many attempts. Please request a new code.' });
        }

        // Verify code with time drift tolerance
        const isValid = totpSystem.verifyTOTP(tokenData.secret, code);
        
        if (!isValid) {
            attemptStore.set(attemptKey, attempts + 1);
            const remaining = 5 - attempts - 1;
            return res.status(400).json({ error: `Invalid code. Attempts remaining: ${remaining}` });
        }

        // Code is valid
        res.status(200).json({
            success: true,
            message: 'Login successful!',
            username: username
        });

    } catch (error) {
        console.error('Verification error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}
