import crypto from 'crypto';

class SimpleTOTP {
    constructor() {
        this.stepSize = 30;
        this.codeLength = 6;
    }

    generateTOTP(secret) {
        const time = Math.floor(Date.now() / 1000 / this.stepSize);
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
        const generatedCode = this.generateTOTP(secret);
        return generatedCode === code;
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

        // Check if expired (60 seconds)
        if (Date.now() - tokenData.timestamp > 60000) {
            return res.status(400).json({ error: 'TOTP code expired. Please request a new code.' });
        }

        // Check attempts (per username in this instance)
        const attemptKey = `${username}_${tokenData.timestamp}`;
        const attempts = attemptStore.get(attemptKey) || 0;
        
        if (attempts >= 3) {
            return res.status(400).json({ error: 'Too many attempts. Please request a new code.' });
        }

        // Verify code
        const isValid = totpSystem.verifyTOTP(tokenData.secret, code);
        
        if (!isValid) {
            attemptStore.set(attemptKey, attempts + 1);
            return res.status(400).json({ error: 'Invalid code. Attempts remaining: ' + (3 - attempts - 1) });
        }

        // Code is valid - create session
        const sessionData = {
            username,
            loggedIn: true,
            loginTime: Date.now()
        };

        // Clean up attempts
        attemptStore.delete(attemptKey);

        res.status(200).json({
            success: true,
            message: 'Login successful!',
            session: sessionData
        });

    } catch (error) {
        console.error('Verification error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}
