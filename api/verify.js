// Simple in-memory storage
const totpStore = new Map();
const sessionStore = new Map();

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
        const { username, code } = req.body;
        
        if (!username || !code) {
            return res.status(400).json({ error: 'Username and code are required' });
        }

        // Get TOTP data
        const totpData = totpStore.get(username);
        
        if (!totpData) {
            return res.status(400).json({ error: 'No active TOTP session found or code expired' });
        }

        // Check if expired (60 seconds)
        if (Date.now() - totpData.timestamp > 60000) {
            totpStore.delete(username);
            return res.status(400).json({ error: 'TOTP code expired' });
        }

        // Check attempts
        if (totpData.attempts >= 3) {
            totpStore.delete(username);
            return res.status(400).json({ error: 'Too many attempts. Please request a new code.' });
        }

        // Verify code
        const isValid = totpSystem.verifyTOTP(totpData.secret, code);
        
        if (!isValid) {
            totpData.attempts += 1;
            totpStore.set(username, totpData);
            return res.status(400).json({ error: 'Invalid code' });
        }

        // Code is valid - create session
        sessionStore.set(username, {
            username,
            loggedIn: true,
            loginTime: Date.now()
        });

        // Clean up TOTP
        totpStore.delete(username);

        res.status(200).json({
            success: true,
            message: 'Login successful!',
            session: { username, loginTime: new Date().toISOString() }
        });

    } catch (error) {
        console.error('Verification error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}
