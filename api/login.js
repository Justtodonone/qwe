import crypto from 'crypto';

class SimpleTOTP {
    constructor() {
        this.stepSize = 30;
        this.codeLength = 6;
    }

    generateUserSecret(username) {
        const salt = process.env.TOTP_SALT || 'default-salt-change-me';
        return crypto
            .createHmac('sha256', salt)
            .update(username + Date.now().toString())
            .digest('hex')
            .slice(0, 32);
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
}

const totpSystem = new SimpleTOTP();

async function sendToDiscord(username, totpCode) {
    const webhookURL = process.env.DISCORD_WEBHOOK_URL;
    
    if (!webhookURL) {
        console.log(`[TOTP] Code for ${username}: ${totpCode} (Set DISCORD_WEBHOOK_URL to send to Discord)`);
        return true;
    }

    try {
        const payload = {
            embeds: [{
                title: "🔐 TOTP Login Code",
                description: `Login attempt for: **${username}**`,
                color: 0x0099ff,
                fields: [
                    { name: "TOTP Code", value: `\`\`\`${totpCode}\`\`\``, inline: false },
                    { name: "Expires In", value: "60 seconds", inline: true },
                    { name: "Time", value: new Date().toLocaleString(), inline: false }
                ],
                timestamp: new Date().toISOString()
            }]
        };

        const response = await fetch(webhookURL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        return response.ok;
    } catch (error) {
        console.error('Discord webhook failed:', error);
        return false;
    }
}

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
        const { username } = req.body;
        
        if (!username) {
            return res.status(400).json({ error: 'Username is required' });
        }

        // Generate unique secret and TOTP
        const secret = totpSystem.generateUserSecret(username);
        const totpCode = totpSystem.generateTOTP(secret);
        
        // Create verification token that contains the secret (URL-safe)
        const tokenData = {
            secret: secret,
            username: username,
            timestamp: Date.now()
        };
        
        // Encode the token data to pass to frontend
        const token = Buffer.from(JSON.stringify(tokenData)).toString('base64url');
        
        // Send to Discord
        await sendToDiscord(username, totpCode);

        res.status(200).json({
            success: true,
            message: 'TOTP code generated!',
            username: username,
            token: token, // Pass token to frontend for verification
            expires_in: 60
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}
