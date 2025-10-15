// Simple in-memory storage
const totpStore = new Map();
const sessionStore = new Map();

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const { username } = req.query;
        
        if (!username) {
            return res.status(400).json({ error: 'Username is required' });
        }

        const session = sessionStore.get(username);
        const totpData = totpStore.get(username);

        res.status(200).json({
            username,
            has_active_session: !!session,
            has_pending_totp: !!totpData,
            totp_attempts: totpData?.attempts || 0,
            session_active: session ? (Date.now() - session.loginTime < 3600000) : false
        });

    } catch (error) {
        console.error('Status error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}
