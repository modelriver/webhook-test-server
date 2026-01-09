const express = require('express');
const path = require('path');
const { verifySignature } = require('./webhook-verifier');

const app = express();
const PORT = process.env.PORT || 3001;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

// Store received webhooks in memory
let webhooks = [];

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// API endpoint to get all received webhooks
app.get('/api/webhooks', (req, res) => {
    res.json(webhooks);
});

// API endpoint to clear webhooks
app.delete('/api/webhooks', (req, res) => {
    webhooks = [];
    res.json({ message: 'Webhooks cleared' });
});

// Webhook receive endpoint
app.post('/webhook', (req, res) => {
    const signature = req.headers['x-modelriver-signature'];
    const timestamp = req.headers['x-modelriver-timestamp'];
    const body = req.body;

    console.log('\n📥 Webhook received!');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('📊 Headers:');
    console.log(`   Signature: ${signature ? signature.substring(0, 20) + '...' : 'N/A'}`);
    console.log(`   Timestamp: ${timestamp || 'N/A'}`);

    // Verify signature if secret is set
    let signatureVerified = null;
    if (WEBHOOK_SECRET) {
        const data = body.data;
        signatureVerified = verifySignature(WEBHOOK_SECRET, timestamp, data, signature);

        if (signatureVerified === false) {
            console.log('❌ Signature verification FAILED!');
            console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
            return res.status(401).json({ error: 'Invalid signature' });
        }

        console.log('✅ Signature verification PASSED!');
    } else {
        console.log('⚠️  No WEBHOOK_SECRET set - signature not verified');
    }

    // Log webhook data
    console.log('📦 Payload:');
    console.log(`   Channel ID: ${body.channel_id || 'N/A'}`);
    console.log(`   Status: ${body.status || 'N/A'}`);
    console.log(`   Data: ${JSON.stringify(body.data, null, 2).split('\n').join('\n   ')}`);
    if (body.meta) {
        console.log(`   Meta: ${JSON.stringify(body.meta, null, 2).split('\n').join('\n   ')}`);
    }
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    // Store the webhook
    const webhook = {
        id: webhooks.length + 1,
        receivedAt: new Date().toISOString(),
        timestamp: timestamp ? parseInt(timestamp) : null,
        signatureVerified,
        channel_id: body.channel_id,
        body: body
    };

    webhooks.unshift(webhook); // Add to beginning of array

    // Keep only last 100 webhooks
    if (webhooks.length > 100) {
        webhooks = webhooks.slice(0, 100);
    }

    res.json({ success: true, message: 'Webhook received' });
});

// Serve the web UI for root path
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
    console.log('\n🚀 ModelRiver Webhook Test Server');
    console.log('================================');
    console.log(`📡 Server running on http://localhost:${PORT}`);
    console.log(`📥 Webhook endpoint: http://localhost:${PORT}/webhook`);
    console.log(`🌐 Web UI: http://localhost:${PORT}`);
    console.log(`📊 API: http://localhost:${PORT}/api/webhooks`);
    console.log('');
    if (WEBHOOK_SECRET) {
        console.log('✅ WEBHOOK_SECRET is set - signature verification enabled');
    } else {
        console.log('⚠️  WEBHOOK_SECRET not set - webhooks will not be verified');
    }
    console.log('\nWaiting for webhooks...');
});
