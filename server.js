const express = require('express');
const { verifyWebhookSignature } = require('./webhook-verifier');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// CORS headers (if needed)
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, X-ModelRiver-Signature, X-ModelRiver-Timestamp, X-ModelRiver-Webhook-Id');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// In-memory storage for received webhooks
const receivedWebhooks = [];

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/webhooks', (req, res) => {
  res.json(receivedWebhooks);
});

app.delete('/api/webhooks', (req, res) => {
  receivedWebhooks.length = 0; // Clear the array
  res.json({ message: 'Webhook history cleared' });
});

app.post('/webhook', (req, res) => {
  const signature = req.headers['x-modelriver-signature'];
  const timestamp = req.headers['x-modelriver-timestamp'];
  const webhookId = req.headers['x-modelriver-webhook-id'];
  const payload = req.body;

  // Validate required headers
  if (!signature || !timestamp) {
    console.warn(`[${new Date().toISOString()}] ⚠️ Missing signature headers for webhook ID: ${webhookId}`);
    return res.status(401).json({ 
      error: 'Missing required headers: X-ModelRiver-Signature and X-ModelRiver-Timestamp' 
    });
  }

  // Validate payload structure
  if (!payload || !payload.data) {
    console.warn(`[${new Date().toISOString()}] ⚠️ Invalid payload structure for webhook ID: ${webhookId}`);
    return res.status(400).json({ 
      error: 'Invalid payload: missing data field' 
    });
  }

  const webhookSecret = process.env.WEBHOOK_SECRET;
  // #region agent log
  fetch('http://127.0.0.1:7242/ingest/d073a867-51c1-42c1-8fd7-7f4b7895ed61',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'server.js:62',message:'WEBHOOK_SECRET env check',data:{webhookSecret:webhookSecret?`${webhookSecret.substring(0,8)}...`:'undefined',hasSecret:!!webhookSecret,secretLength:webhookSecret?.length},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'B'})}).catch(()=>{});
  // #endregion
  let signatureVerified = false;

  if (webhookSecret) {
    // Extract the `data` field for signature verification
    // The signature is generated from payload.data, not the full payload
    // #region agent log
    fetch('http://127.0.0.1:7242/ingest/d073a867-51c1-42c1-8fd7-7f4b7895ed61',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'server.js:68',message:'Before verifyWebhookSignature call',data:{signature:signature?.substring(0,16)+'...',timestamp,hasDataPayload:!!payload.data,dataPayloadKeys:payload.data?Object.keys(payload.data):null},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'C'})}).catch(()=>{});
    // #endregion
    signatureVerified = verifyWebhookSignature(
      signature, 
      timestamp, 
      payload.data,  // Use payload.data, not payload
      webhookSecret
    );
    // #region agent log
    fetch('http://127.0.0.1:7242/ingest/d073a867-51c1-42c1-8fd7-7f4b7895ed61',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'server.js:75',message:'After verifyWebhookSignature call',data:{signatureVerified},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'A'})}).catch(()=>{});
    // #endregion

    if (!signatureVerified) {
      // #region agent log
      fetch('http://127.0.0.1:7242/ingest/d073a867-51c1-42c1-8fd7-7f4b7895ed61',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'server.js:84',message:'Signature verification failed - returning 401',data:{signatureVerified,webhookId},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'E'})}).catch(()=>{});
      // #endregion
      console.error(`[${new Date().toISOString()}] ❌❌❌ INVALID SIGNATURE - REJECTING WEBHOOK ID: ${webhookId}`);
      console.error(`[${new Date().toISOString()}] Signature verified value: ${signatureVerified}`);
      console.error(`[${new Date().toISOString()}] About to return 401 - webhook should NOT be stored`);
      // #region agent log
      fetch('http://127.0.0.1:7242/ingest/d073a867-51c1-42c1-8fd7-7f4b7895ed61',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'server.js:89',message:'About to return 401 - execution should stop here',data:{},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'E'})}).catch(()=>{});
      // #endregion
      const response = res.status(401).json({ 
        error: 'Invalid signature',
        received: false,
        signatureVerified: false
      });
      console.error(`[${new Date().toISOString()}] Returned 401 response - execution should stop`);
      return response;
    } else {
      console.log(`[${new Date().toISOString()}] ✅ Signature verified for webhook ID: ${webhookId}`);
    }
  } else {
    // #region agent log
    fetch('http://127.0.0.1:7242/ingest/d073a867-51c1-42c1-8fd7-7f4b7895ed61',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'server.js:97',message:'WEBHOOK_SECRET not set branch',data:{webhookSecret:webhookSecret},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'B'})}).catch(()=>{});
    // #endregion
    console.warn(`[${new Date().toISOString()}] ⚠️ WEBHOOK_SECRET not set. Skipping signature verification.`);
    // If no secret is set, we still accept the webhook but mark it as unverified
  }

  // CRITICAL: Only create webhookData if we passed signature verification (or no secret set)
  // This ensures invalid signatures never create webhookData objects
  // #region agent log
  fetch('http://127.0.0.1:7242/ingest/d073a867-51c1-42c1-8fd7-7f4b7895ed61',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'server.js:108',message:'Reached webhookData creation - checking if this should happen',data:{signatureVerified,hasWebhookSecret:!!webhookSecret,shouldProceed:signatureVerified||!webhookSecret},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'E'})}).catch(()=>{});
  // #endregion
  console.error(`[${new Date().toISOString()}] ⚠️⚠️⚠️ REACHED WEBHOOK DATA CREATION - signatureVerified: ${signatureVerified}, hasSecret: ${!!webhookSecret}`);
  
  // Only proceed if signature is verified OR no secret is set
  if (!signatureVerified && webhookSecret) {
    // #region agent log
    fetch('http://127.0.0.1:7242/ingest/d073a867-51c1-42c1-8fd7-7f4b7895ed61',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'server.js:115',message:'ERROR: Should not reach here - signature invalid but secret exists',data:{signatureVerified,hasWebhookSecret:!!webhookSecret},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'E'})}).catch(()=>{});
    // #endregion
    console.error(`[${new Date().toISOString()}] ❌❌❌ BUG DETECTED: Invalid signature but execution continued! Returning 401 now.`);
    // This should never happen due to early return above, but defensive check
    const response = res.status(401).json({ 
      error: 'Invalid signature',
      received: false,
      signatureVerified: false
    });
    return response;
  }

  const receivedAt = new Date().toISOString();
  const webhookData = {
    id: webhookId,
    channel_id: payload.channel_id,
    timestamp: payload.timestamp,
    receivedAt,
    headers: req.headers,
    body: payload,
    signatureVerified: webhookSecret ? signatureVerified : null, // null means not checked
  };

  // Only store webhook if signature is valid (or if no secret is set)
  // #region agent log
  fetch('http://127.0.0.1:7242/ingest/d073a867-51c1-42c1-8fd7-7f4b7895ed61',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'server.js:125',message:'Storage condition check',data:{signatureVerified,hasWebhookSecret:!!webhookSecret,conditionResult:signatureVerified||!webhookSecret},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'D'})}).catch(()=>{});
  // #endregion
  if (signatureVerified || !webhookSecret) {
    // #region agent log
    fetch('http://127.0.0.1:7242/ingest/d073a867-51c1-42c1-8fd7-7f4b7895ed61',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'server.js:103',message:'Storing webhook',data:{reason:signatureVerified?'verified':'no_secret'},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'D'})}).catch(()=>{});
    // #endregion
    receivedWebhooks.unshift(webhookData); // Add to the beginning
    console.log(`[${receivedAt}] ✅ Webhook received and stored for channel: ${payload.channel_id}`);
    
    res.status(200).json({ 
      received: true, 
      signatureVerified: webhookSecret ? signatureVerified : null 
    });
  } else {
    // #region agent log
    fetch('http://127.0.0.1:7242/ingest/d073a867-51c1-42c1-8fd7-7f4b7895ed61',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'server.js:112',message:'Should not store - returning 401',data:{signatureVerified,hasWebhookSecret:!!webhookSecret},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'E'})}).catch(()=>{});
    // #endregion
    // This shouldn't happen due to the early return above, but just in case
    res.status(401).json({ 
      received: false,
      signatureVerified: false,
      error: 'Invalid signature'
    });
  }
});

// Start server
app.listen(PORT, () => {
  console.log('');
  console.log('🚀 ModelRiver Webhook Test Server');
  console.log('================================');
  console.log(`📡 Server running on http://localhost:${PORT}`);
  console.log(`📥 Webhook endpoint: http://localhost:${PORT}/webhook`);
  console.log(`🌐 Web UI: http://localhost:${PORT}`);
  console.log(`📊 API: http://localhost:${PORT}/api/webhooks`);
  console.log('');
  
  if (process.env.WEBHOOK_SECRET) {
    console.log('✅ WEBHOOK_SECRET is set - signature verification enabled');
  } else {
    console.log('⚠️  WEBHOOK_SECRET not set - signature verification disabled');
    console.log('   Set it with: WEBHOOK_SECRET=your_secret npm start');
  }
  
  console.log('');
  console.log('Waiting for webhooks...');
  console.log('');
});

