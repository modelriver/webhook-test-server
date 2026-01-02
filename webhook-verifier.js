const crypto = require('crypto');

/**
 * Verifies the HMAC-SHA256 signature of a ModelRiver webhook.
 * 
 * IMPORTANT: The signature is generated from the `data` field of the payload,
 * not the entire request body. The request body structure is:
 * {
 *   channel_id: "...",
 *   timestamp: 1234567890,
 *   data: { ... }  // This is what the signature is based on
 * }
 * 
 * @param {string} signature - The signature from the 'X-ModelRiver-Signature' header.
 * @param {number|string} timestamp - The timestamp from the 'X-ModelRiver-Timestamp' header.
 * @param {object} dataPayload - The `data` field from the request body (not the full body).
 * @param {string} secret - The webhook secret configured in ModelRiver.
 * @returns {boolean} - True if the signature is valid, false otherwise.
 */
function verifyWebhookSignature(signature, timestamp, dataPayload, secret) {
  // #region agent log
  fetch('http://127.0.0.1:7242/ingest/d073a867-51c1-42c1-8fd7-7f4b7895ed61',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'webhook-verifier.js:20',message:'verifyWebhookSignature entry',data:{hasSignature:!!signature,hasTimestamp:!!timestamp,hasDataPayload:!!dataPayload,hasSecret:!!secret,secretLength:secret?.length},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'A'})}).catch(()=>{});
  // #endregion
  if (!signature || !timestamp || !dataPayload || !secret) {
    // #region agent log
    fetch('http://127.0.0.1:7242/ingest/d073a867-51c1-42c1-8fd7-7f4b7895ed61',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'webhook-verifier.js:22',message:'Missing data - returning false',data:{hasSignature:!!signature,hasTimestamp:!!timestamp,hasDataPayload:!!dataPayload,hasSecret:!!secret},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'A'})}).catch(()=>{});
    // #endregion
    console.warn('Missing data for signature verification. Skipping verification.');
    return false;
  }

  // The signature is generated from the `data` field, not the full body
  // Signature payload format: "${timestamp}.${JSON.stringify(data)}"
  // Ensure timestamp is a string (Elixir sends it as a string)
  const timestampStr = String(timestamp);
  const jsonData = JSON.stringify(dataPayload);
  const signaturePayload = `${timestampStr}.${jsonData}`;
  // #region agent log
  fetch('http://127.0.0.1:7242/ingest/d073a867-51c1-42c1-8fd7-7f4b7895ed61',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'webhook-verifier.js:32',message:'Before signature generation',data:{timestampStr,jsonDataLength:jsonData.length,signaturePayloadLength:signaturePayload.length},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'C'})}).catch(()=>{});
  // #endregion

  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(signaturePayload)
    .digest('hex');
  // #region agent log
  fetch('http://127.0.0.1:7242/ingest/d073a867-51c1-42c1-8fd7-7f4b7895ed61',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'webhook-verifier.js:38',message:'After signature generation',data:{providedSignature:signature.substring(0,16)+'...',expectedSignature:expectedSignature.substring(0,16)+'...',signatureLength:signature.length,expectedLength:expectedSignature.length,lengthsMatch:signature.length===expectedSignature.length},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'A'})}).catch(()=>{});
  // #endregion
  console.log(`[VERIFIER] Provided signature (first 16): ${signature.substring(0, 16)}...`);
  console.log(`[VERIFIER] Expected signature (first 16): ${expectedSignature.substring(0, 16)}...`);
  console.log(`[VERIFIER] Signatures match length: ${signature.length === expectedSignature.length}`);

  // Use constant-time comparison to prevent timing attacks
  try {
    // Ensure both are hex strings of the same length
    if (signature.length !== expectedSignature.length) {
      // #region agent log
      fetch('http://127.0.0.1:7242/ingest/d073a867-51c1-42c1-8fd7-7f4b7895ed61',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'webhook-verifier.js:53',message:'Length mismatch - returning false',data:{signatureLength:signature.length,expectedLength:expectedSignature.length},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'A'})}).catch(()=>{});
      // #endregion
      console.log(`[VERIFIER] ❌ Length mismatch - returning false`);
      return false;
    }
    
    const comparisonResult = crypto.timingSafeEqual(
      Buffer.from(signature, 'hex'),
      Buffer.from(expectedSignature, 'hex')
    );
    // #region agent log
    fetch('http://127.0.0.1:7242/ingest/d073a867-51c1-42c1-8fd7-7f4b7895ed61',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'webhook-verifier.js:62',message:'Signature comparison result',data:{comparisonResult},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'A'})}).catch(()=>{});
    // #endregion
    console.log(`[VERIFIER] Comparison result: ${comparisonResult}`);
    return comparisonResult;
  } catch (error) {
    // #region agent log
    fetch('http://127.0.0.1:7242/ingest/d073a867-51c1-42c1-8fd7-7f4b7895ed61',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'webhook-verifier.js:56',message:'Error in comparison - returning false',data:{error:error.message},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'A'})}).catch(()=>{});
    // #endregion
    console.error('Error during timingSafeEqual comparison:', error.message);
    return false;
  }
}

module.exports = { verifyWebhookSignature };

