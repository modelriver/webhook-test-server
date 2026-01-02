# ModelRiver Webhook Test Server

A simple Node.js application to receive and test ModelRiver webhooks. This server receives webhook POST requests, verifies HMAC-SHA256 signatures, and displays received webhooks in a web interface.

## Features

- ✅ Receive webhook POST requests from ModelRiver
- ✅ Verify HMAC-SHA256 signatures (returns 401 if invalid)
- ✅ Web UI to view received webhooks
- ✅ JSON API for webhook history
- ✅ Console logging of all webhook events
- ✅ Auto-refresh option in web UI
- ✅ Clear history functionality

## Quick Start

### 1. Install Dependencies

```bash
cd webhook-test-server
npm install
```

### 2. Set Webhook Secret (Required for Signature Verification)

```bash
export WEBHOOK_SECRET=your_webhook_secret_here
```

Or create a `.env` file:
```bash
WEBHOOK_SECRET=your_webhook_secret_here
```

**Note:** If `WEBHOOK_SECRET` is not set, the server will still receive webhooks but won't verify signatures. However, **signature verification is strongly recommended for production use**.

### 3. Start the Server

```bash
npm start
```

The server will start on `http://localhost:3001` (or the port specified in `PORT` environment variable).

### 4. Access the Web Interface

Open your browser to: `http://localhost:3001`

## Signature Verification

The server verifies webhook signatures using HMAC-SHA256. The signature is generated from the `data` field of the payload, not the entire request body.

**Important:** If signature verification fails, the server will:
- Return HTTP 401 (Unauthorized)
- **NOT** store the webhook data
- Log a warning to the console

### How Signature Verification Works

1. Extract `X-ModelRiver-Signature` header
2. Extract `X-ModelRiver-Timestamp` header
3. Extract `data` field from request body
4. Generate signature: `HMAC-SHA256(secret, "${timestamp}.${JSON.stringify(data)}")`
5. Compare with provided signature using constant-time comparison

## Usage

### Webhook Endpoint

POST requests to `/webhook` will be:
- Verified (if `WEBHOOK_SECRET` is set)
- Stored in memory
- Displayed in the web UI

### API Endpoints

- `GET /api/webhooks` - Get all received webhooks
- `POST /webhook` - Receive webhook from ModelRiver
- `GET /` - Web UI

## Testing

1. Start the server: `npm start`
2. Create a webhook in ModelRiver pointing to `http://localhost:3001/webhook`
3. Make an async AI request in ModelRiver
4. Check the web UI at `http://localhost:3001` to see the received webhook

## Troubleshooting

### Signature Verification Fails

- Ensure `WEBHOOK_SECRET` matches the secret from ModelRiver
- Check that the secret doesn't have extra spaces or newlines
- Verify the webhook URL in ModelRiver is correct

### Webhook Not Received

- Check that the webhook is enabled in ModelRiver
- Verify the webhook URL is accessible from ModelRiver's servers
- Check server logs for errors

### Port Already in Use

```bash
PORT=3002 npm start
```






