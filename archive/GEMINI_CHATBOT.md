# Gemini Chatbot Through CentralWatch

## Architecture

The demo chatbot never reads the Gemini API key from `.env` and never sends that key to the browser. The request path is:

```text
Dashboard prompt
  -> POST /chat with a CentralWatch proxy token
  -> demo-app calls /centralwatch/proxy/gemini_api/...
  -> CentralWatch checks IP + token hash + gemini_chat role
  -> CentralWatch injects x-goog-api-key
  -> Gemini generateContent
  -> demo-app extracts the generated text
  -> dashboard displays the reply
```

The built-in `gemini_chat` role permits only `POST` requests to `gemini_api`. The `gemini_api` registration starts with `replace_with_gemini_api_key`, an unusable placeholder that CentralWatch refuses to send upstream.

## Configure from the dashboard

1. Start the stack with `docker compose up -d --build`.
2. Open `http://127.0.0.1:8080/#chat`.
3. Paste a Gemini API key into **Gemini API key**.
4. Select **Save key in CentralWatch**.
5. Enter a prompt and select **Send prompt**.

Saving the key replaces the placeholder service and returns a one-time CentralWatch token. The dashboard keeps that proxy token in `sessionStorage` for the current browser tab. It clears the Gemini key input and never puts the Gemini key in browser storage.

After closing the tab or rotating the token, paste the current `cw_proxy_...` value into **Existing CentralWatch proxy token**. If the token is rotated from the API proxy page in the same tab, the chatbot automatically uses the replacement.

The default model is `gemini-3.8-flash`. The model field can be changed to another Gemini model ID.

## Direct API example

After configuring `gemini_api` and copying its CentralWatch proxy token:

```powershell
curl.exe -X POST http://127.0.0.1:8000/chat `
  -H "Content-Type: application/json" `
  -H "X-CentralWatch-Proxy-Token: <generated-proxy-token>" `
  -d '{"prompt":"Explain API key firewalls briefly","model":"gemini-3.8-flash"}'
```

The response contains:

```json
{
  "reply": "...",
  "model": "gemini-3.8-flash",
  "finish_reason": "STOP"
}
```

## Security behavior

- The browser sends the Gemini key only once to the local CentralWatch management endpoint.
- The demo app receives only the prompt and CentralWatch proxy token.
- CentralWatch stores the Gemini key in its service registry and stores only the SHA-256 hash of the proxy token.
- CentralWatch injects the Gemini key as `x-goog-api-key`, which is the header required by Gemini's REST API.
- Missing/invalid proxy tokens, disallowed IPs, and non-POST methods are blocked.
- Prompts and generated response bodies are not stored in proxy usage history.
- The local registry is process memory, so configuration disappears when `demo-app` restarts.

For production, put upstream keys in an encrypted secrets manager, persist token hashes and roles in a database, protect management endpoints with administrator authorization, serve the dashboard over HTTPS, and provision the demo application's proxy token through an application secret rather than browser session storage.
