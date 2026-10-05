# CentralWatch API Proxy & Cyberpunk Dashboard Feature

This document outlines the recent changes made to introduce the API Proxy feature and the new redesigned futuristic frontend dashboard.

## Overview of Changes

1. **API Proxy Backend (`centralwatch-security`)**
   - Added `httpx` to `pyproject.toml` dependencies to handle asynchronous HTTP proxying.
   - Modified `centralwatch-security/centralwatch_security/routers.py` to include:
     - `POST /centralwatch/proxy/keys` - An endpoint to register new external API services, their secret keys, and whitelist IPs.
     - `GET /centralwatch/proxy/keys` - An endpoint to list all registered services (safely masking the actual API keys).
     - `ANY /centralwatch/proxy/{service_name}/{path:path}` - The main proxy endpoint. It verifies the client IP against the whitelist, injects the secret API key as a Bearer token, and seamlessly forwards the request to the third-party service.

2. **Cyberpunk Dashboard Frontend (`frontend/dist`)**
   - Completely overhauled the UI located in `frontend/dist`.
   - **`index.html`**: Replaced with a visually stunning, dark-themed HTML structure featuring a CSS-animated central globe/radar.
   - **`styles.css`**: Added advanced CSS for neon glow effects, grid layouts, custom fonts (Orbitron & Share Tech Mono), and responsive panels.
   - **`app.js`**: Connected the frontend to the new proxy management endpoints. It dynamically fetches and displays registered services and allows users to register new keys directly from the central globe form.

## How to Test

1. **Start the Application**
   Make sure the Docker Compose stack is running:
   ```bash
   docker-compose up -d
   ```

2. **View the Dashboard**
   - Navigate to `http://localhost:8080` in your browser.
   - You should immediately see the new futuristic dashboard.

3. **Register a New Proxy Key**
   - In the center of the dashboard (over the globe), fill out the form:
     - **Service ID**: `test_service`
     - **Target Base URL**: `https://jsonplaceholder.typicode.com`
     - **Secret API Key**: `my_super_secret_key`
     - **Allowed IPs**: `127.0.0.1, 10.0.0.0/8`
   - Click **INITIALIZE PROXY**.
   - The left panel ("MANAGED PROXY SERVICES") should instantly update to show your newly registered service.

4. **Test the Proxy Endpoint**
   - Open a terminal or tool like Postman.
   - Make a request to the CentralWatch proxy without providing any API keys:
   ```bash
   curl -X GET http://localhost:8000/centralwatch/proxy/test_service/users/1
   ```
   - **Expected Result**: You should receive a JSON response from the JSONPlaceholder mock service. Behind the scenes, CentralWatch successfully verified your `127.0.0.1` IP address and forwarded the request.

5. **Test Access Control**
   - If you were to make the request from an IP not in the `Allowed IPs` list, CentralWatch would instantly block the request with a `403 Forbidden` response.
