# Milestone 1: Hybrid Security Gateway Implementation

I have successfully implemented the **Hybrid Security Gateway Middleware** in the CentralWatch FastAPI application!

## Changes Made

### 1. Data Model & Schema Updates
- **User Model (`demo-app/app/models/user.py`):** Added `status` (defaulting to `ACTIVE`) and `allowed_cidrs` (defaulting to `0.0.0.0/0`) to the User domain model.
- **Auth Schemas (`demo-app/app/schemas/auth.py`):** Updated `RegisterRequest` to accept an optional `allowed_cidrs` list, and `UserOut` to expose the new fields in API responses.

### 2. Authentication Service Updates
- **AuthService (`demo-app/app/services/auth_service.py`):** Modified the `.register()` function to properly inject the provided `allowed_cidrs` (or fall back to the default) and initialize the key status as `ACTIVE` when saving to DynamoDB.
- **Auth Routes (`demo-app/app/routes/auth.py`):** Passed the `allowed_cidrs` argument through the `/auth/register` endpoint to the service.

### 3. Security Enforcement Middleware (The Gateway)
- **Dependency Update (`demo-app/app/deps.py`):** Transformed the `require_auth` dependency into the Hybrid Security Gateway.
- **Key Revocation Check:** When a protected endpoint is called, it verifies if the API Key has been `REVOKED`. If so, it instantly raises a `403 Forbidden` and logs a structured security event (`TOKEN_REVOKED`).
- **Dynamic IP CIDR Verification:** Extracts the client's IP and evaluates it against the user's specific `allowed_cidrs` rules using Python's `ipaddress` library.
- **Automated Telemetry:** If an IP violation occurs, the request is blocked (`403 Forbidden`) AND a detailed `logger.warning` is emitted containing the `security_event`, `client_ip`, `user_id`, and `action="BLOCKED"`. (This log flows automatically into Loki and OpenTelemetry!).

## What was tested
- Data model fields correctly serialize/deserialize to and from DynamoDB format.
- CIDR block evaluation logic accurately matches or rejects the requesting client's IP.
- Security events are correctly formatted for the OpenTelemetry logging handler.

## Validation Results
The CentralWatch application is now capable of proactively defending against stolen/leaked API keys by evaluating IP rules in real time!
