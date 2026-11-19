# Milestone 2: CentralWatch Security Plugin Creation

I have successfully extracted the security gateway logic into a standalone, reusable Python package called **`centralwatch-security`**!

## Changes Made

### 1. Package Structure
Created a new top-level directory `centralwatch-security` and initialized it as a pip-installable package with a `pyproject.toml` file. This package depends on `fastapi` and `opentelemetry-api`.

### 2. Hybrid Security Gateway Middleware
- **Location:** `centralwatch-security/centralwatch_security/middleware.py`
- Extracted the core security logic (IP CIDR checking, API key revocation checks, and OpenTelemetry logging) into a generic, reusable Starlette `BaseHTTPMiddleware` called `SecurityEnforcementMiddleware`.
- **Dynamic Policy Lookup:** Instead of hardcoding the user lookup logic, the middleware now accepts a generic `get_policy_callback` function. This allows the host application (whether it uses DynamoDB, Postgres, or Redis) to seamlessly provide the security policies!

### 3. Architecture Refactor (Demo App Integration)
- Stripped the hardcoded WAF logic out of `demo-app/app/deps.py`. It is now back to just being a simple token validator.
- Imported the `SecurityEnforcementMiddleware` directly from the `centralwatch-security` plugin package into `demo-app/app/main.py`.
- Created a `fetch_user_security_policy` bridge function that allows the plugin to dynamically query the DynamoDB users for their IP CIDRs and Revocation status!

## What was tested
- The package is fully configured and can be successfully installed in any project using `pip install -e centralwatch-security`.
- The `demo-app` correctly mounts the plugin and successfully blocks unauthorized IPs via the middleware.

## Bug Fixes & Refinements
- Fixed an issue where `/auth/profile` and `/centralwatch/security-scan` bypassed the gateway. They are now strictly protected by the middleware pipeline.
