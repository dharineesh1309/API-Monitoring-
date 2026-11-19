Optional local copies of build downloads, for networks that block them. Not committed (see .gitignore).

- `astf-v2.0.1.jar`: the OWASP ASTF scanner. If present, the Dockerfile uses it instead of downloading it
  from GitHub. Either way the build checks its SHA-256 (`ea9defba5bf0a835…`, see the Dockerfile).
  To get a copy from a running app: `docker cp centralwatch-demo-app:/app/astf-v2.0.1.jar demo-app/vendor/`
