# Authentication verification API

The backend implements these endpoints. OTPs are stored as hashes, expire after five minutes, allow up to five verification attempts, and are single-use. In local development only, `AUTH_OTP_DEV_MODE` may include a development code in the response when no delivery provider is configured.

## Send a code

- `POST /api/v1/auth/verification/email/send`
  - Request: `{ "email": "analyst@example.com" }`
- `POST /api/v1/auth/verification/phone/send`
  - Request: `{ "phone": "+15550000000" }`
- Response for either: `{ "challenge_id": "opaque-id", "expires_in_seconds": 300 }`

Code sends are limited to three per destination in 15 minutes. Delivery requires SMTP and Twilio settings in the backend environment. The API returns `503` when a provider is not configured.

## Verify a code

- `POST /api/v1/auth/verification/email/verify`
  - Request: `{ "email": "analyst@example.com", "code": "123456", "challenge_id": "opaque-id" }`
- `POST /api/v1/auth/verification/phone/verify`
  - Request: `{ "phone": "+15550000000", "code": "123456", "challenge_id": "opaque-id" }`
- Response: `{ "verification_token": "short-lived, single-use token" }`

Tokens are bound to the verified address/number and expire with the challenge. The frontend requires both tokens before enabling registration.

## Register

`POST /api/v1/auth/register` accepts `phone`, `email_verification_token`, and `phone_verification_token` along with username, email, password, and role. It validates and consumes both tokens before creating the account.

## Sign in with mobile

- `POST /api/v1/auth/phone/login`
  - Request: `{ "phone": "+15550000000", "code": "123456", "challenge_id": "opaque-id" }`
  - Response: same token response as `POST /api/v1/auth/login` (`access_token`, `username`, `role`), or an email two-factor challenge when that option is enabled.

The provider values are documented in the backend `.env.example`. Configure real SMTP and Twilio credentials in the backend's private `.env` to enable delivery; do not commit those credentials.

## Account Center

These endpoints require the signed-in user's bearer token:

- `GET /api/v1/auth/account/overview` returns account details, linked Google/GitHub providers, and email two-factor status.
- `POST /api/v1/auth/account/password` accepts `current_password` and `new_password`. Updating a password signs out other sessions and returns a replacement access token for the current browser.
- `POST /api/v1/auth/account/email-2fa/send` sends a confirmation code to the account email.
- `POST /api/v1/auth/account/email-2fa/confirm` accepts `challenge_id`, `code`, and `enabled` to turn email-code two-factor authentication on or off.
- `GET /api/v1/auth/account/sessions` lists active sign-ins with device/browser details, IP address, timestamps, and a current-device indicator. It does not perform an external location lookup.
- `DELETE /api/v1/auth/account/sessions/{session_id}` signs out one device.
- `POST /api/v1/auth/account/sessions/revoke-others` signs out other tracked devices.
- `POST /api/v1/auth/account/sessions/revoke-all` signs out all devices, including the current one.

Email two-factor authentication is checked after password, phone, and Google/GitHub sign-in. A password login that needs the second factor returns `requires_email_verification` and a `challenge_id`; submit `challenge_id` and `code` to `POST /api/v1/auth/login/email-2fa/verify` to finish signing in. Saved logins are tracked sessions; SIEM AI does not store browser-saved passwords.

To connect a social account to an existing account, an authenticated browser requests `GET /api/v1/auth/oauth/{google|github}/link`. The response contains an `authorization_url`; the provider callback links that verified identity to the signed-in account.

## Google and GitHub sign-in

The API also implements `GET /api/v1/auth/oauth/providers`, provider start routes at `/api/v1/auth/oauth/{google|github}/start`, and matching callback routes. OAuth state is stored server-side and expires after ten minutes. A provider account with a verified email signs into its matching account or creates a new analyst account.

Configure each provider's client ID, secret, and callback URI in the backend private `.env`. The callback URI must exactly match the URL registered with Google or GitHub. Set `FRONTEND_URL` to the UI's origin. For a separately hosted UI, set frontend `VITE_API_BASE_URL` to the backend API root (for example, `https://api.example.com/api/v1`) and configure the backend's `FRONTEND_URL` to the UI origin.

## Local development

Run `npm run dev` for the UI and `npm run dev:api` for the API. The API script uses a local SQLite file and keeps local uploads in that database. Production deployments should set a persistent database URL and deploy the API behind HTTPS.
