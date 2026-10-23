# Phone, Google, and GitHub sign-in setup

The API already implements phone verification and Google/GitHub OAuth. Provider credentials are supplied through the backend environment; do not put secrets in frontend code.

## Local phone verification

Start the API with `frontend/scripts/start-api.ps1`. The local API script disables development codes, so phone OTP is sent through Twilio. Set `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, and either `TWILIO_VERIFY_SERVICE_SID` or `TWILIO_FROM_NUMBER` in `backend/.env`. Use the Twilio number in international format. Phone sign-in requires an account already registered with that number. If Twilio is not configured, the API returns an error instead of displaying a local code.

## Google sign-in

Create a Google OAuth web client and set these values in `backend/.env`:

```dotenv
OAUTH_GOOGLE_CLIENT_ID=your-client-id
OAUTH_GOOGLE_CLIENT_SECRET=your-client-secret
OAUTH_GOOGLE_REDIRECT_URI=http://127.0.0.1:8000/api/v1/auth/oauth/google/callback
```

Register that exact callback URL as an authorized redirect URI for the OAuth client.

## GitHub sign-in

Create a GitHub OAuth App and set these values in `backend/.env`:

```dotenv
OAUTH_GITHUB_CLIENT_ID=your-client-id
OAUTH_GITHUB_CLIENT_SECRET=your-client-secret
OAUTH_GITHUB_REDIRECT_URI=http://127.0.0.1:8000/api/v1/auth/oauth/github/callback
```

Set the OAuth App authorization callback URL to the exact URI above. GitHub accounts must have a verified primary email address for this implementation to create/link an account.

After changing `backend/.env`, restart the API. `GET /api/v1/auth/oauth/providers` reports whether each OAuth provider has all required values configured.
