# Admin login

This static mirror now includes a small Node.js authentication service at `/admin/`. It uses scrypt password hashes, HTTP-only SameSite cookies, in-memory sessions, and login rate limiting.

## Setup

1. Install Node.js 20 or newer on the server.
2. Copy `.env.example` to `.env` and provide `ADMIN_USERNAME`, a long random `SESSION_SECRET`, and an `ADMIN_PASSWORD_HASH`. The suggested admin identifier is `devamc`.
3. Generate a password hash with this command, replacing `YOUR_PASSWORD`:

```powershell
node -e "const c=require('crypto'); const p='YOUR_PASSWORD'; const s=c.randomBytes(16).toString('base64url'); console.log('scrypt$16384$'+s+'$'+c.scryptSync(p,s,64,{N:16384}).toString('base64url'))"
```

4. Export the variables from `.env` using your hosting provider's environment settings, then run `npm start`.
5. Put the service behind HTTPS in production. The `Secure` cookie flag is enabled automatically when `NODE_ENV=production`.

The current session store is intentionally in memory, so restarting the process signs out active sessions. A production deployment with multiple instances should replace it with a shared session store such as Redis.