# Dodo Checks

Dodo Checks is a check printing, mailing, and deposit workflow app.

## What’s included
- `public/` — marketing site + policy pages + dashboard assets
- `src/` — Node.js + Express server
  - public signup + login
  - cookie-based auth (JWT)
  - local SQL storage via SQLite (Node’s `node:sqlite`)
  - Increase API wrapper (stub)

## Local development (Windows)
1) Install dependencies:
- `npm install`

2) Configure your local env:
- Update `.env.example` (this is what `npm run dev` loads locally)
- Set `APP_COOKIE_SECRET` to a long random value
- Set `APP_DATA_ENCRYPTION_KEY` (base64 32 bytes) so SSNs can be stored encrypted
- Set Increase vars:
  - `INCREASE_API_KEY=...`
  - `INCREASE_URL=https://sandbox.increase.com` (sandbox)

3) Run the server:
- `npm run dev`

Then open:
- Marketing site: `http://localhost:3000/`
- Sign up: `http://localhost:3000/signup`
- Log in: `http://localhost:3000/login`
- Dashboard: `http://localhost:3000/app/overview`

## Database
- Local dev uses SQLite by default at `./data/dodo-checks.sqlite` (ignored by git).
- Production should use a managed database (DigitalOcean MySQL, Postgres, etc.). App Platform’s filesystem is ephemeral, so SQLite is not a good long-term production choice.
- To use MySQL, set `DATABASE_URL` to a MySQL connection string (for DigitalOcean this typically includes `?ssl-mode=REQUIRED`).

## Deploy to DigitalOcean App Platform
This repo should be deployed as a **Web Service** (Node.js), not a Static Site.

High-level settings:
- Build command: `npm ci`
- Run command: `npm start`
- Environment variables:
  - `NODE_ENV=production`
  - `APP_COOKIE_SECRET=...`
  - `DATABASE_URL=...` (MySQL connection string)
  - `INCREASE_API_KEY=...`
  - `INCREASE_URL=https://api.increase.com` (production) or `https://sandbox.increase.com` (sandbox)
  - Optional:
    - `APP_DEBUG=false`
    - `INCREASE_DEBUG=false`
    - `MYSQL_SSL_CA=...` (CA certificate contents, if you want TLS verification)

## Contact
- Email: mailing@dodochecks.com
- Address: 1209 Mountain Road PL NE, STE R, Albuquerque, NM 87110, USA
