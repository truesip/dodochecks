# Dodo Checks

Dodo Checks is a check printing and mailing workflow app.

## What's included
- `public/` — marketing site + policy pages
- `src/` — Node.js + Express server (static file serving + health checks)

## Local development (Windows)
1) Install dependencies:
- `npm install`

2) Configure your local env (optional):
- Update `.env.example` (this is what `npm run dev` loads locally)

3) Run the server:
- `npm run dev`

Then open:
- Marketing site: `http://localhost:3000/`


## Deploy to DigitalOcean App Platform
This repo should be deployed as a **Web Service** (Node.js), not a Static Site.

High-level settings:
- Build command: `npm ci`
- Run command: `npm start`
- Environment variables:
  - `NODE_ENV=production`
  - Optional:
    - `APP_DEBUG=false`

## Contact
- Email: mailing@dodochecks.com
- Address: 1209 Mountain Road PL NE, STE R, Albuquerque, NM 87110, USA
