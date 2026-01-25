'use strict';

const path = require('node:path');

// Local development uses `.env.example` (when running `npm run dev`).
// Production uses `.env` (when running `npm start`) or platform-provided env vars.
const dotenv = require('dotenv');
const envFile =
  process.env.DOTENV_FILE || (process.env.npm_lifecycle_event === 'dev' ? '.env.example' : '.env');

dotenv.config({ path: path.join(__dirname, '..', envFile) });

const express = require('express');


const app = express();
app.disable('x-powered-by');

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

const publicDir = path.join(__dirname, '..', 'public');
app.use(express.static(publicDir));

function env(name) {
  const v = process.env[name];
  if (!v) return null;
  const s = String(v).trim();
  return s ? s : null;
}

function parseBool(value, defaultValue = false) {
  if (value == null) return defaultValue;
  const s = String(value).trim().toLowerCase();
  if (!s) return defaultValue;
  return ['1', 'true', 'yes', 'y', 'on'].includes(s);
}

const APP_DEBUG = parseBool(env('APP_DEBUG'), false);

if (APP_DEBUG) {
  // eslint-disable-next-line no-console
  console.log('[debug] enabled');
}

app.use((req, res, next) => {
  if (APP_DEBUG) {
    // eslint-disable-next-line no-console
    console.log(`[http] ${req.method} ${req.originalUrl}`);
  }
  next();
});

// ===== Health checks =====
app.get('/healthz', (req, res) => {
  res.type('text/plain').send('ok');
});

app.get('/api/health', (req, res) => {
  res.json({ ok: true });
});


const port = Number(process.env.PORT || 3000);
app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`Dodo Checks server running on http://localhost:${port}`);
});
