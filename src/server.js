'use strict';

const path = require('node:path');
const crypto = require('node:crypto');

// Local development uses `.env.example` (when running `npm run dev`).
// Production uses `.env` (when running `npm start`) or platform-provided env vars.
const dotenv = require('dotenv');
const envFile =
  process.env.DOTENV_FILE || (process.env.npm_lifecycle_event === 'dev' ? '.env.example' : '.env');

dotenv.config({ path: path.join(__dirname, '..', envFile) });

const express = require('express');
const bcrypt = require('bcryptjs');
const multer = require('multer');

const { createIncreaseClient } = require('./increase');

const {
  createUser,
  getUserByEmail,
  createAuditEvent,
  listRecentEventsForUser,

  // Per-user data
  getUserCompliance,
  upsertUserCompliance,
  addUserComplianceDocument,
  listUserComplianceDocuments,

  getUserIncrease,
  upsertUserIncrease,

  addUserExternalAccount,
  listUserExternalAccounts,

  addUserExport,
  listUserExports,
} = require('./db');
const { setAuthCookie, clearAuthCookie, getAuthPayload, requireAuth } = require('./auth');
const { esc, renderAuthPage, renderAppLayout } = require('./pages');

const app = express();
app.disable('x-powered-by');

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB
  },
});

const publicDir = path.join(__dirname, '..', 'public');
app.use(express.static(publicDir));

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function safeNextUrl(nextUrl) {
  // Only allow relative URLs within this site.
  const raw = String(nextUrl || '').trim();
  if (!raw) return '/app/overview';
  if (!raw.startsWith('/')) return '/app/overview';
  if (raw.startsWith('//')) return '/app/overview';
  return raw;
}

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

function getDataEncryptionKey() {
  // Base64-encoded 32-byte key (AES-256-GCM)
  const raw = env('APP_DATA_ENCRYPTION_KEY');
  if (!raw) return null;

  let buf;
  try {
    buf = Buffer.from(String(raw), 'base64');
  } catch {
    return null;
  }

  if (buf.length !== 32) return null;
  return buf;
}

function encryptString(plaintext) {
  const key = getDataEncryptionKey();
  if (!key) return null;

  const value = String(plaintext || '');
  if (!value) return null;

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return [iv.toString('base64'), ciphertext.toString('base64'), tag.toString('base64')].join('.');
}

function decryptString(ciphertext) {
  const key = getDataEncryptionKey();
  if (!key) return null;

  const raw = String(ciphertext || '').trim();
  if (!raw) return null;

  const parts = raw.split('.');
  if (parts.length !== 3) return null;

  try {
    const iv = Buffer.from(parts[0], 'base64');
    const data = Buffer.from(parts[1], 'base64');
    const tag = Buffer.from(parts[2], 'base64');

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);

    const plaintext = Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
    return plaintext;
  } catch {
    return null;
  }
}

function digitsOnly(value) {
  return String(value || '').replace(/\D/g, '');
}

function ssnLast4(value) {
  const digits = digitsOnly(value);
  if (digits.length < 4) return '';
  return digits.slice(-4);
}

const APP_DEBUG = parseBool(env('APP_DEBUG'), false);

if (APP_DEBUG) {
  // eslint-disable-next-line no-console
  console.log('[debug] enabled');
  // eslint-disable-next-line no-console
  console.log('[config]', {
    increase_url:
      env('INCREASE_URL') ||
      env('INCREASE_BASE_URL') ||
      env('INCREASE_API_URL') ||
      'https://api.increase.com',
    increase_api_key: env('INCREASE_API_KEY') ? '(set)' : '(not set)',
  });
}

app.use((req, res, next) => {
  if (APP_DEBUG) {
    // eslint-disable-next-line no-console
    console.log(`[http] ${req.method} ${req.originalUrl}`);
  }
  next();
});

function requireAuthApi(req, res, next) {
  const payload = getAuthPayload(req);
  if (!payload?.sub) {
    res.status(401).json({ error: 'unauthorized' });
    return;
  }

  req.user = {
    id: Number(payload.sub),
    email: String(payload.email || ''),
  };

  next();
}

function extractDataArray(listResponse) {
  if (Array.isArray(listResponse)) return listResponse;
  if (listResponse && Array.isArray(listResponse.data)) return listResponse.data;
  return [];
}

function getBalanceCents(balanceResponse) {
  if (!balanceResponse || typeof balanceResponse !== 'object') return null;
  const maybe =
    balanceResponse.balance ??
    balanceResponse.available_balance ??
    balanceResponse.current_balance;
  return typeof maybe === 'number' ? maybe : null;
}

function formatUsdFromCents(cents) {
  const dollars = Number(cents) / 100;
  return dollars.toLocaleString('en-US', { style: 'currency', currency: 'USD' });
}

function formatShortDateTime(iso) {
  if (!iso) return '';
  const d = new Date(String(iso));
  if (Number.isNaN(d.getTime())) return String(iso);

  return d.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
}

function humanizeEnum(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';

  const parts = raw.replaceAll('-', '_').split('_').filter(Boolean);
  const upper = new Set(['ach', 'atm', 'api', 'id', 'url', 'usd']);

  return parts
    .map((p) => {
      const lower = p.toLowerCase();
      if (upper.has(lower)) return lower.toUpperCase();
      return lower.charAt(0).toUpperCase() + lower.slice(1);
    })
    .join(' ');
}

function getTxCategory(tx) {
  if (!tx || typeof tx !== 'object') return 'Transaction';
  const raw = tx.category ?? tx.type ?? tx.transaction_type ?? tx.source?.category;
  const label = raw ? humanizeEnum(raw) : '';
  return label || 'Transaction';
}

function getTxAmountCents(tx) {
  if (!tx || typeof tx !== 'object') return null;
  const maybe = tx.amount ?? tx.amount_cents ?? tx.amount_in_cents;
  return typeof maybe === 'number' ? maybe : null;
}

function findFirstIdByPrefixes(value, prefixes, depth = 0, seen) {
  const maxDepth = 8;
  if (!prefixes || prefixes.length === 0) return '';
  if (value == null) return '';
  if (depth > maxDepth) return '';

  if (typeof value === 'string') {
    const s = value.trim();
    if (!s) return '';
    for (const p of prefixes) {
      if (s.startsWith(p)) return s;
    }
    return '';
  }

  if (typeof value !== 'object') return '';

  if (!seen) seen = new Set();
  if (seen.has(value)) return '';
  seen.add(value);

  if (Array.isArray(value)) {
    for (const item of value) {
      const found = findFirstIdByPrefixes(item, prefixes, depth + 1, seen);
      if (found) return found;
    }
    return '';
  }

  for (const v of Object.values(value)) {
    const found = findFirstIdByPrefixes(v, prefixes, depth + 1, seen);
    if (found) return found;
  }

  return '';
}

function findCancelableTransferId(tx) {
  const prefixes = ['ach_transfer_', 'wire_transfer_', 'check_transfer_', 'real_time_payments_transfer_'];
  if (!tx || typeof tx !== 'object') return '';
  return (
    findFirstIdByPrefixes(tx.source, prefixes) ||
    findFirstIdByPrefixes(tx, prefixes)
  );
}

function findInboundAchTransferId(tx) {
  const prefixes = ['inbound_ach_transfer_'];
  if (!tx || typeof tx !== 'object') return '';
  return (
    findFirstIdByPrefixes(tx.source, prefixes) ||
    findFirstIdByPrefixes(tx, prefixes)
  );
}

function redactForUi(value, path = []) {
  if (value == null) return value;

  if (Array.isArray(value)) {
    return value.map((v) => redactForUi(v, path));
  }

  if (typeof value === 'object') {
    const out = {};
    const parentKey = path[path.length - 1];
    const parentKeyLower = parentKey ? String(parentKey).toLowerCase() : '';

    for (const [k, v] of Object.entries(value)) {
      const key = String(k);
      const keyLower = key.toLowerCase();
      const nextPath = path.concat(key);

      const isAddressObject = parentKeyLower.includes('address');
      const isSensitiveAddressField =
        isAddressObject &&
        (keyLower === 'line1' ||
          keyLower === 'line2' ||
          keyLower === 'city' ||
          keyLower === 'state' ||
          keyLower === 'zip' ||
          keyLower === 'postal_code' ||
          keyLower === 'country');

      if (
        keyLower === 'account_number' ||
        keyLower === 'routing_number' ||
        keyLower === 'api_key' ||
        keyLower === 'token' ||
        keyLower === 'authorization' ||
        keyLower === 'identification_number' ||
        keyLower === 'tax_identifier' ||
        keyLower === 'tax_identification_number' ||
        keyLower === 'taxpayer_identification_number' ||
        keyLower === 'ssn' ||
        keyLower === 'social_security_number' ||
        keyLower === 'email' ||
        keyLower === 'phone' ||
        keyLower === 'date_of_birth' ||
        keyLower === 'recipient_name' ||
        keyLower === 'creditor_name' ||
        keyLower === 'name' ||
        (keyLower === 'number' && parentKeyLower === 'identification') ||
        isSensitiveAddressField
      ) {
        out[key] = '[REDACTED]';
      } else {
        out[key] = redactForUi(v, nextPath);
      }
    }

    return out;
  }

  return value;
}

function getTransferDescription(transfer) {
  if (!transfer || typeof transfer !== 'object') return '';
  return String(
    transfer.statement_descriptor ??
      transfer.description ??
      transfer.memo ??
      transfer.id ??
      ''
  );
}

function getTransferStatus(transfer) {
  if (!transfer || typeof transfer !== 'object') return '';
  return String(transfer.status ?? transfer.state ?? transfer.transfer_status ?? '').trim();
}

function transferStatusClass(status) {
  const s = String(status || '').trim().toLowerCase();
  if (!s) return 'pending';

  if (s.includes('complete') || s.includes('completed') || s.includes('settled')) return 'completed';
  if (
    s.includes('rejected') ||
    s.includes('returned') ||
    s.includes('canceled') ||
    s.includes('cancelled') ||
    s.includes('reversed') ||
    s.includes('failed')
  ) {
    return 'failed';
  }
  return 'pending';
}

function cardStatusClass(status) {
  const s = String(status || '').trim().toLowerCase();
  if (!s) return 'pending';
  if (s === 'active') return 'completed';

  if (s.includes('disable') || s.includes('cancel') || s.includes('terminate') || s.includes('closed')) {
    return 'failed';
  }

  return 'pending';
}

function lockboxBehaviorClass(behavior) {
  const s = String(behavior || '').trim().toLowerCase();
  if (!s) return 'pending';
  if (s === 'enabled') return 'completed';
  if (s === 'disabled') return 'failed';
  return 'pending';
}

function fileDirectionClass(direction) {
  const s = String(direction || '').trim().toLowerCase();
  if (!s) return 'pending';
  if (s === 'from_increase') return 'completed';
  if (s === 'to_increase') return 'pending';
  return 'pending';
}

function entityStatusClass(status) {
  const s = String(status || '').trim().toLowerCase();
  if (!s) return 'pending';
  if (s === 'active') return 'completed';
  if (s === 'archived' || s === 'disabled') return 'failed';
  return 'pending';
}

function riskRatingClass(rating) {
  const s = String(rating || '').trim().toLowerCase();
  if (!s) return 'pending';
  if (s === 'low') return 'completed';
  if (s === 'high') return 'failed';
  return 'pending';
}

function formatCardSummary(card) {
  if (!card || typeof card !== 'object') return '—';

  const last4 = card.last4 != null ? String(card.last4).trim() : '';
  const mm =
    card.expiration_month != null && card.expiration_month !== ''
      ? String(card.expiration_month).padStart(2, '0')
      : '';
  const yyyy = card.expiration_year != null ? String(card.expiration_year).trim() : '';

  const pan = last4 ? `•••• ${last4}` : '';
  const exp = mm && yyyy ? `${mm}/${yyyy}` : '';

  if (pan && exp) return `${pan} · ${exp}`;
  return pan || exp || '—';
}

function csvEscape(value) {
  const s = value == null ? '' : String(value);
  if (/[\",\n\r]/.test(s)) return `"${s.replaceAll('"', '""')}"`;
  return s;
}

function renderEvents(events) {
  if (!events || events.length === 0) {
    return '<li class="small">No events yet.</li>';
  }

  return events
    .map((e) => {
      const type = String(e.type || 'event');
      const when = String(e.created_at || '');
      return `
        <li class="event">
          <div>
            <div class="type">${esc(type)}</div>
            <div class="meta">${esc(when)}</div>
          </div>
          <span class="pill">ok</span>
        </li>
      `;
    })
    .join('');
}

app.get('/healthz', (req, res) => {
  res.type('text/plain').send('ok');
});

app.get('/api/health', (req, res) => {
  res.json({ ok: true });
});

app.get('/api/accounts', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const userIncrease = await getUserIncrease(req.user.id);
  const accountId = userIncrease?.account_id ? String(userIncrease.account_id).trim() : '';

  if (!accountId) {
    res.json({ data: [], next_cursor: null });
    return;
  }

  try {
    const increase = createIncreaseClient();
    const account = await increase.retrieveAccount({ accountId });
    res.json({ data: account ? [account] : [], next_cursor: null });
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

// Transfer between Increase accounts (book transfer)
app.post('/api/internal-transfers', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  // Consumer MVP only supports ACH/wires/checks; internal book transfers are disabled.
  res.status(400).json({ error: 'not_supported' });
  return;

  const fromAccountId = String(req.body?.from_account_id || '').trim();
  const toAccountNumberId = String(req.body?.to_account_number_id || '').trim();
  const toAccountId = String(req.body?.to_account_id || '').trim();
  const description = String(req.body?.description || '').trim();
  const amountCentsRaw = Number(req.body?.amount_cents);

  if (!fromAccountId) {
    res.status(400).json({ error: 'from_account_id is required' });
    return;
  }

  if (!toAccountNumberId && !toAccountId) {
    res.status(400).json({ error: 'to_account_id is required' });
    return;
  }

  if (!Number.isInteger(amountCentsRaw) || amountCentsRaw <= 0) {
    res.status(400).json({ error: 'amount_cents must be an integer greater than 0' });
    return;
  }

  try {
    const increase = createIncreaseClient();

    let destinationAccountId = toAccountId;

    if (!destinationAccountId && toAccountNumberId) {
      const acctNum = await increase.retrieveAccountNumber({ accountNumberId: toAccountNumberId });
      destinationAccountId = String(acctNum?.account_id || '').trim();
    }

    if (!destinationAccountId) {
      res.status(400).json({ error: 'Destination account is required' });
      return;
    }

    const created = await increase.createAccountTransfer({
      fromAccountId,
      toAccountId: destinationAccountId,
      amountCents: amountCentsRaw,
      description: description || undefined,
    });

    createAuditEvent({
      userId: req.user.id,
      type: 'increase.account_transfer.created',
      payload: {
        id: created?.id,
        from_account_id: fromAccountId,
        to_account_id: destinationAccountId,
        amount_cents: amountCentsRaw,
      },
    });

    res.status(201).json(created);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

// Check deposit (front + back images)
app.post(
  '/api/check-deposits',
  requireAuthApi,
  upload.fields([
    { name: 'front', maxCount: 1 },
    { name: 'back', maxCount: 1 },
  ]),
  async (req, res) => {
    if (!env('INCREASE_API_KEY')) {
      res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
      return;
    }

    const userIncrease = await getUserIncrease(req.user.id);
    const accountId = userIncrease?.account_id ? String(userIncrease.account_id).trim() : '';

    if (!accountId) {
      res.status(400).json({ error: 'account_not_provisioned' });
      return;
    }

    const amountCentsRaw = Number(req.body?.amount_cents);
    const description = String(req.body?.description || '').trim();

    const frontFile = Array.isArray(req.files?.front) ? req.files.front[0] : null;
    const backFile = Array.isArray(req.files?.back) ? req.files.back[0] : null;

    if (!Number.isInteger(amountCentsRaw) || amountCentsRaw <= 0) {
      res.status(400).json({ error: 'amount_cents must be an integer greater than 0' });
      return;
    }

    if (!frontFile || !backFile) {
      res.status(400).json({ error: 'front and back check images are required' });
      return;
    }

    try {
      const increase = createIncreaseClient();

      const front = await increase.createFile({
        fileBuffer: frontFile.buffer,
        filename: frontFile.originalname,
        mimeType: frontFile.mimetype,
        purpose: 'check_deposit_front_image',
        description: description || undefined,
      });

      const back = await increase.createFile({
        fileBuffer: backFile.buffer,
        filename: backFile.originalname,
        mimeType: backFile.mimetype,
        purpose: 'check_deposit_back_image',
        description: description || undefined,
      });

      const created = await increase.createCheckDeposit({
        accountId,
        amountCents: amountCentsRaw,
        frontFileId: front?.id,
        backFileId: back?.id,
        description: description || undefined,
        idempotencyKey: `user-${req.user.id}-check-deposit-${Date.now()}`,
      });

      createAuditEvent({
        userId: req.user.id,
        type: 'increase.check_deposit.created',
        payload: {
          id: created?.id,
          account_id: accountId,
          amount_cents: amountCentsRaw,
          front_file_id: front?.id,
          back_file_id: back?.id,
        },
      });

      res.status(201).json(created);
    } catch (err) {
      res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
    }
  }
);

app.get('/api/transactions', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const userIncrease = await getUserIncrease(req.user.id);
  const accountId = userIncrease?.account_id ? String(userIncrease.account_id).trim() : '';

  if (!accountId) {
    res.status(400).json({ error: 'account_not_provisioned' });
    return;
  }

  const cursor = String(req.query?.cursor || '').trim() || null;
  const limitRaw = req.query?.limit != null ? Number(req.query.limit) : null;
  const limit = Number.isInteger(limitRaw) && limitRaw > 0 && limitRaw <= 100 ? limitRaw : 50;

  try {
    const increase = createIncreaseClient();
    const txs = await increase.listTransactions({
      limit,
      cursor,
      account_id: accountId,
    });
    res.json(txs);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.get('/api/transactions/export.csv', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).type('text/plain').send('INCREASE_API_KEY is not set');
    return;
  }

  const userIncrease = await getUserIncrease(req.user.id);
  const accountId = userIncrease?.account_id ? String(userIncrease.account_id).trim() : '';

  if (!accountId) {
    res.status(400).type('text/plain').send('account_not_provisioned');
    return;
  }

  try {
    const increase = createIncreaseClient();

    const [account, pendingResp, txsResp] = await Promise.all([
      increase.retrieveAccount({ accountId }).catch(() => null),
      increase.listPendingTransactions({ limit: 100, account_id: accountId }).catch(() => null),
      increase.listTransactions({ limit: 100, account_id: accountId }),
    ]);

    const accountNameById = new Map([[accountId, String(account?.name || accountId)]]);

    const pending = extractDataArray(pendingResp);
    const txs = extractDataArray(txsResp);

    const header = ['status', 'created_at', 'description', 'account', 'category', 'amount'].join(',');

    const rows = [];
    function pushRow(status, tx) {
      const createdAt = String(tx.created_at || tx.created || '');
      const desc = String(tx.description || tx.memo || tx.id || '');
      const acctId = String(tx.account_id || '');
      const acctName = accountNameById.get(acctId) || acctId;
      const category = getTxCategory(tx);
      const amountCents = getTxAmountCents(tx);
      const amount = amountCents == null ? '' : formatUsdFromCents(amountCents);

      rows.push(
        [status, createdAt, desc, acctName, category, amount]
          .map(csvEscape)
          .join(',')
      );
    }

    for (const tx of pending) pushRow('pending', tx);
    for (const tx of txs) pushRow('completed', tx);

    const csv = `${header}\n${rows.join('\n')}\n`;

    const filename = `transactions_${accountId}.csv`;
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.type('text/csv').send(csv);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.post('/api/pending-transactions/:pendingTransactionId/release', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const pendingTransactionId = String(req.params.pendingTransactionId || '').trim();
  if (!pendingTransactionId) {
    res.status(400).json({ error: 'pendingTransactionId is required' });
    return;
  }

  const userIncrease = await getUserIncrease(req.user.id);
  const accountId = userIncrease?.account_id ? String(userIncrease.account_id).trim() : '';

  if (!accountId) {
    res.status(400).json({ error: 'account_not_provisioned' });
    return;
  }

  try {
    const increase = createIncreaseClient();

    const pending = await increase.retrievePendingTransaction({ pendingTransactionId });
    const pendingAccountId = String(pending?.account_id || '').trim();

    if (pendingAccountId && pendingAccountId !== accountId) {
      res.status(404).json({ error: 'not_found' });
      return;
    }

    const released = await increase.releasePendingTransaction({ pendingTransactionId });

    createAuditEvent({
      userId: req.user.id,
      type: 'increase.pending_transaction.released',
      payload: { pending_transaction_id: pendingTransactionId },
    });

    res.status(200).json(released);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.post('/api/transactions/:transactionId/cancel', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const transactionId = String(req.params.transactionId || '').trim();
  if (!transactionId) {
    res.status(400).json({ error: 'transactionId is required' });
    return;
  }

  const userIncrease = await getUserIncrease(req.user.id);
  const accountId = userIncrease?.account_id ? String(userIncrease.account_id).trim() : '';

  if (!accountId) {
    res.status(400).json({ error: 'account_not_provisioned' });
    return;
  }

  try {
    const increase = createIncreaseClient();

    const tx = await increase.retrieveTransaction({ transactionId });
    const txAccountId = String(tx?.account_id || '').trim();

    if (txAccountId && txAccountId !== accountId) {
      res.status(404).json({ error: 'not_found' });
      return;
    }

    const transferId = findCancelableTransferId(tx);
    if (!transferId) {
      res.status(400).json({ error: 'cancel_not_supported_for_transaction' });
      return;
    }

    let canceled;

    if (transferId.startsWith('ach_transfer_')) {
      canceled = await increase.cancelAchTransfer({ achTransferId: transferId });
    } else if (transferId.startsWith('wire_transfer_')) {
      canceled = await increase.cancelWireTransfer({ wireTransferId: transferId });
    } else if (transferId.startsWith('check_transfer_')) {
      canceled = await increase.cancelCheckTransfer({ checkTransferId: transferId });
    } else if (transferId.startsWith('real_time_payments_transfer_')) {
      canceled = await increase.cancelRealTimePaymentsTransfer({ realTimePaymentsTransferId: transferId });
    } else {
      res.status(400).json({ error: 'cancel_not_supported_for_transfer_type' });
      return;
    }

    createAuditEvent({
      userId: req.user.id,
      type: 'increase.transfer.canceled',
      payload: { transaction_id: transactionId, transfer_id: transferId },
    });

    res.status(200).json(canceled);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.post('/api/transactions/:transactionId/return-inbound-ach', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const transactionId = String(req.params.transactionId || '').trim();
  if (!transactionId) {
    res.status(400).json({ error: 'transactionId is required' });
    return;
  }

  const reason = String(req.body?.reason || '').trim();
  if (!reason) {
    res.status(400).json({ error: 'reason is required' });
    return;
  }

  // Basic validation; Increase enforces the actual enum.
  if (!/^[a-z0-9_\-]+$/i.test(reason) || reason.length > 100) {
    res.status(400).json({ error: 'reason must be 100 characters or fewer and contain only letters, numbers, underscore, or dash' });
    return;
  }

  const userIncrease = await getUserIncrease(req.user.id);
  const accountId = userIncrease?.account_id ? String(userIncrease.account_id).trim() : '';

  if (!accountId) {
    res.status(400).json({ error: 'account_not_provisioned' });
    return;
  }

  try {
    const increase = createIncreaseClient();

    const tx = await increase.retrieveTransaction({ transactionId });
    const txAccountId = String(tx?.account_id || '').trim();

    if (txAccountId && txAccountId !== accountId) {
      res.status(404).json({ error: 'not_found' });
      return;
    }

    const inboundAchTransferId = findInboundAchTransferId(tx);
    if (!inboundAchTransferId) {
      res.status(400).json({ error: 'return_not_supported_for_transaction' });
      return;
    }

    const returned = await increase.returnInboundAchTransfer({ inboundAchTransferId, reason });

    createAuditEvent({
      userId: req.user.id,
      type: 'increase.inbound_ach_transfer.returned',
      payload: { transaction_id: transactionId, inbound_ach_transfer_id: inboundAchTransferId, reason },
    });

    res.status(200).json(returned);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.get('/api/transfers', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const userIncrease = await getUserIncrease(req.user.id);
  const accountId = userIncrease?.account_id ? String(userIncrease.account_id).trim() : '';

  if (!accountId) {
    res.status(400).json({ error: 'account_not_provisioned' });
    return;
  }

  const cursor = String(req.query?.cursor || '').trim() || null;
  const limitRaw = req.query?.limit != null ? Number(req.query.limit) : null;
  const limit = Number.isInteger(limitRaw) && limitRaw > 0 && limitRaw <= 100 ? limitRaw : 50;

  try {
    const increase = createIncreaseClient();
    const transfers = await increase.listAchTransfers({
      limit,
      cursor,
      account_id: accountId,
    });
    res.json(transfers);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.get('/api/transfers/export.csv', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).type('text/plain').send('INCREASE_API_KEY is not set');
    return;
  }

  const userIncrease = await getUserIncrease(req.user.id);
  const accountId = userIncrease?.account_id ? String(userIncrease.account_id).trim() : '';

  if (!accountId) {
    res.status(400).type('text/plain').send('account_not_provisioned');
    return;
  }

  try {
    const increase = createIncreaseClient();

    const [account, transfersResp] = await Promise.all([
      increase.retrieveAccount({ accountId }).catch(() => null),
      increase.listAchTransfers({ limit: 100, account_id: accountId }),
    ]);

    const accountNameById = new Map([[accountId, String(account?.name || accountId)]]);

    const transfers = extractDataArray(transfersResp);

    const header = ['created_at', 'description', 'account', 'status', 'amount'].join(',');

    const rows = transfers.map((t) => {
      const createdAt = String(t.created_at || t.created || '');
      const desc = getTransferDescription(t);
      const acctId = String(t.account_id || '');
      const acctName = accountNameById.get(acctId) || acctId;
      const status = humanizeEnum(getTransferStatus(t) || '');
      const amountCents = getTxAmountCents(t);
      const amount = amountCents == null ? '' : formatUsdFromCents(amountCents);

      return [createdAt, desc, acctName, status, amount].map(csvEscape).join(',');
    });

    const csv = `${header}\n${rows.join('\n')}\n`;

    const filename = `transfers_${accountId}.csv`;
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.type('text/csv').send(csv);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.get('/api/cards', requireAuthApi, async (req, res) => {
  // Cards are not part of the consumer MVP. Keep endpoint user-scoped to avoid data leaks.
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const userIncrease = await getUserIncrease(req.user.id);
  const accountId = userIncrease?.account_id ? String(userIncrease.account_id).trim() : '';

  if (!accountId) {
    res.json({ data: [], next_cursor: null });
    return;
  }

  const cursor = String(req.query?.cursor || '').trim() || null;
  const limitRaw = req.query?.limit != null ? Number(req.query.limit) : null;
  const limit = Number.isInteger(limitRaw) && limitRaw > 0 && limitRaw <= 100 ? limitRaw : 50;

  try {
    const increase = createIncreaseClient();
    const cards = await increase.listCards({
      limit,
      cursor,
      account_id: accountId,
    });
    res.json(cards);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.get('/api/account-numbers', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const userIncrease = await getUserIncrease(req.user.id);
  const accountId = userIncrease?.account_id ? String(userIncrease.account_id).trim() : '';

  if (!accountId) {
    res.json({ data: [], next_cursor: null });
    return;
  }

  const cursor = String(req.query?.cursor || '').trim() || null;
  const limitRaw = req.query?.limit != null ? Number(req.query.limit) : null;
  const limit = Number.isInteger(limitRaw) && limitRaw > 0 && limitRaw <= 100 ? limitRaw : 50;

  try {
    const increase = createIncreaseClient();
    const accountNumbers = await increase.listAccountNumbers({
      limit,
      cursor,
      account_id: accountId,
    });
    res.json(accountNumbers);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.get('/api/external-accounts', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const limitRaw = req.query?.limit != null ? Number(req.query.limit) : null;
  const limit = Number.isInteger(limitRaw) && limitRaw > 0 && limitRaw <= 100 ? limitRaw : 50;

  try {
    const mapped = await listUserExternalAccounts(req.user.id, limit);

    const increase = createIncreaseClient();

    const externalAccounts = [];
    for (const row of mapped) {
      const externalAccountId = String(row?.external_account_id || '').trim();
      if (!externalAccountId) continue;

      try {
        const ea = await increase.retrieveExternalAccount({ externalAccountId });
        if (ea) externalAccounts.push(ea);
      } catch {
        // ignore
      }
    }

    res.json({ data: externalAccounts, next_cursor: null });
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.get('/api/lockboxes', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const userIncrease = await getUserIncrease(req.user.id);
  const accountId = userIncrease?.account_id ? String(userIncrease.account_id).trim() : '';

  if (!accountId) {
    res.json({ data: [], next_cursor: null });
    return;
  }

  const cursor = String(req.query?.cursor || '').trim() || null;
  const limitRaw = req.query?.limit != null ? Number(req.query.limit) : null;
  const limit = Number.isInteger(limitRaw) && limitRaw > 0 && limitRaw <= 100 ? limitRaw : 50;

  try {
    const increase = createIncreaseClient();
    const lockboxes = await increase.listLockboxes({
      limit,
      cursor,
      account_id: accountId,
    });
    res.json(lockboxes);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.get('/api/account-statements', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const userIncrease = await getUserIncrease(req.user.id);
  const accountId = userIncrease?.account_id ? String(userIncrease.account_id).trim() : '';

  if (!accountId) {
    res.json({ data: [], next_cursor: null });
    return;
  }

  const cursor = String(req.query?.cursor || '').trim() || null;
  const limitRaw = req.query?.limit != null ? Number(req.query.limit) : null;
  const limit = Number.isInteger(limitRaw) && limitRaw > 0 && limitRaw <= 100 ? limitRaw : 50;

  try {
    const increase = createIncreaseClient();
    const statements = await increase.listAccountStatements({
      limit,
      cursor,
      account_id: accountId,
    });
    res.json(statements);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.get('/api/entities', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const cursor = String(req.query?.cursor || '').trim() || null;
  const limitRaw = req.query?.limit != null ? Number(req.query.limit) : null;
  const limit = Number.isInteger(limitRaw) && limitRaw > 0 && limitRaw <= 100 ? limitRaw : 50;

  const status = String(req.query?.status || '').trim() || null;

  try {
    const increase = createIncreaseClient();
    const entitiesResp = await increase.listEntities({
      limit,
      cursor,
      ...(status ? { 'status.in': [status] } : {}),
    });
    res.json(entitiesResp);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.post('/api/entities/:entityId/confirm', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const entityId = String(req.params.entityId || '').trim();
  if (!entityId) {
    res.status(400).json({ error: 'entityId is required' });
    return;
  }

  try {
    const increase = createIncreaseClient();
    const updated = await increase.request({
      method: 'POST',
      pathname: `/entities/${encodeURIComponent(entityId)}/confirm`,
      body: {},
    });

    createAuditEvent({
      userId: req.user.id,
      type: 'increase.entity.confirmed',
      payload: { id: updated?.id, status: updated?.status },
    });

    res.status(200).json(updated);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.post('/api/entities/:entityId/update-address', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const entityId = String(req.params.entityId || '').trim();
  const line1 = String(req.body?.line1 || '').trim();
  const line2 = String(req.body?.line2 || '').trim();
  const city = String(req.body?.city || '').trim();
  const state = String(req.body?.state || '').trim();
  const zip = String(req.body?.zip || '').trim();

  if (!entityId) {
    res.status(400).json({ error: 'entityId is required' });
    return;
  }

  if (!line1 || !city || !state || !zip) {
    res.status(400).json({ error: 'line1, city, state, and zip are required' });
    return;
  }

  try {
    const increase = createIncreaseClient();
    const updated = await increase.request({
      method: 'POST',
      pathname: `/entities/${encodeURIComponent(entityId)}/update_address`,
      body: {
        address: {
          line1,
          ...(line2 ? { line2 } : {}),
          city,
          state,
          zip,
        },
      },
    });

    createAuditEvent({
      userId: req.user.id,
      type: 'increase.entity.address_updated',
      payload: { id: updated?.id, line1, city, state, zip },
    });

    res.status(200).json(updated);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.post('/api/entities/:entityId/update-industry-code', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const entityId = String(req.params.entityId || '').trim();
  const industryCode = String(req.body?.industry_code || '').trim();

  if (!entityId) {
    res.status(400).json({ error: 'entityId is required' });
    return;
  }

  if (!industryCode) {
    res.status(400).json({ error: 'industry_code is required' });
    return;
  }

  try {
    const increase = createIncreaseClient();
    const updated = await increase.request({
      method: 'POST',
      pathname: `/entities/${encodeURIComponent(entityId)}/update_industry_code`,
      body: {
        industry_code: industryCode,
      },
    });

    createAuditEvent({
      userId: req.user.id,
      type: 'increase.entity.industry_code_updated',
      payload: { id: updated?.id, industry_code: industryCode },
    });

    res.status(200).json(updated);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.post('/api/entities/:entityId/archive', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const entityId = String(req.params.entityId || '').trim();
  if (!entityId) {
    res.status(400).json({ error: 'entityId is required' });
    return;
  }

  try {
    const increase = createIncreaseClient();
    const updated = await increase.request({
      method: 'POST',
      pathname: `/entities/${encodeURIComponent(entityId)}/archive`,
    });

    createAuditEvent({
      userId: req.user.id,
      type: 'increase.entity.archived',
      payload: { id: updated?.id, status: updated?.status },
    });

    res.status(200).json(updated);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.post('/api/entities/:entityId/documents', requireAuthApi, upload.single('file'), async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const entityId = String(req.params.entityId || '').trim();
  const description = String(req.body?.description || '').trim();

  if (!entityId) {
    res.status(400).json({ error: 'entityId is required' });
    return;
  }

  if (!req.file) {
    res.status(400).json({ error: 'file is required' });
    return;
  }

  if (description && description.length > 200) {
    res.status(400).json({ error: 'description must be 200 characters or fewer' });
    return;
  }

  try {
    const increase = createIncreaseClient();
    const createdFile = await increase.createFile({
      fileBuffer: req.file.buffer,
      filename: req.file.originalname,
      mimeType: req.file.mimetype,
      purpose: 'entity_supplemental_document',
      description: description || undefined,
    });

    const createdDoc = await increase.createEntitySupplementalDocument({
      entityId,
      fileId: createdFile?.id,
    });

    createAuditEvent({
      userId: req.user.id,
      type: 'increase.entity_supplemental_document.created',
      payload: { entityId, fileId: createdFile?.id, id: createdDoc?.id },
    });

    res.status(201).json({ file: createdFile, document: createdDoc });
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.get('/api/exports', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const limitRaw = req.query?.limit != null ? Number(req.query.limit) : null;
  const limit = Number.isInteger(limitRaw) && limitRaw > 0 && limitRaw <= 100 ? limitRaw : 50;

  try {
    const mapped = await listUserExports(req.user.id, limit);

    const increase = createIncreaseClient();

    const exportsList = [];
    for (const row of mapped) {
      const exportId = String(row?.export_id || '').trim();
      if (!exportId) continue;

      try {
        const ex = await increase.retrieveExport({ exportId });
        if (ex) exportsList.push(ex);
      } catch {
        // ignore
      }
    }

    res.json({ data: exportsList, next_cursor: null });
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.post('/api/exports', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const category = String(req.body?.category || '').trim();

  if (!category) {
    res.status(400).json({ error: 'category is required' });
    return;
  }

  const userIncrease = await getUserIncrease(req.user.id);
  const accountId = userIncrease?.account_id ? String(userIncrease.account_id).trim() : '';

  // Only allow user-scoped export types (anything else could leak other users' data).
  const allowed = new Set([
    'transaction_csv',
    'balance_csv',
    'account_statement_ofx',
    'account_statement_bai2',
  ]);

  if (!allowed.has(category)) {
    res.status(400).json({ error: 'unsupported_export_category' });
    return;
  }

  if (!accountId) {
    res.status(400).json({ error: 'account_not_provisioned' });
    return;
  }

  const body = {
    category,
    [category]: {
      account_id: accountId,
    },
  };

  try {
    const increase = createIncreaseClient();
    const created = await increase.createExport({
      body,
      idempotencyKey: `user-${req.user.id}-export-${category}-${Date.now()}`,
    });

    try {
      if (created?.id) {
        await addUserExport({
          userId: req.user.id,
          exportId: String(created.id),
          category: String(created.category || category),
        });
      }
    } catch {
      // ignore
    }

    createAuditEvent({
      userId: req.user.id,
      type: 'increase.export.created',
      payload: { id: created?.id, category: created?.category, status: created?.status },
    });

    res.status(201).json(created);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.get('/api/files', requireAuthApi, async (req, res) => {
  // NOTE: Increase Files cannot be safely listed per-user with our current data model.
  // Disable this endpoint to prevent leaking other users' documents.
  res.status(403).json({ error: 'disabled_for_safety' });
});

app.post('/api/files', requireAuthApi, upload.single('file'), async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const purpose = String(req.body?.purpose || '').trim();
  const description = String(req.body?.description || '').trim();

  if (!purpose) {
    res.status(400).json({ error: 'purpose is required' });
    return;
  }

  if (!req.file) {
    res.status(400).json({ error: 'file is required' });
    return;
  }

  if (description && description.length > 200) {
    res.status(400).json({ error: 'description must be 200 characters or fewer' });
    return;
  }

  try {
    const increase = createIncreaseClient();
    const created = await increase.createFile({
      fileBuffer: req.file.buffer,
      filename: req.file.originalname,
      mimeType: req.file.mimetype,
      purpose,
      description: description || undefined,
    });

    createAuditEvent({
      userId: req.user.id,
      type: 'increase.file.created',
      payload: { id: created?.id, purpose: created?.purpose, filename: created?.filename },
    });

    res.status(201).json(created);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.post('/api/accounts', requireAuthApi, async (req, res) => {
  // Use the onboarding provision flow to create the user's single account + account number + lockbox.
  res.status(400).json({ error: 'use_onboarding_provision' });
});

app.post('/api/cards', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const accountId = String(req.body?.account_id || '').trim();
  const description = String(req.body?.description || '').trim();

  if (!accountId) {
    res.status(400).json({ error: 'account_id is required' });
    return;
  }

  const billing = req.body?.billing_address;
  const line1 = String(billing?.line1 || '').trim();
  const line2 = String(billing?.line2 || '').trim();
  const city = String(billing?.city || '').trim();
  const state = String(billing?.state || '').trim();
  const postalCode = String(billing?.postal_code || '').trim();

  const anyBilling = Boolean(line1 || line2 || city || state || postalCode);
  let billingAddress = null;

  if (anyBilling) {
    if (!line1 || !city || !state || !postalCode) {
      res.status(400).json({
        error: 'billing_address requires line1, city, state, and postal_code (or leave all billing fields blank)',
      });
      return;
    }

    billingAddress = {
      line1,
      ...(line2 ? { line2 } : {}),
      city,
      state,
      postal_code: postalCode,
    };
  }

  try {
    const increase = createIncreaseClient();
    const created = await increase.createCard({
      accountId,
      description: description || undefined,
      billingAddress: billingAddress || undefined,
    });

    createAuditEvent({
      userId: req.user.id,
      type: 'increase.card.created',
      payload: { id: created?.id, accountId, last4: created?.last4 },
    });

    res.status(201).json(created);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.post('/api/cards/:cardId/update-status', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const cardId = String(req.params.cardId || '').trim();
  const status = String(req.body?.status || '').trim();

  if (!cardId) {
    res.status(400).json({ error: 'cardId is required' });
    return;
  }

  const allowed = new Set(['active', 'disabled', 'canceled']);
  if (!allowed.has(status)) {
    res.status(400).json({ error: 'status must be active, disabled, or canceled' });
    return;
  }

  try {
    const increase = createIncreaseClient();
    const updated = await increase.updateCard({
      cardId,
      body: {
        status,
      },
    });

    createAuditEvent({
      userId: req.user.id,
      type: 'increase.card.status_updated',
      payload: { id: updated?.id, status },
    });

    res.status(200).json(updated);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.post('/api/cards/:cardId/update-description', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const cardId = String(req.params.cardId || '').trim();
  const description = String(req.body?.description || '').trim();

  if (!cardId) {
    res.status(400).json({ error: 'cardId is required' });
    return;
  }

  if (description.length > 200) {
    res.status(400).json({ error: 'description must be 200 characters or fewer' });
    return;
  }

  try {
    const increase = createIncreaseClient();
    const updated = await increase.updateCard({
      cardId,
      body: {
        description: description || null,
      },
    });

    createAuditEvent({
      userId: req.user.id,
      type: 'increase.card.description_updated',
      payload: { id: updated?.id, description },
    });

    res.status(200).json(updated);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.post('/api/cards/:cardId/update-billing-address', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const cardId = String(req.params.cardId || '').trim();

  const line1 = String(req.body?.line1 || '').trim();
  const line2 = String(req.body?.line2 || '').trim();
  const city = String(req.body?.city || '').trim();
  const state = String(req.body?.state || '').trim();
  const postalCode = String(req.body?.postal_code || '').trim();

  if (!cardId) {
    res.status(400).json({ error: 'cardId is required' });
    return;
  }

  const anyBilling = Boolean(line1 || line2 || city || state || postalCode);

  if (anyBilling && (!line1 || !city || !state || !postalCode)) {
    res.status(400).json({
      error: 'Billing address requires line1, city, state, and postal_code (or leave all billing fields blank)',
    });
    return;
  }

  const billingAddress = anyBilling
    ? {
        line1,
        ...(line2 ? { line2 } : {}),
        city,
        state,
        postal_code: postalCode,
      }
    : null;

  try {
    const increase = createIncreaseClient();
    const updated = await increase.updateCard({
      cardId,
      body: {
        billing_address: billingAddress,
      },
    });

    createAuditEvent({
      userId: req.user.id,
      type: 'increase.card.billing_address_updated',
      payload: { id: updated?.id, billing_address: billingAddress ? { line1, city, state, postal_code: postalCode } : null },
    });

    res.status(200).json(updated);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.post('/api/account-numbers', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const accountId = String(req.body?.account_id || '').trim();
  const name = String(req.body?.name || '').trim();

  if (!accountId) {
    res.status(400).json({ error: 'account_id is required' });
    return;
  }

  if (!name) {
    res.status(400).json({ error: 'name is required' });
    return;
  }

  try {
    const increase = createIncreaseClient();
    const created = await increase.createAccountNumber({ accountId, name });

    createAuditEvent({
      userId: req.user.id,
      type: 'increase.account_number.created',
      payload: { id: created?.id, accountId, name },
    });

    res.status(201).json(created);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.post('/api/account-numbers/:accountNumberId/update-name', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const accountNumberId = String(req.params.accountNumberId || '').trim();
  const name = String(req.body?.name || '').trim();

  if (!accountNumberId) {
    res.status(400).json({ error: 'accountNumberId is required' });
    return;
  }

  if (!name) {
    res.status(400).json({ error: 'name is required' });
    return;
  }

  if (name.length > 200) {
    res.status(400).json({ error: 'name must be 200 characters or fewer' });
    return;
  }

  try {
    const increase = createIncreaseClient();
    const updated = await increase.updateAccountNumber({
      accountNumberId,
      body: {
        name,
      },
    });

    createAuditEvent({
      userId: req.user.id,
      type: 'increase.account_number.name_updated',
      payload: { id: updated?.id, name },
    });

    res.status(200).json(updated);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.post('/api/account-numbers/:accountNumberId/update-status', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const accountNumberId = String(req.params.accountNumberId || '').trim();
  const status = String(req.body?.status || '').trim();

  if (!accountNumberId) {
    res.status(400).json({ error: 'accountNumberId is required' });
    return;
  }

  const allowed = new Set(['active', 'disabled', 'canceled']);
  if (!allowed.has(status)) {
    res.status(400).json({ error: 'status must be active, disabled, or canceled' });
    return;
  }

  try {
    const increase = createIncreaseClient();
    const updated = await increase.updateAccountNumber({
      accountNumberId,
      body: {
        status,
      },
    });

    createAuditEvent({
      userId: req.user.id,
      type: 'increase.account_number.status_updated',
      payload: { id: updated?.id, status },
    });

    res.status(200).json(updated);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.post('/api/account-numbers/:accountNumberId/update-inbound-ach-debit-status', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const accountNumberId = String(req.params.accountNumberId || '').trim();
  const debitStatus = String(req.body?.debit_status || '').trim();

  if (!accountNumberId) {
    res.status(400).json({ error: 'accountNumberId is required' });
    return;
  }

  const allowed = new Set(['allowed', 'blocked']);
  if (!allowed.has(debitStatus)) {
    res.status(400).json({ error: 'debit_status must be allowed or blocked' });
    return;
  }

  try {
    const increase = createIncreaseClient();
    const updated = await increase.updateAccountNumber({
      accountNumberId,
      body: {
        inbound_ach: {
          debit_status: debitStatus,
        },
      },
    });

    createAuditEvent({
      userId: req.user.id,
      type: 'increase.account_number.inbound_ach_debit_status_updated',
      payload: { id: updated?.id, debit_status: debitStatus },
    });

    res.status(200).json(updated);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.post('/api/account-numbers/:accountNumberId/update-inbound-checks-status', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const accountNumberId = String(req.params.accountNumberId || '').trim();
  const inboundChecksStatus = String(req.body?.status || '').trim();

  if (!accountNumberId) {
    res.status(400).json({ error: 'accountNumberId is required' });
    return;
  }

  const allowed = new Set(['allowed', 'check_transfers_only']);
  if (!allowed.has(inboundChecksStatus)) {
    res.status(400).json({ error: 'status must be allowed or check_transfers_only' });
    return;
  }

  try {
    const increase = createIncreaseClient();
    const updated = await increase.updateAccountNumber({
      accountNumberId,
      body: {
        inbound_checks: {
          status: inboundChecksStatus,
        },
      },
    });

    createAuditEvent({
      userId: req.user.id,
      type: 'increase.account_number.inbound_checks_status_updated',
      payload: { id: updated?.id, status: inboundChecksStatus },
    });

    res.status(200).json(updated);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.post('/api/external-accounts', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const description = String(req.body?.description || '').trim();
  const routingNumber = String(req.body?.routing_number || '').trim();
  const accountNumber = String(req.body?.account_number || '').trim();
  const accountHolder = String(req.body?.account_holder || '').trim();
  const funding = String(req.body?.funding || '').trim();

  if (!description) {
    res.status(400).json({ error: 'description is required' });
    return;
  }

  if (!routingNumber || !accountNumber) {
    res.status(400).json({ error: 'routing_number and account_number are required' });
    return;
  }

  try {
    const increase = createIncreaseClient();
    const created = await increase.createExternalAccount({
      description,
      routingNumber,
      accountNumber,
      accountHolder: accountHolder || undefined,
      funding: funding || undefined,
    });

    try {
      if (created?.id) {
        await addUserExternalAccount({
          userId: req.user.id,
          externalAccountId: String(created.id),
          description,
        });
      }
    } catch {
      // Ignore mapping failures (e.g., duplicate insert) so the core call succeeds.
    }

    createAuditEvent({
      userId: req.user.id,
      type: 'increase.external_account.created',
      payload: { id: created?.id, description },
    });

    res.status(201).json(created);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.post('/api/lockboxes', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const description = String(req.body?.description || '').trim();
  const recipientName = String(req.body?.recipient_name || '').trim();

  const userIncrease = await getUserIncrease(req.user.id);
  const entityId = userIncrease?.entity_id ? String(userIncrease.entity_id).trim() : '';
  const accountId = userIncrease?.account_id ? String(userIncrease.account_id).trim() : '';

  if (!accountId) {
    res.status(400).json({ error: 'account_not_provisioned' });
    return;
  }

  try {
    const increase = createIncreaseClient();
    const created = await increase.createLockbox({
      accountId,
      description: description || undefined,
      recipientName: recipientName || undefined,
      idempotencyKey: `user-${req.user.id}-lockbox-${Date.now()}`,
    });

    // If the user doesn't have a default lockbox yet, store this one.
    try {
      if (!userIncrease?.lockbox_id && created?.id) {
        await upsertUserIncrease({
          userId: req.user.id,
          entityId: entityId || null,
          accountId,
          accountNumberId: userIncrease?.account_number_id ? String(userIncrease.account_number_id) : null,
          lockboxId: String(created.id),
        });
      }
    } catch {
      // ignore
    }

    createAuditEvent({
      userId: req.user.id,
      type: 'increase.lockbox.created',
      payload: { id: created?.id, accountId, description: created?.description },
    });

    res.status(201).json(created);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.post('/api/transfers', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const userIncrease = await getUserIncrease(req.user.id);
  const accountId = userIncrease?.account_id ? String(userIncrease.account_id).trim() : '';

  if (!accountId) {
    res.status(400).json({ error: 'account_not_provisioned' });
    return;
  }

  const routingNumber = String(req.body?.routing_number || '').trim();
  const accountNumber = String(req.body?.account_number || '').trim();
  const statementDescriptor = String(req.body?.statement_descriptor || 'Dodo Checks').trim();
  const direction = String(req.body?.direction || 'credit').trim().toLowerCase();
  const amountCentsRaw = Number(req.body?.amount_cents);

  if (!routingNumber || !accountNumber) {
    res.status(400).json({ error: 'routing_number and account_number are required' });
    return;
  }

  if (!Number.isInteger(amountCentsRaw) || amountCentsRaw <= 0) {
    res.status(400).json({ error: 'amount_cents must be an integer greater than 0' });
    return;
  }

  const amountCents = direction === 'debit' ? -Math.abs(amountCentsRaw) : Math.abs(amountCentsRaw);

  try {
    const increase = createIncreaseClient();
    const created = await increase.createAchTransfer({
      accountId,
      routingNumber,
      accountNumber,
      amountCents,
      statementDescriptor,
      idempotencyKey: `user-${req.user.id}-ach-${Date.now()}`,
    });

    createAuditEvent({
      userId: req.user.id,
      type: 'increase.ach_transfer.created',
      payload: { id: created?.id, accountId, amountCents, direction },
    });

    res.status(201).json(created);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.post('/api/wire-transfers', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const userIncrease = await getUserIncrease(req.user.id);
  const accountId = userIncrease?.account_id ? String(userIncrease.account_id).trim() : '';

  if (!accountId) {
    res.status(400).json({ error: 'account_not_provisioned' });
    return;
  }

  const routingNumber = String(req.body?.routing_number || '').trim();
  const accountNumber = String(req.body?.account_number || '').trim();
  const creditorName = String(req.body?.creditor_name || '').trim();
  const remittanceMessage = String(req.body?.remittance_message || '').trim();
  const amountCentsRaw = Number(req.body?.amount_cents);

  if (!routingNumber || !accountNumber || !creditorName) {
    res.status(400).json({ error: 'routing_number, account_number, and creditor_name are required' });
    return;
  }

  if (!Number.isInteger(amountCentsRaw) || amountCentsRaw <= 0) {
    res.status(400).json({ error: 'amount_cents must be an integer greater than 0' });
    return;
  }

  try {
    const increase = createIncreaseClient();
    const created = await increase.createWireTransfer({
      accountId,
      amountCents: amountCentsRaw,
      routingNumber,
      accountNumber,
      creditorName,
      remittanceMessage: remittanceMessage || '.',
      idempotencyKey: `user-${req.user.id}-wire-${Date.now()}`,
    });

    createAuditEvent({
      userId: req.user.id,
      type: 'increase.wire_transfer.created',
      payload: { id: created?.id, accountId, amount_cents: amountCentsRaw },
    });

    res.status(201).json(created);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.post('/api/check-transfers', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  const userIncrease = await getUserIncrease(req.user.id);
  const accountId = userIncrease?.account_id ? String(userIncrease.account_id).trim() : '';
  const sourceAccountNumberId = userIncrease?.account_number_id
    ? String(userIncrease.account_number_id).trim()
    : '';

  if (!accountId) {
    res.status(400).json({ error: 'account_not_provisioned' });
    return;
  }

  if (!sourceAccountNumberId) {
    res.status(400).json({ error: 'account_number_not_provisioned' });
    return;
  }

  const recipientName = String(req.body?.recipient_name || '').trim();
  const memo = String(req.body?.memo || '').trim();
  const amountCentsRaw = Number(req.body?.amount_cents);

  const line1 = String(req.body?.mailing_line1 || '').trim();
  const line2 = String(req.body?.mailing_line2 || '').trim();
  const city = String(req.body?.mailing_city || '').trim();
  const state = String(req.body?.mailing_state || '').trim();
  const postalCode = String(req.body?.mailing_postal_code || '').trim();

  if (!recipientName || !line1 || !city || !state || !postalCode) {
    res.status(400).json({ error: 'recipient_name and complete mailing address are required' });
    return;
  }

  if (!Number.isInteger(amountCentsRaw) || amountCentsRaw <= 0) {
    res.status(400).json({ error: 'amount_cents must be an integer greater than 0' });
    return;
  }

  try {
    const increase = createIncreaseClient();
    const created = await increase.createCheckTransfer({
      accountId,
      sourceAccountNumberId,
      amountCents: amountCentsRaw,
      recipientName,
      memo: memo || undefined,
      mailingAddress: {
        line1,
        ...(line2 ? { line2 } : {}),
        city,
        state,
        postal_code: postalCode,
      },
      idempotencyKey: `user-${req.user.id}-check-${Date.now()}`,
    });

    createAuditEvent({
      userId: req.user.id,
      type: 'increase.check_transfer.created',
      payload: { id: created?.id, accountId, amount_cents: amountCentsRaw },
    });

    res.status(201).json(created);
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.get('/api/compliance', requireAuthApi, async (req, res) => {
  const compliance = await getUserCompliance(req.user.id);
  const docs = await listUserComplianceDocuments(req.user.id, 50);
  const increaseIds = await getUserIncrease(req.user.id);

  // Never return SSN ciphertext over the API.
  const safeCompliance = compliance
    ? {
        user_id: compliance.user_id,
        full_name: compliance.full_name,
        email: compliance.email,
        phone: compliance.phone,
        date_of_birth: compliance.date_of_birth,
        ssn_last4: compliance.ssn_last4,
        address_line1: compliance.address_line1,
        address_line2: compliance.address_line2,
        city: compliance.city,
        state: compliance.state,
        zip: compliance.zip,
        status: compliance.status,
        created_at: compliance.created_at,
        updated_at: compliance.updated_at,
      }
    : null;

  res.json({ compliance: safeCompliance, documents: docs, increase: increaseIds });
});

app.post('/api/compliance', requireAuthApi, async (req, res) => {
  const existing = await getUserCompliance(req.user.id);

  const fullName = String(req.body?.full_name || '').trim();
  const phone = String(req.body?.phone || '').trim();
  const dateOfBirth = String(req.body?.date_of_birth || '').trim();

  const addressLine1 = String(req.body?.address_line1 || '').trim();
  const addressLine2 = String(req.body?.address_line2 || '').trim();
  const city = String(req.body?.city || '').trim();
  const state = String(req.body?.state || '').trim();
  const zip = String(req.body?.zip || '').trim();

  const ssnRaw = String(req.body?.ssn || '').trim();

  // Allow updating other fields without re-entering SSN.
  let ssnCiphertext = existing?.ssn_ciphertext ? String(existing.ssn_ciphertext) : null;
  let ssnLast4Val = existing?.ssn_last4 ? String(existing.ssn_last4) : null;

  if (ssnRaw) {
    const digits = digitsOnly(ssnRaw);
    if (digits.length !== 9) {
      res.status(400).json({ error: 'ssn must be 9 digits' });
      return;
    }

    const enc = encryptString(digits);
    if (!enc) {
      res.status(400).json({ error: 'APP_DATA_ENCRYPTION_KEY is not set (required to store SSN)' });
      return;
    }

    ssnCiphertext = enc;
    ssnLast4Val = ssnLast4(digits);
  }

  if (!fullName || !phone || !dateOfBirth || !addressLine1 || !city || !state || !zip) {
    res.status(400).json({ error: 'missing_required_fields' });
    return;
  }

  if (!ssnCiphertext) {
    res.status(400).json({ error: 'ssn_required' });
    return;
  }

  const status = 'submitted';

  await upsertUserCompliance({
    userId: req.user.id,
    fullName,
    email: req.user.email,
    phone,
    dateOfBirth,
    ssnLast4: ssnLast4Val,
    ssnCiphertext,
    addressLine1,
    addressLine2: addressLine2 || null,
    city,
    state,
    zip,
    status,
  });

  createAuditEvent({
    userId: req.user.id,
    type: 'user.compliance.saved',
    payload: { status },
  });

  res.status(200).json({ ok: true, status });
});

app.post(
  '/api/compliance/documents',
  requireAuthApi,
  upload.single('file'),
  async (req, res) => {
    if (!env('INCREASE_API_KEY')) {
      res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
      return;
    }

    const kind = String(req.body?.kind || '').trim();
    const allowed = new Set(['id_card', 'proof_of_address']);

    if (!allowed.has(kind)) {
      res.status(400).json({ error: 'invalid_document_kind' });
      return;
    }

    if (!req.file) {
      res.status(400).json({ error: 'file is required' });
      return;
    }

    try {
      const increase = createIncreaseClient();

      const purpose = kind === 'id_card' ? 'identity_document' : 'entity_supplemental_document';
      const created = await increase.createFile({
        fileBuffer: req.file.buffer,
        filename: req.file.originalname,
        mimeType: req.file.mimetype,
        purpose,
        description: kind,
      });

      await addUserComplianceDocument({
        userId: req.user.id,
        kind,
        fileId: String(created?.id || ''),
        filename: req.file.originalname,
        mimeType: req.file.mimetype,
      });

      createAuditEvent({
        userId: req.user.id,
        type: 'user.compliance.document_uploaded',
        payload: { kind, file_id: created?.id },
      });

      res.status(201).json(created);
    } catch (err) {
      res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
    }
  }
);

app.post('/api/onboarding/provision', requireAuthApi, async (req, res) => {
  if (!env('INCREASE_API_KEY')) {
    res.status(400).json({ error: 'INCREASE_API_KEY is not set' });
    return;
  }

  // The program is platform-level.
  // Each end-user gets their own natural-person Entity, and their Account is owned by that Entity.
  const programId = env('INCREASE_PROGRAM_ID');
  const allowSharedEntityFallback = parseBool(env('INCREASE_ALLOW_SHARED_ENTITY_FALLBACK'), false);
  const platformEntityId = env('INCREASE_ENTITY_ID');

  if (!programId) {
    res.status(400).json({ error: 'INCREASE_PROGRAM_ID must be set' });
    return;
  }

  if (allowSharedEntityFallback && !platformEntityId) {
    res.status(400).json({
      error: 'INCREASE_ENTITY_ID must be set when INCREASE_ALLOW_SHARED_ENTITY_FALLBACK=true',
    });
    return;
  }

  const compliance = await getUserCompliance(req.user.id);
  const docs = await listUserComplianceDocuments(req.user.id, 50);

  const hasId = docs.some((d) => String(d.kind || '') === 'id_card');
  const hasProof = docs.some((d) => String(d.kind || '') === 'proof_of_address');

  if (!compliance?.full_name || !compliance?.date_of_birth || !compliance?.ssn_ciphertext) {
    res.status(400).json({ error: 'compliance_incomplete' });
    return;
  }

  if (!hasId || !hasProof) {
    res.status(400).json({ error: 'documents_incomplete', missing: [!hasId ? 'id_card' : null, !hasProof ? 'proof_of_address' : null].filter(Boolean) });
    return;
  }

  const existing = await getUserIncrease(req.user.id);

  const increase = createIncreaseClient();

  let userEntityId = existing?.entity_id ? String(existing.entity_id).trim() : '';
  let accountId = existing?.account_id ? String(existing.account_id).trim() : '';
  let accountNumberId = existing?.account_number_id ? String(existing.account_number_id).trim() : '';
  let lockboxId = existing?.lockbox_id ? String(existing.lockbox_id).trim() : '';

  try {
    if (!userEntityId) {
      const ssnDigits = decryptString(String(compliance.ssn_ciphertext || ''));
      if (!ssnDigits || ssnDigits.length !== 9) {
        res.status(400).json({ error: 'unable_to_decrypt_ssn' });
        return;
      }

      const fileIds = docs
        .map((d) => String(d?.file_id || '').trim())
        .filter(Boolean);

      const entityBody = {
        structure: 'natural_person',
        natural_person: {
          name: String(compliance.full_name || '').trim(),
          date_of_birth: String(compliance.date_of_birth || '').trim(),
          identification: {
            method: 'social_security_number',
            number: ssnDigits,
          },
          address: {
            line1: String(compliance.address_line1 || '').trim(),
            ...(String(compliance.address_line2 || '').trim()
              ? { line2: String(compliance.address_line2 || '').trim() }
              : {}),
            city: String(compliance.city || '').trim(),
            state: String(compliance.state || '').trim().toUpperCase(),
            zip: String(compliance.zip || '').trim(),
          },
        },
      };

      try {
        const createdEntity = await increase.createEntity({
          body: entityBody,
          idempotencyKey: `user-${req.user.id}-entity-v2`,
        });
        userEntityId = String(createdEntity?.id || '').trim();

        if (!userEntityId) {
          res.status(500).json({ error: 'entity_create_failed' });
          return;
        }

        createAuditEvent({
          userId: req.user.id,
          type: 'increase.entity.created',
          payload: { id: userEntityId, structure: 'natural_person' },
        });

        // Attach documents (ID + proof of address) as entity supplemental documents.
        // Not all Increase accounts support `supplemental_documents` during entity creation.
        for (const fileId of fileIds) {
          try {
            await increase.createEntitySupplementalDocument({ entityId: userEntityId, fileId });
          } catch {
            // ignore
          }
        }

        await upsertUserIncrease({
          userId: req.user.id,
          entityId: userEntityId || null,
          accountId: accountId || null,
          accountNumberId: accountNumberId || null,
          lockboxId: lockboxId || null,
        });
      } catch (err) {
        const detail = String(err?.body?.detail || '');
        const unsupported =
          Number(err?.status) === 409 && detail.toLowerCase().includes('not supported for your account');

        if (unsupported && allowSharedEntityFallback) {
          // Proceed without a per-user entity; account will be owned by the platform entity.
          createAuditEvent({
            userId: req.user.id,
            type: 'increase.entity.create_skipped',
            payload: { reason: 'not_supported_for_account', platform_entity_id: platformEntityId },
          });
        } else if (unsupported) {
          res.status(409).json({
            error: 'increase_entity_create_not_supported',
            message:
              'Your Increase account does not support creating end-user entities via API. Ask Increase to enable it, or set INCREASE_ALLOW_SHARED_ENTITY_FALLBACK=true to provision accounts owned by the platform entity (not recommended for real money).',
            body: err?.body,
          });
          return;
        } else {
          throw err;
        }
      }
    }

    if (!accountId) {
      const accountEntityId = userEntityId || platformEntityId;

      if (!accountEntityId) {
        res.status(400).json({
          error: 'unable_to_select_account_entity',
          message:
            'Unable to provision an account because no entity is available. Set INCREASE_ALLOW_SHARED_ENTITY_FALLBACK=true + INCREASE_ENTITY_ID, or enable entity creation on your Increase account.',
        });
        return;
      }

      const createdAccount = await increase.createAccount({
        name: `DodoChecks - User ${req.user.id}`,
        entityId: accountEntityId,
        programId,
        idempotencyKey: `user-${req.user.id}-account`,
      });
      accountId = String(createdAccount?.id || '').trim();

      createAuditEvent({
        userId: req.user.id,
        type: 'increase.account.created',
        payload: { id: accountId, entity_id: accountEntityId, end_user_entity_id: userEntityId || null },
      });
    }

    if (accountId && !accountNumberId) {
      const createdAcctNum = await increase.createAccountNumber({
        accountId,
        name: 'Primary',
      });
      accountNumberId = String(createdAcctNum?.id || '').trim();

      createAuditEvent({
        userId: req.user.id,
        type: 'increase.account_number.created',
        payload: { id: accountNumberId, accountId },
      });
    }

    if (accountId && !lockboxId) {
      const createdLockbox = await increase.createLockbox({
        accountId,
        description: 'Personal lockbox',
        recipientName: String(compliance.full_name || '').trim() || undefined,
        idempotencyKey: `user-${req.user.id}-lockbox`,
      });
      lockboxId = String(createdLockbox?.id || '').trim();

      createAuditEvent({
        userId: req.user.id,
        type: 'increase.lockbox.created',
        payload: { id: lockboxId, accountId },
      });
    }

    await upsertUserIncrease({
      userId: req.user.id,
      entityId: userEntityId || null,
      accountId: accountId || null,
      accountNumberId: accountNumberId || null,
      lockboxId: lockboxId || null,
    });

    res.status(201).json({
      ok: true,
      entity_id: userEntityId || null,
      account_owner_entity_id: (userEntityId || platformEntityId) || null,
      account_id: accountId || null,
      account_number_id: accountNumberId || null,
      lockbox_id: lockboxId || null,
    });
  } catch (err) {
    res.status(Number(err?.status) || 500).json({ error: String(err?.message || err), body: err?.body });
  }
});

app.get('/signup', (req, res) => {
  const payload = getAuthPayload(req);
  if (payload?.sub) {
    res.redirect('/app/overview');
    return;
  }

  const next = safeNextUrl(req.query.next);
  res.type('html').send(renderAuthPage({ mode: 'signup', next }));
});

app.post('/signup', async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || '');
  const next = safeNextUrl(req.body.next);

  if (!email) {
    res.type('html').send(renderAuthPage({ mode: 'signup', error: 'Email is required.', next, email }));
    return;
  }

  if (password.length < 8) {
    res
      .type('html')
      .send(renderAuthPage({ mode: 'signup', error: 'Password must be at least 8 characters.', next, email }));
    return;
  }

  try {
    const passwordHash = bcrypt.hashSync(password, 12);
    const userId = await createUser({ email, passwordHash });

    createAuditEvent({
      userId,
      type: 'user.signup',
      payload: { email },
    });

    setAuthCookie(res, { userId, email });
    res.redirect(next);
  } catch (err) {
    const msg = String(err && err.message ? err.message : err);
    const code = String(err && err.code ? err.code : '');

    const isDuplicateEmail =
      code === 'ER_DUP_ENTRY' ||
      msg.includes('Duplicate entry') ||
      msg.includes('UNIQUE') ||
      msg.includes('SQLITE_CONSTRAINT');

    const friendly = isDuplicateEmail ? 'That email is already in use.' : 'Something went wrong.';
    res.type('html').send(renderAuthPage({ mode: 'signup', error: friendly, next, email }));
  }
});

app.get('/login', (req, res) => {
  const payload = getAuthPayload(req);
  if (payload?.sub) {
    res.redirect('/app/overview');
    return;
  }

  const next = safeNextUrl(req.query.next);
  res.type('html').send(renderAuthPage({ mode: 'login', next }));
});

app.post('/login', async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || '');
  const next = safeNextUrl(req.body.next);

  try {
    const user = email ? await getUserByEmail(email) : null;
    if (!user) {
      res.type('html').send(renderAuthPage({ mode: 'login', error: 'Invalid email or password.', next, email }));
      return;
    }

    const ok = bcrypt.compareSync(password, String(user.password_hash));
    if (!ok) {
      res.type('html').send(renderAuthPage({ mode: 'login', error: 'Invalid email or password.', next, email }));
      return;
    }

    createAuditEvent({
      userId: Number(user.id),
      type: 'user.login',
      payload: { email },
    });

    setAuthCookie(res, { userId: Number(user.id), email: String(user.email) });
    res.redirect(next);
  } catch {
    res.type('html').send(renderAuthPage({ mode: 'login', error: 'Something went wrong.', next, email }));
  }
});

app.post('/logout', (req, res) => {
  clearAuthCookie(res);
  res.redirect('/');
});

app.get('/app', requireAuth, (req, res) => {
  res.redirect('/app/overview');
});

const APP_PAGES = {
  overview: { title: 'Overview', key: 'overview' },
  transactions: { title: 'Transactions', key: 'transactions' },
  transfers: { title: 'Transfers', key: 'transfers' },
  'external-accounts': { title: 'External Accounts', key: 'external-accounts' },
  lockboxes: { title: 'Lockboxes', key: 'lockboxes' },
  documents: { title: 'Documents', key: 'documents' },
  compliance: { title: 'Compliance', key: 'compliance' },
};

app.get('/app/cards/:cardId', requireAuth, async (req, res) => {
  const cardId = String(req.params.cardId || '').trim();
  if (!cardId) {
    res.status(404).type('text/plain').send('Not found');
    return;
  }

  const hasIncrease = Boolean(env('INCREASE_API_KEY'));

  let title = 'Card';
  let subtitle = 'Card details';
  let actionsHtml = `<a class="btn" href="/app/cards">Back</a>`;
  let content = '';

  function formatBillingAddress(addr) {
    if (!addr || typeof addr !== 'object') return '';
    const line1 = String(addr.line1 || '').trim();
    const line2 = String(addr.line2 || '').trim();
    const city = String(addr.city || '').trim();
    const state = String(addr.state || '').trim();
    const postal = String(addr.postal_code || '').trim();

    const street = [line1, line2].filter(Boolean).join(', ');
    const locality = [city, state, postal].filter(Boolean).join(' ');
    return [street, locality].filter(Boolean).join(', ');
  }

  function findCardIdDeep(value, depth) {
    const d = typeof depth === 'number' ? depth : 0;
    if (d > 6) return null;

    if (!value) return null;

    if (typeof value === 'object') {
      if (Array.isArray(value)) {
        for (const item of value) {
          const found = findCardIdDeep(item, d + 1);
          if (found) return found;
        }
        return null;
      }

      for (const [k, v] of Object.entries(value)) {
        if (k === 'card_id' && typeof v === 'string' && v.trim()) {
          return String(v).trim();
        }
        const found = findCardIdDeep(v, d + 1);
        if (found) return found;
      }
    }

    return null;
  }

  if (!hasIncrease) {
    content = `
      <section class="card">
        <h2>Card</h2>
        <p class="muted" style="margin: 0;">Set <code>INCREASE_API_KEY</code> in your .env to load card data.</p>
      </section>
    `;

    res.type('html').send(
      renderAppLayout({
        title,
        subtitle,
        activeKey: 'cards',
        user: req.user,
        content,
        actionsHtml,
      })
    );
    return;
  }

  const increase = createIncreaseClient();

  try {
    const card = await increase.retrieveCard({ cardId });

    const id = String(card?.id || cardId).trim();
    const description = String(card?.description || '').trim();

    title = description || 'Unnamed card';

    const statusRaw = String(card?.status || '').trim();
    const statusLabel = humanizeEnum(statusRaw) || statusRaw || '—';
    const statusLower = statusRaw.toLowerCase();

    const statusChecked = statusLower === 'active';
    const isTerminal = ['canceled', 'cancelled', 'terminated', 'closed'].includes(statusLower);
    const canToggleStatus = !isTerminal;

    const dotClass = `tx-dot ${cardStatusClass(statusRaw)}`;

    const brand = String(card?.brand || card?.network || '').trim();
    const cardProfile = String(
      card?.card_profile_id || card?.digital_card_profile_id || card?.digital_card_profile?.id || ''
    ).trim();

    const billingObj = card?.billing_address && typeof card.billing_address === 'object' ? card.billing_address : null;
    const billingLine1 = String(billingObj?.line1 || '').trim();
    const billingLine2 = String(billingObj?.line2 || '').trim();
    const billingCity = String(billingObj?.city || '').trim();
    const billingState = String(billingObj?.state || '').trim();
    const billingPostal = String(billingObj?.postal_code || '').trim();
    const billingDisplay = formatBillingAddress(billingObj);

    const createdAt = formatShortDateTime(card?.created_at || '');

    const accountId = String(card?.account_id || '').trim();

    // Account name (best-effort)
    let accountName = accountId || '—';
    if (accountId) {
      try {
        const accountsResp = await increase.listAccounts();
        const accounts = extractDataArray(accountsResp);
        const found = accounts.find((a) => String(a?.id || '') === accountId);
        if (found) accountName = String(found.name || found.id || accountId);
      } catch {
        // ignore
      }
    }

    subtitle = [accountName ? `Account ${accountName}` : '', id ? `ID ${id}` : ''].filter(Boolean).join(' · ');

    // Transactions (best-effort): filter account transactions by card id.
    let txRows = [];
    let txError = null;

    if (accountId) {
      try {
        const q = { limit: 50, account_id: accountId };
        const [pendingResp, txsResp] = await Promise.all([
          increase.listPendingTransactions(q).catch(() => null),
          increase.listTransactions(q),
        ]);

        const pending = extractDataArray(pendingResp).map((t) => ({ tx: t, kind: 'pending' }));
        const completed = extractDataArray(txsResp).map((t) => ({ tx: t, kind: 'completed' }));

        const combined = pending.concat(completed);
        txRows = combined.filter((row) => {
          const direct = row?.tx && typeof row.tx === 'object' ? String(row.tx.card_id || '').trim() : '';
          const found = direct || findCardIdDeep(row?.tx, 0) || '';
          return found === id;
        });
      } catch (err) {
        txError = err;
      }
    }

    function renderCardTxRow(row) {
      const tx = row && typeof row === 'object' ? row.tx : null;
      const kind = row && typeof row === 'object' ? row.kind : '';

      const created = tx ? formatShortDateTime(tx.created_at || tx.created || '') : '';
      const desc = tx ? String(tx.description || tx.memo || tx.id || '') : '';
      const category = tx ? getTxCategory(tx) : 'Transaction';
      const amountCents = tx ? getTxAmountCents(tx) : null;
      const amount = amountCents == null ? '—' : formatUsdFromCents(amountCents);
      const neg = typeof amountCents === 'number' && amountCents < 0;

      const dot = kind === 'pending' ? 'tx-dot pending' : 'tx-dot completed';

      const additional = accountName || accountId || '—';

      return `
        <div class="tx-row">
          <div class="tx-created"><span class="${dot}" aria-hidden="true"></span>${esc(created || '—')}</div>
          <div class="tx-desc">${esc(desc || '—')}</div>
          <div class="tx-acct">${esc(additional)}</div>
          <div class="tx-cat">${esc(category)}</div>
          <div class="tx-amt${neg ? ' neg' : ''}">${esc(amount)}</div>
        </div>
      `;
    }

    const txErrorHtml = txError
      ? `<div class="alert" role="alert"><strong>Increase:</strong> ${esc(String(txError.message || 'error'))}</div>`
      : '';

    const txTableRows = txRows.map((r) => renderCardTxRow(r)).join('');
    const txEmpty = !txTableRows ? '<div class="tx-empty">No transactions found.</div>' : '';

    const detailsCard = `
      <section class="card">
        <h2>Details</h2>
        <div class="alert" data-inline-error hidden></div>

        <div class="kv">
          <div class="k">Card status</div>
          <div class="v">
            <label class="toggle">
              <input type="checkbox" data-toggle="card-status" data-card-id="${esc(id)}"${
                statusChecked ? ' checked' : ''
              }${canToggleStatus ? '' : ' disabled'} />
              <span class="toggle-track" aria-hidden="true"><span class="toggle-thumb"></span></span>
              <span class="toggle-text"><span class="${dotClass}" aria-hidden="true"></span> ${esc(statusLabel)}</span>
            </label>
          </div>

          <div class="k">Description</div>
          <div class="v" style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;">
            <span>${esc(description || '—')}</span>
            <button class="link" type="button" data-open-modal="card-edit-description">Edit</button>
          </div>

          <div class="k">Card brand</div>
          <div class="v">${esc(brand || '—')}</div>

          <div class="k">Card profile</div>
          <div class="v">${cardProfile ? `<code>${esc(cardProfile)}</code>` : '—'}</div>

          <div class="k">Billing address</div>
          <div class="v" style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;">
            <span>${esc(billingDisplay || '—')}</span>
            <button class="link" type="button" data-open-modal="card-edit-billing">Edit</button>
          </div>

          <div class="k">Email</div>
          <div class="v">—</div>

          <div class="k">Phone</div>
          <div class="v">—</div>
        </div>
      </section>
    `;

    const physicalCardsCard = `
      <section class="card">
        <h2>Physical Cards</h2>
        <p class="small" style="margin: 0;">No physical cards. You can order a physical card (coming soon).</p>
      </section>
    `;

    const walletTokensCard = `
      <section class="card">
        <h2>Digital Wallet Tokens</h2>
        <p class="small" style="margin: 0;">No digital wallet tokens. Digital wallet tokens will appear here.</p>
      </section>
    `;

    const transactionsCard = `
      <section class="card">
        <h2>Transactions</h2>
        ${txErrorHtml}
        <div class="tx-table" role="table" aria-label="Card transactions">
          <div class="tx-head" role="row">
            <div role="columnheader">Created</div>
            <div role="columnheader">Description</div>
            <div role="columnheader">Additional info</div>
            <div role="columnheader">Category</div>
            <div role="columnheader" style="text-align:right;">Amount</div>
          </div>
          ${txTableRows}
          ${txEmpty}
        </div>
      </section>
    `;

    const summaryCard = `
      <section class="card">
        <h2>Summary</h2>
        <div class="kv">
          <div class="k">Account</div>
          <div class="v">${esc(accountName || accountId || '—')}</div>

          <div class="k">Card</div>
          <div class="v">${esc(formatCardSummary(card) || '—')}</div>

          <div class="k">Created</div>
          <div class="v">${esc(createdAt || '—')}</div>

          <div class="k">ID</div>
          <div class="v"><code>${esc(id)}</code></div>
        </div>
      </section>
    `;

    const editDescriptionModal = `
      <div class="modal" data-modal="card-edit-description" hidden>
        <div class="modal-backdrop" data-close-modal></div>
        <div class="modal-card" role="dialog" aria-modal="true" aria-label="Edit card description">
          <div class="modal-head">
            <h2>Edit description</h2>
            <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
          </div>

          <form class="form" data-form="card-update-description">
            <input type="hidden" name="card_id" value="${esc(id)}" />

            <label class="field">
              <span>Description</span>
              <input name="description" type="text" placeholder="e.g. Office expenses" value="${esc(description)}" />
            </label>

            <div class="modal-actions">
              <button class="btn" type="button" data-close-modal>Cancel</button>
              <button class="btn-primary" type="submit">Save</button>
            </div>

            <div class="modal-error small" data-modal-error hidden></div>
          </form>
        </div>
      </div>


    `;

    const editBillingModal = `
      <div class="modal" data-modal="card-edit-billing" hidden>
        <div class="modal-backdrop" data-close-modal></div>
        <div class="modal-card" role="dialog" aria-modal="true" aria-label="Edit billing address">
          <div class="modal-head">
            <h2>Edit billing address</h2>
            <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
          </div>

          <form class="form" data-form="card-update-billing-address">
            <input type="hidden" name="card_id" value="${esc(id)}" />

            <label class="field">
              <span>Line 1</span>
              <input name="line1" type="text" value="${esc(billingLine1)}" />
            </label>

            <label class="field">
              <span>Line 2 (optional)</span>
              <input name="line2" type="text" value="${esc(billingLine2)}" />
            </label>

            <label class="field">
              <span>City</span>
              <input name="city" type="text" value="${esc(billingCity)}" />
            </label>

            <label class="field">
              <span>State</span>
              <input name="state" type="text" value="${esc(billingState)}" />
            </label>

            <label class="field">
              <span>Postal code</span>
              <input name="postal_code" type="text" value="${esc(billingPostal)}" />
            </label>

            <div class="modal-actions">
              <button class="btn" type="button" data-close-modal>Cancel</button>
              <button class="btn-primary" type="submit">Save</button>
            </div>

            <div class="modal-error small" data-modal-error hidden></div>
          </form>

          <p class="small" style="margin: 10px 2px 0;">Leave all fields blank to clear the billing address.</p>
        </div>
      </div>
    `;

    content = `
      <section class="grid">
        <div style="display:grid; gap: 14px;">
          ${detailsCard}
          ${physicalCardsCard}
          ${walletTokensCard}
          ${transactionsCard}
        </div>
        ${summaryCard}
      </section>

      ${editDescriptionModal}
      ${editBillingModal}
    `;
  } catch (err) {
    content = `
      <section class="card">
        <h2>Card</h2>
        <div class="alert" role="alert"><strong>Increase:</strong> ${esc(String(err?.message || 'error'))}</div>
        <p class="muted" style="margin: 0;">Check the card id and your API key, then try again.</p>
      </section>
    `;
  }

  res.type('html').send(
    renderAppLayout({
      title,
      subtitle,
      activeKey: 'cards',
      user: req.user,
      content,
      actionsHtml,
    })
  );
});

app.get('/app/account-numbers/:accountNumberId', requireAuth, async (req, res) => {
  const accountNumberId = String(req.params.accountNumberId || '').trim();
  if (!accountNumberId) {
    res.status(404).type('text/plain').send('Not found');
    return;
  }

  const hasIncrease = Boolean(env('INCREASE_API_KEY'));

  let title = 'Account number';
  let subtitle = 'Account number details';
  let actionsHtml = `<a class="btn" href="/app/account-numbers">Back</a>`;
  let content = '';

  function inboundChecksLabel(status) {
    const s = String(status || '').trim();
    if (s === 'check_transfers_only') return 'Only when a Check Transfer exists';
    return humanizeEnum(s) || s || '—';
  }

  function inboundAchDebitLabel(status) {
    const s = String(status || '').trim();
    return humanizeEnum(s) || s || '—';
  }

  function inboundAchTransferStatusClass(status) {
    const s = String(status || '').trim().toLowerCase();
    if (!s) return 'pending';
    if (s === 'accepted') return 'completed';
    if (s === 'declined') return 'failed';
    return 'pending';
  }

  if (!hasIncrease) {
    content = `
      <section class="card">
        <h2>Account number</h2>
        <p class="muted" style="margin: 0;">Set <code>INCREASE_API_KEY</code> in your .env to load account number data.</p>
      </section>
    `;

    res.type('html').send(
      renderAppLayout({
        title,
        subtitle,
        activeKey: 'account-numbers',
        user: req.user,
        content,
        actionsHtml,
      })
    );
    return;
  }

  const increase = createIncreaseClient();

  try {
    const an = await increase.retrieveAccountNumber({ accountNumberId });

    const id = String(an?.id || accountNumberId).trim();
    const name = String(an?.name || '').trim();
    const statusRaw = String(an?.status || '').trim();

    const inboundAchDebitRaw = String(an?.inbound_ach?.debit_status || '').trim();
    const inboundChecksRaw = String(an?.inbound_checks?.status || '').trim();

    const routingNumber = String(an?.routing_number || '').trim();
    const accountNumber = String(an?.account_number || '').trim();

    const accountId = String(an?.account_id || '').trim();

    title = name || 'Account number';
    subtitle = [accountId ? `Account ${accountId}` : '', id ? `ID ${id}` : ''].filter(Boolean).join(' · ');

    // Accounts (best-effort) - used for Account display and ACH transfer source selection.
    let accounts = [];
    try {
      const accountsResp = await increase.listAccounts();
      accounts = extractDataArray(accountsResp);
    } catch {
      accounts = [];
    }

    // Account name (best-effort)
    let accountName = accountId || '—';
    if (accountId) {
      const found = accounts.find((a) => String(a?.id || '') === accountId);
      if (found) {
        accountName = String(found.name || found.id || accountId);
      }
    }

    const accountOptionsHtml = accounts
      .map((a) => {
        const label = String(a.name || a.id || 'Account');
        const aid = String(a.id || '');
        return `<option value="${esc(aid)}">${esc(label)}</option>`;
      })
      .join('');

    const canToggleStatus = statusRaw !== 'canceled';
    const statusChecked = statusRaw === 'active';
    const statusText = statusRaw ? humanizeEnum(statusRaw) : '—';

    const achChecked = inboundAchDebitRaw === 'allowed';
    const achText = inboundAchDebitRaw ? inboundAchDebitLabel(inboundAchDebitRaw) : '—';

    const inboundChecksText = inboundChecksRaw ? inboundChecksLabel(inboundChecksRaw) : '—';

    const canSendAch = Boolean(routingNumber && accountNumber && accountOptionsHtml);
    const sendAchBtn = canSendAch
      ? '<button class="btn-primary" type="button" data-open-modal="send-ach">Send ACH</button>'
      : `<button class="btn-primary" type="button" disabled title="${
          accounts.length ? 'Missing routing/account number' : 'No accounts loaded yet'
        }">Send ACH</button>`;

    actionsHtml = `<a class="btn" href="/app/account-numbers">Back</a>${sendAchBtn}`;

    // Transactions (Inbound ACH transfers for this account number)
    let inboundTransfers = [];
    let transfersError = null;

    try {
      const transfersResp = await increase.listInboundAchTransfers({ limit: 50, account_number_id: id });
      inboundTransfers = extractDataArray(transfersResp);
    } catch (err) {
      transfersError = err;
    }

    function renderInboundTransferRow(t) {
      const created = formatShortDateTime(t.created_at || t.created || '');
      const statusRawT = String(t.status || '').trim();
      const dotClass = `tx-dot ${inboundAchTransferStatusClass(statusRawT)}`;

      const desc = String(
        t.originator_company_entry_description ||
          t.originator_company_name ||
          t.description ||
          t.id ||
          ''
      ).trim();

      const additional = String(t.receiver_name || name || '').trim();

      const amtCents = typeof t.amount === 'number' ? t.amount : null;
      const amt = amtCents == null ? '—' : formatUsdFromCents(amtCents);

      const category = 'Inbound ACH Transfer';
      const statusLabel = humanizeEnum(statusRawT) || statusRawT || '';

      return `
        <div class="tx-row">
          <div class="tx-created"><span class="${dotClass}" aria-hidden="true"></span>${esc(created || '—')}</div>
          <div class="tx-desc">${esc(desc || '—')}</div>
          <div class="tx-acct">${esc(additional || '—')}</div>
          <div class="tx-cat">${esc(category)}${statusLabel ? ` <span class="muted">${esc(statusLabel)}</span>` : ''}</div>
          <div class="tx-amt">${esc(amt)}</div>
        </div>
      `;
    }

    const transfersErrorHtml = transfersError
      ? `<div class="alert" role="alert"><strong>Increase:</strong> ${esc(String(transfersError.message || 'error'))}</div>`
      : '';

    const transferRows = inboundTransfers.map((t) => renderInboundTransferRow(t)).join('');
    const transferEmptyState = !transferRows ? '<div class="tx-empty">No inbound ACH transfers yet.</div>' : '';

    const detailsCard = `
      <section class="card">
        <h2>Details</h2>
        <div class="alert" data-inline-error hidden></div>
        <div class="kv">
          <div class="k">Name</div>
          <div class="v" style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;">
            <span>${esc(name || '—')}</span>
            <button class="link" type="button" data-open-modal="account-number-edit-name">Edit</button>
          </div>

          <div class="k">Status</div>
          <div class="v">
            <label class="toggle">
              <input type="checkbox" data-toggle="account-number-status" data-account-number-id="${esc(id)}"${
                statusChecked ? ' checked' : ''
              }${canToggleStatus ? '' : ' disabled'} />
              <span class="toggle-track" aria-hidden="true"><span class="toggle-thumb"></span></span>
              <span class="toggle-text">${esc(statusText)}</span>
            </label>
          </div>

          <div class="k">Allow ACH debits</div>
          <div class="v">
            <label class="toggle">
              <input type="checkbox" data-toggle="account-number-ach-debits" data-account-number-id="${esc(id)}"${
                achChecked ? ' checked' : ''
              } />
              <span class="toggle-track" aria-hidden="true"><span class="toggle-thumb"></span></span>
              <span class="toggle-text">${esc(achText)}</span>
            </label>
          </div>

          <div class="k">Allows inbound check deposits</div>
          <div class="v" style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;">
            <span>${esc(inboundChecksText)}</span>
            <button class="link" type="button" data-open-modal="account-number-edit-inbound-checks">Edit</button>
          </div>
        </div>
      </section>
    `;

    const transactionsCard = `
      <section class="card">
        <div class="tx-toolbar">
          <h2 style="margin:0;">Transactions</h2>
        </div>
        ${transfersErrorHtml}
        <div class="tx-table" role="table" aria-label="Inbound ACH transfers">
          <div class="tx-head" role="row">
            <div role="columnheader">Created</div>
            <div role="columnheader">Description</div>
            <div role="columnheader">Additional info</div>
            <div role="columnheader">Category</div>
            <div role="columnheader" style="text-align:right;">Amount</div>
          </div>
          ${transferRows}
          ${transferEmptyState}
        </div>
      </section>
    `;

    const summaryCard = `
      <section class="card">
        <h2>Summary</h2>
        <div class="kv">
          <div class="k">Routing number</div>
          <div class="v">${routingNumber ? `<code>${esc(routingNumber)}</code>` : '—'}</div>

          <div class="k">Account number</div>
          <div class="v">${accountNumber ? `<code>${esc(accountNumber)}</code>` : '—'}</div>

          <div class="k">Account</div>
          <div class="v">${esc(accountName || '—')}</div>

          <div class="k">Created</div>
          <div class="v">${esc(formatShortDateTime(an?.created_at || '') || '—')}</div>

          <div class="k">ID</div>
          <div class="v"><code>${esc(id)}</code></div>
        </div>
      </section>
    `;

    const editNameModal = `
      <div class="modal" data-modal="account-number-edit-name" hidden>
        <div class="modal-backdrop" data-close-modal></div>
        <div class="modal-card" role="dialog" aria-modal="true" aria-label="Edit account number name">
          <div class="modal-head">
            <h2>Edit name</h2>
            <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
          </div>

          <form class="form" data-form="account-number-update-name">
            <input type="hidden" name="account_number_id" value="${esc(id)}" />

            <label class="field">
              <span>Name</span>
              <input name="name" type="text" required value="${esc(name)}" />
            </label>

            <div class="modal-actions">
              <button class="btn" type="button" data-close-modal>Cancel</button>
              <button class="btn-primary" type="submit">Save</button>
            </div>

            <div class="modal-error small" data-modal-error hidden></div>
          </form>
        </div>
      </div>

    `;

    const editInboundChecksModal = `
      <div class="modal" data-modal="account-number-edit-inbound-checks" hidden>
        <div class="modal-backdrop" data-close-modal></div>
        <div class="modal-card" role="dialog" aria-modal="true" aria-label="Edit inbound check deposits">
          <div class="modal-head">
            <h2>Inbound check deposits</h2>
            <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
          </div>

          <form class="form" data-form="account-number-update-inbound-checks">
            <input type="hidden" name="account_number_id" value="${esc(id)}" />

            <label class="field">
              <span>Status</span>
              <select name="status" required>
                <option value="allowed"${inboundChecksRaw === 'allowed' ? ' selected' : ''}>Allowed</option>
                <option value="check_transfers_only"${inboundChecksRaw === 'check_transfers_only' ? ' selected' : ''}>Only when a Check Transfer exists</option>
              </select>
            </label>

            <div class="modal-actions">
              <button class="btn" type="button" data-close-modal>Cancel</button>
              <button class="btn-primary" type="submit">Save</button>
            </div>

            <div class="modal-error small" data-modal-error hidden></div>
          </form>
        </div>
      </div>
    `;

    const sendAchModal = `
      <div class="modal" data-modal="send-ach" hidden>
        <div class="modal-backdrop" data-close-modal></div>
        <div class="modal-card" role="dialog" aria-modal="true" aria-label="Send ACH">
          <div class="modal-head">
            <h2>Send ACH</h2>
            <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
          </div>

          <form class="form" data-form="ach-transfer">
            <input type="hidden" name="direction" value="credit" />

            <label class="field">
              <span>From account</span>
              <select name="account_id" required>
                <option value="">Select an account</option>
                ${accountOptionsHtml}
              </select>
            </label>

            <label class="field">
              <span>Routing number</span>
              <input name="routing_number" type="text" inputmode="numeric" required readonly value="${esc(routingNumber)}" />
            </label>

            <label class="field">
              <span>Account number</span>
              <input name="account_number" type="text" inputmode="numeric" required readonly value="${esc(accountNumber)}" />
            </label>

            <label class="field">
              <span>Amount (USD)</span>
              <input name="amount_usd" type="number" step="0.01" min="0.01" placeholder="10.00" required />
            </label>

            <label class="field">
              <span>Statement descriptor</span>
              <input name="statement_descriptor" type="text" placeholder="Dodo Checks" value="Dodo Checks" />
            </label>

            <div class="modal-actions">
              <button class="btn" type="button" data-close-modal>Cancel</button>
              <button class="btn-primary" type="submit">Send</button>
            </div>

            <div class="modal-error small" data-modal-error hidden></div>
          </form>

          <p class="small" style="margin: 10px 2px 0;">This creates a real ACH transfer via Increase.</p>
        </div>
      </div>
    `;

    content = `
      <section class="grid">
        <div style="display:grid; gap: 14px;">
          ${detailsCard}
          ${transactionsCard}
        </div>
        ${summaryCard}
      </section>

      ${editNameModal}
      ${editInboundChecksModal}
      ${sendAchModal}
    `;
  } catch (err) {
    content = `
      <section class="card">
        <h2>Account number</h2>
        <div class="alert" role="alert"><strong>Increase:</strong> ${esc(String(err?.message || 'error'))}</div>
        <p class="muted" style="margin: 0;">Check the account number id and your API key, then try again.</p>
      </section>
    `;
  }

  res.type('html').send(
    renderAppLayout({
      title,
      subtitle,
      activeKey: 'account-numbers',
      user: req.user,
      content,
      actionsHtml,
    })
  );
});

app.get('/app/transactions/:transactionId', requireAuth, async (req, res) => {
  const transactionId = String(req.params.transactionId || '').trim();
  if (!transactionId) {
    res.status(404).type('text/plain').send('Not found');
    return;
  }

  const hasIncrease = Boolean(env('INCREASE_API_KEY'));

  let title = 'Transaction';
  let subtitle = 'Transaction details';
  let actionsHtml = `<a class="btn" href="/app/transactions">Back</a>`;
  let content = '';

  if (!hasIncrease) {
    content = `
      <section class="card">
        <h2>Transaction</h2>
        <p class="muted" style="margin: 0;">Set <code>INCREASE_API_KEY</code> in your .env to load transaction data.</p>
      </section>
    `;

    res.type('html').send(
      renderAppLayout({
        title,
        subtitle,
        activeKey: 'transactions',
        user: req.user,
        content,
        actionsHtml,
      })
    );
    return;
  }

  const userIncrease = await getUserIncrease(req.user.id);
  const accountId = userIncrease?.account_id ? String(userIncrease.account_id).trim() : '';

  if (!accountId) {
    content = `
      <section class="card">
        <h2>Transaction</h2>
        <p class="muted" style="margin: 0;">Finish compliance and provision your account to view transactions.</p>
        <div style="margin-top: 12px; display: flex; gap: 10px; flex-wrap: wrap;">
          <a class="btn-primary" href="/app/compliance">Go to Compliance</a>
          <a class="btn" href="/app/overview">Back to Overview</a>
        </div>
      </section>
    `;

    res.type('html').send(
      renderAppLayout({
        title,
        subtitle,
        activeKey: 'transactions',
        user: req.user,
        content,
        actionsHtml,
      })
    );
    return;
  }

  const increase = createIncreaseClient();

  let tx = null;
  let kind = 'completed';

  try {
    try {
      tx = await increase.retrieveTransaction({ transactionId });
      kind = 'completed';
    } catch (err) {
      if (Number(err?.status) === 404) {
        tx = await increase.retrievePendingTransaction({ pendingTransactionId: transactionId });
        kind = 'pending';
      } else {
        throw err;
      }
    }

    const txAccountId = String(tx?.account_id || '').trim();
    if (txAccountId && txAccountId !== accountId) {
      res.status(404).type('text/plain').send('Not found');
      return;
    }

    const id = String(tx?.id || transactionId).trim();
    const created = formatShortDateTime(tx?.created_at || tx?.created || '');
    const desc = String(tx?.description || tx?.memo || '').trim();

    const category = getTxCategory(tx);

    const amountCents = getTxAmountCents(tx);
    const amount = amountCents == null ? '—' : formatUsdFromCents(amountCents);
    const routeTypeRaw = String(tx?.route_type || '').trim();
    const routeTypeLabel = routeTypeRaw ? humanizeEnum(routeTypeRaw) : '';
    const routeId = String(tx?.route_id || '').trim();

    let routeIdHtml = routeId ? `<code>${esc(routeId)}</code>` : '—';
    if (routeId && routeTypeRaw === 'card') {
      routeIdHtml = `<a href="/app/cards/${encodeURIComponent(routeId)}"><code>${esc(routeId)}</code></a>`;
    } else if (routeId && routeTypeRaw === 'account_number') {
      routeIdHtml = `<a href="/app/account-numbers/${encodeURIComponent(routeId)}"><code>${esc(routeId)}</code></a>`;
    }

    const statusLabel = kind === 'pending' ? 'Pending' : 'Completed';
    const dotClass = kind === 'pending' ? 'tx-dot pending' : 'tx-dot completed';

    const sourceCategoryRaw = String(tx?.source?.category || '').trim();
    const sourceCategoryLabel = sourceCategoryRaw ? humanizeEnum(sourceCategoryRaw) : '';

    const cancelableTransferId = findCancelableTransferId(tx);
    const inboundAchTransferId = findInboundAchTransferId(tx);

    title = desc || category || 'Transaction';
    subtitle = [statusLabel, id ? `ID ${id}` : ''].filter(Boolean).join(' · ');

    const rawObj = tx?.source && typeof tx.source === 'object' ? tx.source : tx;
    const rawJson = esc(JSON.stringify(redactForUi(rawObj), null, 2));

    const detailsCard = `
      <section class="card">
        <h2>Details</h2>
        <div class="kv">
          <div class="k">Status</div>
          <div class="v"><span class="pill" style="display:inline-flex;align-items:center;gap:8px;"><span class="${dotClass}" aria-hidden="true"></span>${esc(statusLabel)}</span></div>

          <div class="k">Amount</div>
          <div class="v">${esc(amount)}</div>

          <div class="k">Category</div>
          <div class="v">${esc(category || '—')}</div>

          <div class="k">Description</div>
          <div class="v">${esc(desc || '—')}</div>

          <div class="k">Created</div>
          <div class="v">${esc(created || '—')}</div>

          <div class="k">Account</div>
          <div class="v"><code>${esc(String(tx?.account_id || accountId))}</code></div>

          <div class="k">Route</div>
          <div class="v">${routeTypeLabel ? `${esc(routeTypeLabel)} · ` : ''}${routeIdHtml}</div>

          <div class="k">Transaction ID</div>
          <div class="v"><code>${esc(id)}</code></div>

          <div class="k">Source</div>
          <div class="v">${esc(sourceCategoryLabel || sourceCategoryRaw || '—')}</div>
        </div>

        <details style="margin-top: 14px;">
          <summary class="btn">Raw source (sanitized)</summary>
          <pre class="small" style="white-space: pre-wrap; margin: 12px 0 0;">${rawJson}</pre>
        </details>
      </section>
    `;

    const actionButtons = [];

    if (kind === 'pending') {
      actionButtons.push(
        `<button class="btn-primary" type="button" data-open-modal="tx-release">Release pending transaction</button>`
      );
    }

    if (cancelableTransferId) {
      actionButtons.push(`<button class="btn" type="button" data-open-modal="tx-cancel">Cancel transfer</button>`);
    }

    if (inboundAchTransferId) {
      actionButtons.push(`<button class="btn" type="button" data-open-modal="tx-return-inbound-ach">Return inbound ACH</button>`);
    }

    const actionsCard = `
      <section class="card">
        <h2>Actions</h2>
        <div class="alert" data-inline-error hidden></div>

        ${
          actionButtons.length
            ? `<div style="display:flex; gap: 10px; flex-wrap: wrap;">${actionButtons.join('')}</div>`
            : '<div class="small">No actions available for this transaction.</div>'
        }

        ${
          cancelableTransferId
            ? `<div class="small" style="margin-top: 12px;">Transfer: <code>${esc(cancelableTransferId)}</code></div>`
            : ''
        }

        ${
          inboundAchTransferId
            ? `<div class="small" style="margin-top: 8px;">Inbound ACH: <code>${esc(inboundAchTransferId)}</code></div>`
            : ''
        }

        <p class="small" style="margin: 12px 2px 0;">These actions call real Increase endpoints. No simulations are available.</p>
      </section>
    `;

    const releaseModal =
      kind === 'pending'
        ? `
          <div class="modal" data-modal="tx-release" hidden>
            <div class="modal-backdrop" data-close-modal></div>
            <div class="modal-card" role="dialog" aria-modal="true" aria-label="Release pending transaction">
              <div class="modal-head">
                <h2>Release pending transaction</h2>
                <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
              </div>

              <p class="muted" style="margin: 0;">This will release the pending transaction in Increase.</p>

              <form class="form" data-form="tx-release">
                <input type="hidden" name="pending_transaction_id" value="${esc(id)}" />

                <div class="modal-actions">
                  <button class="btn" type="button" data-close-modal>Cancel</button>
                  <button class="btn-primary" type="submit">Release</button>
                </div>

                <div class="modal-error small" data-modal-error hidden></div>
              </form>
            </div>
          </div>
        `
        : '';

    const cancelModal =
      cancelableTransferId
        ? `
          <div class="modal" data-modal="tx-cancel" hidden>
            <div class="modal-backdrop" data-close-modal></div>
            <div class="modal-card" role="dialog" aria-modal="true" aria-label="Cancel transfer">
              <div class="modal-head">
                <h2>Cancel transfer</h2>
                <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
              </div>

              <p class="muted" style="margin: 0;">This will attempt to cancel the underlying transfer in Increase.</p>
              <p class="small" style="margin: 10px 2px 0;">Transfer: <code>${esc(cancelableTransferId)}</code></p>

              <form class="form" data-form="tx-cancel">
                <input type="hidden" name="transaction_id" value="${esc(id)}" />

                <div class="modal-actions">
                  <button class="btn" type="button" data-close-modal>Nevermind</button>
                  <button class="btn-primary" type="submit">Cancel transfer</button>
                </div>

                <div class="modal-error small" data-modal-error hidden></div>
              </form>
            </div>
          </div>
        `
        : '';

    const returnInboundAchModal =
      inboundAchTransferId
        ? `
          <div class="modal" data-modal="tx-return-inbound-ach" hidden>
            <div class="modal-backdrop" data-close-modal></div>
            <div class="modal-card" role="dialog" aria-modal="true" aria-label="Return inbound ACH">
              <div class="modal-head">
                <h2>Return inbound ACH</h2>
                <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
              </div>

              <p class="muted" style="margin: 0;">This will submit a return for the inbound ACH transfer in Increase.</p>
              <p class="small" style="margin: 10px 2px 0;">Inbound ACH: <code>${esc(inboundAchTransferId)}</code></p>

              <form class="form" data-form="tx-return-inbound-ach">
                <input type="hidden" name="transaction_id" value="${esc(id)}" />

                <label class="field">
                  <span>Reason</span>
                  <input name="reason" type="text" required placeholder="e.g. insufficient_funds" />
                </label>

                <div class="modal-actions">
                  <button class="btn" type="button" data-close-modal>Cancel</button>
                  <button class="btn-primary" type="submit">Return</button>
                </div>

                <div class="modal-error small" data-modal-error hidden></div>
              </form>

              <p class="small" style="margin: 10px 2px 0;">Reason must match Increase’s return reason enum.</p>
            </div>
          </div>
        `
        : '';

    content = `
      <section class="grid">
        ${detailsCard}
        ${actionsCard}
      </section>

      ${releaseModal}
      ${cancelModal}
      ${returnInboundAchModal}
    `;
  } catch (err) {
    content = `
      <section class="card">
        <h2>Transaction</h2>
        <div class="alert" role="alert"><strong>Increase:</strong> ${esc(String(err?.message || 'error'))}</div>
        <p class="muted" style="margin: 0;">Check the transaction id and your API key, then try again.</p>
      </section>
    `;
  }

  res.type('html').send(
    renderAppLayout({
      title,
      subtitle,
      activeKey: 'transactions',
      user: req.user,
      content,
      actionsHtml,
    })
  );
});

app.get('/app/compliance/:entityId', requireAuth, async (req, res) => {
  const entityId = String(req.params.entityId || '').trim();
  if (!entityId) {
    res.status(404).type('text/plain').send('Not found');
    return;
  }

  const hasIncrease = Boolean(env('INCREASE_API_KEY'));

  let title = 'Entity';
  let subtitle = 'Entity details';
  let actionsHtml = `<a class="btn" href="/app/compliance">Back</a>`;
  let content = '';

  function entityDisplayName(e) {
    if (!e || typeof e !== 'object') return '';

    const corpName = e.corporation && typeof e.corporation === 'object' ? String(e.corporation.name || '') : '';
    if (corpName) return corpName;

    const npName = e.natural_person && typeof e.natural_person === 'object' ? String(e.natural_person.name || '') : '';
    if (npName) return npName;

    const trustName = e.trust && typeof e.trust === 'object' ? String(e.trust.name || '') : '';
    if (trustName) return trustName;

    const govtName =
      e.government_authority && typeof e.government_authority === 'object'
        ? String(e.government_authority.name || '')
        : '';
    if (govtName) return govtName;

    // Joint entities may not have a single name.
    const joint = e.joint && typeof e.joint === 'object' ? e.joint : null;
    const individuals = Array.isArray(joint?.individuals) ? joint.individuals : [];
    const joined = individuals
      .map((i) => (i && typeof i === 'object' ? String(i.name || '').trim() : ''))
      .filter(Boolean)
      .join(' & ');
    if (joined) return joined;

    const desc = String(e.description || '').trim();
    if (desc) return desc;

    return String(e.id || '').trim();
  }

  function getEntityAddress(e) {
    if (!e || typeof e !== 'object') return null;

    if (e.address && typeof e.address === 'object') return e.address;

    const corp = e.corporation && typeof e.corporation === 'object' ? e.corporation : null;
    if (corp?.address && typeof corp.address === 'object') return corp.address;

    const np = e.natural_person && typeof e.natural_person === 'object' ? e.natural_person : null;
    if (np?.address && typeof np.address === 'object') return np.address;

    const trust = e.trust && typeof e.trust === 'object' ? e.trust : null;
    if (trust?.address && typeof trust.address === 'object') return trust.address;

    const govt = e.government_authority && typeof e.government_authority === 'object' ? e.government_authority : null;
    if (govt?.address && typeof govt.address === 'object') return govt.address;

    // As a fallback for joint entities, show the first individual's address.
    const joint = e.joint && typeof e.joint === 'object' ? e.joint : null;
    const first = Array.isArray(joint?.individuals) ? joint.individuals[0] : null;
    if (first && typeof first === 'object' && first.address && typeof first.address === 'object') return first.address;

    return null;
  }

  function addressField(addr, key, fallbackKey) {
    if (!addr || typeof addr !== 'object') return '';
    const v = addr[key] != null ? String(addr[key] || '').trim() : '';
    if (v) return v;
    if (!fallbackKey) return '';
    return addr[fallbackKey] != null ? String(addr[fallbackKey] || '').trim() : '';
  }

  function formatAddress(addr) {
    if (!addr || typeof addr !== 'object') return '';

    const line1 = addressField(addr, 'line1', 'line_1');
    const line2 = addressField(addr, 'line2', 'line_2');
    const city = addressField(addr, 'city');
    const state = addressField(addr, 'state');
    const zip = addressField(addr, 'zip', 'postal_code');

    const street = [line1, line2].filter(Boolean).join(', ');
    const locality = [city, state, zip].filter(Boolean).join(' ');

    return [street, locality].filter(Boolean).join(', ');
  }

  if (!hasIncrease) {
    title = 'Compliance';
    subtitle = `Entity ${entityId}`;
    content = `
      <section class="card">
        <h2>Entity</h2>
        <p class="muted" style="margin: 0;">Set <code>INCREASE_API_KEY</code> in your .env to load entity data.</p>
      </section>
    `;

    res.type('html').send(
      renderAppLayout({
        title,
        subtitle,
        activeKey: 'compliance',
        user: req.user,
        content,
        actionsHtml,
      })
    );
    return;
  }

  const increase = createIncreaseClient();

  try {
    const entity = await increase.retrieveEntity({ entityId });

    const id = String(entity?.id || entityId).trim();
    const name = entityDisplayName(entity) || id || 'Entity';

    title = name || 'Entity';

    const structureRaw = String(entity?.structure || '').trim();
    const structureLabel = humanizeEnum(structureRaw) || structureRaw || '—';

    const statusRaw = String(entity?.status || '').trim();
    const statusLabel = humanizeEnum(statusRaw) || statusRaw || '—';
    const statusDot = `tx-dot ${entityStatusClass(statusRaw)}`;

    const riskRaw =
      entity?.risk_rating && typeof entity.risk_rating === 'object' ? String(entity.risk_rating.rating || '').trim() : '';
    const riskLabel = riskRaw ? humanizeEnum(riskRaw) : 'Not rated';
    const riskDot = `tx-dot ${riskRatingClass(riskRaw)}`;

    const created = formatShortDateTime(entity?.created_at || '');
    const confirmed = formatShortDateTime(entity?.details_confirmed_at || '');

    const addrObj = getEntityAddress(entity);
    const addrLine1 = addressField(addrObj, 'line1', 'line_1');
    const addrLine2 = addressField(addrObj, 'line2', 'line_2');
    const addrCity = addressField(addrObj, 'city');
    const addrState = addressField(addrObj, 'state');
    const addrZip = addressField(addrObj, 'zip', 'postal_code');
    const addressDisplay = formatAddress(addrObj);

    const corp = entity?.corporation && typeof entity.corporation === 'object' ? entity.corporation : null;
    const industryCode = corp ? String(corp.industry_code || '').trim() : '';
    const showIndustryCode = structureRaw === 'corporation' || Boolean(industryCode);

    const owners = corp && Array.isArray(corp.beneficial_owners) ? corp.beneficial_owners : [];

    // Documents
    let docsError = null;
    let docs = [];

    try {
      const docsResp = await increase.listEntitySupplementalDocuments({ limit: 100, entity_id: id });
      docs = extractDataArray(docsResp);
    } catch (err) {
      docsError = err;
    }

    if (!docs.length && Array.isArray(entity?.supplemental_documents)) {
      docs = entity.supplemental_documents;
    }

    // Best-effort filter by entity
    docs = docs.filter((d) => {
      const docEntityId = d && typeof d === 'object' ? String(d.entity_id || '').trim() : '';
      if (!docEntityId) return true;
      return docEntityId === id;
    });

    const filesById = new Map();

    if (docs.length) {
      const uniqueFileIds = Array.from(
        new Set(
          docs
            .map((d) => (d && typeof d === 'object' ? String(d.file_id || '').trim() : ''))
            .filter(Boolean)
        )
      ).slice(0, 25);

      const fileMetas = await Promise.all(
        uniqueFileIds.map(async (fileId) => {
          try {
            return await increase.retrieveFile({ fileId });
          } catch {
            return null;
          }
        })
      );

      for (const f of fileMetas) {
        if (!f || typeof f !== 'object') continue;
        const fid = String(f.id || '').trim();
        if (!fid) continue;
        filesById.set(fid, f);
      }
    }

    subtitle = [
      structureLabel && structureLabel !== '—' ? structureLabel : '',
      statusLabel && statusLabel !== '—' ? statusLabel : '',
      id ? `ID ${id}` : '',
    ]
      .filter(Boolean)
      .join(' · ');

    const actionsMenu = `
      <details class="menu">
        <summary class="btn">Actions</summary>
        <div class="menu-panel" role="menu" aria-label="Entity actions">
          <button class="menu-item" type="button" role="menuitem" data-open-modal="entity-edit-address">
            <div class="menu-title">Edit address</div>
            <div class="menu-desc">Update the entity’s legal address.</div>
          </button>
          ${
            structureRaw === 'corporation'
              ? `
            <button class="menu-item" type="button" role="menuitem" data-open-modal="entity-edit-industry-code">
              <div class="menu-title">Edit industry code</div>
              <div class="menu-desc">Update the corporation’s industry code.</div>
            </button>
          `
              : ''
          }
          <button class="menu-item" type="button" role="menuitem" data-open-modal="entity-upload-document">
            <div class="menu-title">Upload document</div>
            <div class="menu-desc">Attach a supplemental document to this entity.</div>
          </button>
          <button class="menu-item" type="button" role="menuitem" data-open-modal="entity-archive">
            <div class="menu-title">Archive entity</div>
            <div class="menu-desc">Disable onboarding actions for this entity.</div>
          </button>
        </div>
      </details>
    `;

    actionsHtml = `<a class="btn" href="/app/compliance">Back</a>${actionsMenu}`;

    function renderOwnerItem(o) {
      const name = o && typeof o === 'object' ? String(o.name || '').trim() : '';
      const title = o && typeof o === 'object' ? String(o.title || '').trim() : '';
      const company = o && typeof o === 'object' ? String(o.company || '').trim() : '';

      const meta = [title, company].filter(Boolean).join(' · ');

      return `
        <li class="event">
          <div>
            <div class="type">${esc(name || 'Owner')}</div>
            <div class="meta">${esc(meta || 'Beneficial owner')}</div>
          </div>
          <span class="pill">Owner</span>
        </li>
      `;
    }

    function renderDocItem(d) {
      const createdAt = d && typeof d === 'object' ? formatShortDateTime(d.created_at || '') : '';
      const docId = d && typeof d === 'object' ? String(d.id || '').trim() : '';
      const fileId = d && typeof d === 'object' ? String(d.file_id || '').trim() : '';

      const statusRawDoc = d && typeof d === 'object' ? String(d.status || '').trim() : '';
      const statusLabelDoc = humanizeEnum(statusRawDoc) || statusRawDoc || 'Document';

      const fileMeta = fileId ? filesById.get(fileId) : null;
      const filename = fileMeta && typeof fileMeta === 'object' ? String(fileMeta.filename || '').trim() : '';
      const description = fileMeta && typeof fileMeta === 'object' ? String(fileMeta.description || '').trim() : '';

      const titleText = filename || description || (fileId ? `File ${fileId}` : docId ? `Document ${docId}` : 'Document');

      const metaParts = [];
      if (createdAt) metaParts.push(`Created ${createdAt}`);
      if (docId) metaParts.push(`Doc ${docId}`);
      if (fileId) metaParts.push(`File ${fileId}`);

      return `
        <li class="event">
          <div>
            <div class="type">${esc(titleText)}</div>
            <div class="meta">${esc(metaParts.join(' · ') || 'Supplemental document')}</div>
          </div>
          <span class="pill">${esc(statusLabelDoc)}</span>
        </li>
      `;
    }

    const ownersHtml = owners.length
      ? `
        <div style="margin-top: 16px;">
          <div style="font-weight: 900; margin-bottom: 10px;">Beneficial owners</div>
          <ul class="events">${owners.map((o) => renderOwnerItem(o)).join('')}</ul>
        </div>
      `
      : '';

    const docsErrorHtml = docsError
      ? `<div class="alert" role="alert"><strong>Documents:</strong> ${esc(String(docsError?.message || 'error'))}</div>`
      : '';

    const docsHtml = docs.length
      ? `
        ${docsErrorHtml}
        <ul class="events" style="margin-top: 12px;">${docs.map((d) => renderDocItem(d)).join('')}</ul>
        <p class="small" style="margin: 10px 2px 0;">Downloads aren’t wired up yet (we can add File Links next).</p>
      `
      : `
        ${docsErrorHtml}
        <div class="small" style="margin-top: 10px;">${docsError ? 'Unable to load documents for this entity.' : 'No documents uploaded yet.'}</div>
      `;

    const entityDetailsCard = `
      <section class="card">
        <h2>Entity details</h2>
        <div class="kv">
          <div class="k">Entity</div>
          <div class="v">${esc(name)}</div>

          <div class="k">Entity ID</div>
          <div class="v"><code>${esc(id)}</code></div>

          <div class="k">Status</div>
          <div class="v"><span class="pill" style="display:inline-flex;align-items:center;gap:8px;"><span class="${statusDot}" aria-hidden="true"></span>${esc(statusLabel)}</span></div>

          <div class="k">Structure</div>
          <div class="v">${esc(structureLabel)}</div>

          <div class="k">Risk</div>
          <div class="v"><span class="pill" style="display:inline-flex;align-items:center;gap:8px;"><span class="${riskDot}" aria-hidden="true"></span>${esc(riskLabel)}</span></div>

          <div class="k">Created</div>
          <div class="v">${esc(created || '—')}</div>

          <div class="k">Address</div>
          <div class="v">${esc(addressDisplay || '—')}</div>

          ${
            showIndustryCode
              ? `
            <div class="k">Industry code</div>
            <div class="v">${industryCode ? `<code>${esc(industryCode)}</code>` : '—'}</div>
          `
              : ''
          }

          <div class="k">Details confirmed</div>
          <div class="v">${esc(confirmed || '—')}</div>
        </div>
        ${ownersHtml}
      </section>
    `;

    const docsCard = `
      <section class="card">
        <h2>Documents</h2>
        <p class="muted" style="margin: 0;">Upload supplemental documents for this entity.</p>
        <div style="margin-top: 12px; display:flex; gap: 10px; flex-wrap: wrap;">
          <button class="btn-primary" type="button" data-open-modal="entity-upload-document">Upload document</button>
          <button class="btn" type="button" data-open-modal="entity-edit-address">Edit address</button>
          ${
            structureRaw === 'corporation'
              ? '<button class="btn" type="button" data-open-modal="entity-edit-industry-code">Edit industry code</button>'
              : ''
          }
        </div>
        ${docsHtml}
      </section>
    `;

    const editAddressModal = `
      <div class="modal" data-modal="entity-edit-address" hidden>
        <div class="modal-backdrop" data-close-modal></div>
        <div class="modal-card" role="dialog" aria-modal="true" aria-label="Edit entity address">
          <div class="modal-head">
            <h2>Edit address</h2>
            <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
          </div>

          <form class="form" data-form="entity-update-address">
            <input type="hidden" name="entity_id" value="${esc(id)}" />

            <label class="field">
              <span>Line 1</span>
              <input name="line1" type="text" required value="${esc(addrLine1)}" />
            </label>

            <label class="field">
              <span>Line 2 (optional)</span>
              <input name="line2" type="text" value="${esc(addrLine2)}" />
            </label>

            <label class="field">
              <span>City</span>
              <input name="city" type="text" required value="${esc(addrCity)}" />
            </label>

            <label class="field">
              <span>State</span>
              <input name="state" type="text" required value="${esc(addrState)}" />
            </label>

            <label class="field">
              <span>ZIP</span>
              <input name="zip" type="text" required value="${esc(addrZip)}" />
            </label>

            <div class="modal-actions">
              <button class="btn" type="button" data-close-modal>Cancel</button>
              <button class="btn-primary" type="submit">Save</button>
            </div>

            <div class="modal-error small" data-modal-error hidden></div>
          </form>
        </div>
      </div>

      <div class="modal" data-modal="internal-transfer" hidden>
        <div class="modal-backdrop" data-close-modal></div>
        <div class="modal-card" role="dialog" aria-modal="true" aria-label="Transfer between accounts">
          <div class="modal-head">
            <h2>Transfer between accounts</h2>
            <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
          </div>

          <form class="form" data-form="internal-transfer">
            <label class="field">
              <span>From account</span>
              <select name="from_account_id" required>
                <option value="">Select an account</option>
                ${accountOptionsHtml}
              </select>
            </label>

            <label class="field">
              <span>To account</span>
              <select name="to_account_id" required>
                <option value="">Select an account</option>
                ${accountOptionsHtml}
              </select>
            </label>

            <label class="field">
              <span>Amount (USD)</span>
              <input name="amount_usd" type="number" step="0.01" min="0.01" placeholder="25.00" required />
            </label>

            <label class="field">
              <span>Description (optional)</span>
              <input name="description" type="text" placeholder="Internal transfer" />
            </label>

            <div class="modal-actions">
              <button class="btn" type="button" data-close-modal>Cancel</button>
              <button class="btn-primary" type="submit">Transfer</button>
            </div>

            <div class="modal-error small" data-modal-error hidden></div>
          </form>

          <p class="small" style="margin: 10px 2px 0;">Creates an Increase account transfer instantly.</p>
        </div>
      </div>

      <div class="modal" data-modal="check-deposit" hidden>
        <div class="modal-backdrop" data-close-modal></div>
        <div class="modal-card" role="dialog" aria-modal="true" aria-label="Deposit a check">
          <div class="modal-head">
            <h2>Deposit a check</h2>
            <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
          </div>

          <form class="form" data-form="check-deposit" enctype="multipart/form-data">
            <label class="field">
              <span>Account</span>
              <select name="account_id" required>
                <option value="">Select an account</option>
                ${accountOptionsHtml}
              </select>
            </label>

            <label class="field">
              <span>Amount (USD)</span>
              <input name="amount_usd" type="number" step="0.01" min="0.01" placeholder="100.00" required />
            </label>

            <label class="field">
              <span>Description (optional)</span>
              <input name="description" type="text" placeholder="Check deposit" />
            </label>

            <label class="field">
              <span>Front image</span>
              <input name="front" type="file" accept="image/*" required />
            </label>

            <label class="field">
              <span>Back image</span>
              <input name="back" type="file" accept="image/*" required />
            </label>

            <div class="modal-actions">
              <button class="btn" type="button" data-close-modal>Cancel</button>
              <button class="btn-primary" type="submit">Deposit</button>
            </div>

            <div class="modal-error small" data-modal-error hidden></div>
          </form>

          <p class="small" style="margin: 10px 2px 0;">Uploads front and back images to create a real deposit via Increase.</p>
        </div>
      </div>
    `;

    const editIndustryModal = `
      <div class="modal" data-modal="entity-edit-industry-code" hidden>
        <div class="modal-backdrop" data-close-modal></div>
        <div class="modal-card" role="dialog" aria-modal="true" aria-label="Edit industry code">
          <div class="modal-head">
            <h2>Edit industry code</h2>
            <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
          </div>

          <form class="form" data-form="entity-update-industry-code">
            <input type="hidden" name="entity_id" value="${esc(id)}" />

            <label class="field">
              <span>Industry code</span>
              <input name="industry_code" type="text" required placeholder="e.g. 541511" value="${esc(industryCode)}" />
            </label>

            <div class="modal-actions">
              <button class="btn" type="button" data-close-modal>Cancel</button>
              <button class="btn-primary" type="submit">Save</button>
            </div>

            <div class="modal-error small" data-modal-error hidden></div>
          </form>

          <p class="small" style="margin: 10px 2px 0;">This is only supported for corporation entities.</p>
        </div>
      </div>
    `;

    const uploadDocModal = `
      <div class="modal" data-modal="entity-upload-document" hidden>
        <div class="modal-backdrop" data-close-modal></div>
        <div class="modal-card" role="dialog" aria-modal="true" aria-label="Upload entity document">
          <div class="modal-head">
            <h2>Upload document</h2>
            <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
          </div>

          <form class="form" data-form="entity-upload-document">
            <input type="hidden" name="entity_id" value="${esc(id)}" />

            <label class="field">
              <span>File</span>
              <input name="file" type="file" required />
            </label>

            <label class="field">
              <span>Description (optional)</span>
              <input name="description" type="text" placeholder="e.g. EIN letter" />
            </label>

            <div class="modal-actions">
              <button class="btn" type="button" data-close-modal>Cancel</button>
              <button class="btn-primary" type="submit">Upload</button>
            </div>

            <div class="modal-error small" data-modal-error hidden></div>
          </form>

          <p class="small" style="margin: 10px 2px 0;">Uploads as an <code>entity_supplemental_document</code> file + links it to this entity.</p>
        </div>
      </div>
    `;

    const archiveModal = `
      <div class="modal" data-modal="entity-archive" hidden>
        <div class="modal-backdrop" data-close-modal></div>
        <div class="modal-card" role="dialog" aria-modal="true" aria-label="Archive entity">
          <div class="modal-head">
            <h2>Archive entity</h2>
            <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
          </div>

          <p class="muted" style="margin: 0;">This will archive the entity in Increase. You can’t undo this from Dodo Checks yet.</p>

          <form class="form" data-form="entity-archive">
            <input type="hidden" name="entity_id" value="${esc(id)}" />

            <div class="modal-actions">
              <button class="btn" type="button" data-close-modal>Cancel</button>
              <button class="btn-primary" type="submit">Archive</button>
            </div>

            <div class="modal-error small" data-modal-error hidden></div>
          </form>
        </div>
      </div>
    `;

    content = `
      <section class="grid">
        ${entityDetailsCard}
        ${docsCard}
      </section>

      ${editAddressModal}
      ${structureRaw === 'corporation' ? editIndustryModal : ''}
      ${uploadDocModal}
      ${archiveModal}
    `;
  } catch (err) {
    title = 'Compliance';
    subtitle = `Entity ${entityId}`;

    content = `
      <section class="card">
        <h2>Entity</h2>
        <div class="alert" role="alert"><strong>Increase:</strong> ${esc(String(err?.message || 'error'))}</div>
        <p class="muted" style="margin: 0;">Check the entity id and your API key, then try again.</p>
      </section>
    `;
  }

  res.type('html').send(
    renderAppLayout({
      title,
      subtitle,
      activeKey: 'compliance',
      user: req.user,
      content,
      actionsHtml,
    })
  );
});

app.get('/app/:section', requireAuth, async (req, res) => {
  const section = String(req.params.section || 'overview');
  const pageDef = APP_PAGES[section];

  if (!pageDef) {
    res.status(404).type('text/plain').send('Not found');
    return;
  }

  const hasIncrease = Boolean(env('INCREASE_API_KEY'));
  const canCreateAccount =
    hasIncrease && Boolean(env('INCREASE_ENTITY_ID')) && Boolean(env('INCREASE_PROGRAM_ID'));

  let subtitle = '';
  let content = '';
  let actionsHtml = '';

  const userIncrease = await getUserIncrease(req.user.id);
  const userEntityId = userIncrease?.entity_id ? String(userIncrease.entity_id).trim() : '';
  const userAccountId = userIncrease?.account_id ? String(userIncrease.account_id).trim() : '';
  const userAccountNumberId = userIncrease?.account_number_id
    ? String(userIncrease.account_number_id).trim()
    : '';
  const userLockboxId = userIncrease?.lockbox_id ? String(userIncrease.lockbox_id).trim() : '';

  let increaseAccounts = [];
  let balancesById = new Map();
  let totalBalanceCents = null;
  let increaseError = null;

  let pendingTransactions = [];
  let transactions = [];
  let achTransfers = [];
  let cards = [];
  let accountNumbers = [];
  let externalAccounts = [];
  let lockboxes = [];
  let files = [];
  let accountStatements = [];
  let exportsList = [];
  let entities = [];

  const documentsTab = (() => {
    if (section !== 'documents') return null;
    const raw = String(req.query?.tab || '').trim().toLowerCase();
    const allowed = new Set(['statements', 'tax-forms', 'fees', 'exports']);
    return allowed.has(raw) ? raw : 'statements';
  })();

  const needsAccounts =
    hasIncrease &&
    (section === 'overview' ||
      section === 'accounts' ||
      section === 'transactions' ||
      section === 'transfers' ||
      section === 'cards' ||
      section === 'account-numbers' ||
      section === 'lockboxes' ||
      section === 'documents');
  const needsBalances = hasIncrease && (section === 'overview' || section === 'accounts');
  const needsTransactions = hasIncrease && section === 'transactions';
  const needsTransfers = hasIncrease && section === 'transfers';
  const needsCards = hasIncrease && section === 'cards';
  const needsAccountNumbers = hasIncrease && section === 'account-numbers';
  const needsExternalAccounts = hasIncrease && section === 'external-accounts';
  const needsLockboxes = hasIncrease && section === 'lockboxes';
  const needsEntities = hasIncrease && section === 'compliance';

  const needsAccountStatements = hasIncrease && section === 'documents' && documentsTab === 'statements';
  const needsFiles =
    hasIncrease &&
    section === 'documents' &&
    (documentsTab === 'tax-forms' || documentsTab === 'fees');
  const needsExports = hasIncrease && section === 'documents' && documentsTab === 'exports';

  if (
    hasIncrease &&
    (needsAccounts ||
      needsBalances ||
      needsTransactions ||
      needsTransfers ||
      needsCards ||
      needsAccountNumbers ||
      needsExternalAccounts ||
      needsLockboxes ||
      needsEntities ||
      needsAccountStatements ||
      needsFiles ||
      needsExports)
  ) {
    const increase = createIncreaseClient();

    try {
      const needsUserAccount =
        (needsAccounts ||
          needsBalances ||
          needsTransactions ||
          needsTransfers ||
          needsCards ||
          needsAccountNumbers ||
          needsLockboxes ||
          needsAccountStatements) &&
        Boolean(userAccountId);

      if (needsUserAccount) {
        const account = await increase.retrieveAccount({ accountId: userAccountId }).catch(() => null);
        increaseAccounts = account ? [account] : [];
      }

      // For the Overview page, show the user's primary routing + account number.
      // We retrieve it directly from Increase using the stored account_number_id.
      if (section === 'overview' && userAccountNumberId) {
        const an = await increase
          .retrieveAccountNumber({ accountNumberId: userAccountNumberId })
          .catch(() => null);

        const anAccountId = an?.account_id ? String(an.account_id).trim() : '';
        const expectedAccountId = userAccountId ? String(userAccountId).trim() : '';

        if (an && (!expectedAccountId || !anAccountId || anAccountId === expectedAccountId)) {
          accountNumbers = [an];
        }
      }

      if (needsBalances && userAccountId) {
        try {
          const balResp = await increase.getAccountBalance({ accountId: userAccountId });
          const cents = getBalanceCents(balResp);
          balancesById.set(userAccountId, cents);
          totalBalanceCents = typeof cents === 'number' ? cents : null;
        } catch {
          balancesById.set(userAccountId, null);
          totalBalanceCents = null;
        }
      }

      if (needsTransactions && userAccountId) {
        const q = {
          limit: 50,
          account_id: userAccountId,
        };

        const [pendingResp, txsResp] = await Promise.all([
          increase.listPendingTransactions(q).catch(() => null),
          increase.listTransactions(q),
        ]);

        pendingTransactions = extractDataArray(pendingResp);
        transactions = extractDataArray(txsResp);
      }

      if (needsTransfers && userAccountId) {
        const q = {
          limit: 50,
          account_id: userAccountId,
        };

        const transfersResp = await increase.listAchTransfers(q);
        achTransfers = extractDataArray(transfersResp);
      }

      if (needsCards && userAccountId) {
        const q = {
          limit: 50,
          account_id: userAccountId,
        };

        const cardsResp = await increase.listCards(q);
        cards = extractDataArray(cardsResp);
      }

      if (needsAccountNumbers && userAccountId) {
        const q = {
          limit: 50,
          account_id: userAccountId,
        };

        const acctNumsResp = await increase.listAccountNumbers(q);
        accountNumbers = extractDataArray(acctNumsResp);
      }

      if (needsExternalAccounts) {
        const mapped = await listUserExternalAccounts(req.user.id, 50);
        externalAccounts = [];

        for (const row of mapped) {
          const externalAccountId = String(row?.external_account_id || '').trim();
          if (!externalAccountId) continue;

          try {
            const ea = await increase.retrieveExternalAccount({ externalAccountId });
            if (ea) externalAccounts.push(ea);
          } catch {
            // ignore
          }
        }
      }

      if (needsLockboxes && userAccountId) {
        const q = {
          limit: 50,
          account_id: userAccountId,
        };

        const lockboxesResp = await increase.listLockboxes(q);
        lockboxes = extractDataArray(lockboxesResp);
      }

      if (needsAccountStatements && userAccountId) {
        const q = {
          limit: 50,
          account_id: userAccountId,
        };

        const statementsResp = await increase.listAccountStatements(q);
        accountStatements = extractDataArray(statementsResp);
      }

      // Files can't be safely listed per-user (tax forms / fee statements).
      if (needsFiles) {
        files = [];
      }

      if (needsExports) {
        const mapped = await listUserExports(req.user.id, 50);
        exportsList = [];

        for (const row of mapped) {
          const exportId = String(row?.export_id || '').trim();
          if (!exportId) continue;

          try {
            const ex = await increase.retrieveExport({ exportId });
            if (ex) exportsList.push(ex);
          } catch {
            // ignore
          }
        }
      }
    } catch (err) {
      increaseError = err;
    }
  }

  const accountOptionsHtml = increaseAccounts
    .map((a) => {
      const label = String(a.name || a.id || 'Account');
      const id = String(a.id || '');
      return `<option value="${esc(id)}">${esc(label)}</option>`;
    })
    .join('');


  if (section === 'overview') {
    subtitle = 'Your balance';

    const createButton = canCreateAccount
      ? '<button class="btn-primary" type="button" data-open-modal="create-account">Create Account</button>'
      : '<button class="btn-primary" type="button" disabled title="Set INCREASE_API_KEY, INCREASE_ENTITY_ID, and INCREASE_PROGRAM_ID">Create Account</button>';

    const canMoveMoney = hasIncrease && !increaseError && increaseAccounts.length > 0;

    const moveMoneyButton = canMoveMoney
      ? `
        <details class="menu">
          <summary class="btn">Move Money</summary>
          <div class="menu-panel" role="menu" aria-label="Move money">
            <button class="menu-item" type="button" role="menuitem" data-open-modal="send-money">
              <div class="menu-title">Send money</div>
              <div class="menu-desc">Push funds to an external account.</div>
            </button>
            <button class="menu-item" type="button" role="menuitem" data-open-modal="debit-money">
              <div class="menu-title">Debit money</div>
              <div class="menu-desc">Pull funds from an external account.</div>
            </button>
            <button class="menu-item" type="button" role="menuitem" data-open-modal="internal-transfer">
              <div class="menu-title">Transfer between accounts</div>
              <div class="menu-desc">Move funds between your Increase accounts.</div>
            </button>
            <button class="menu-item" type="button" role="menuitem" data-open-modal="check-deposit">
              <div class="menu-title">Deposit a check</div>
              <div class="menu-desc">Upload images of a physical check.</div>
            </button>
          </div>
        </details>
      `
      : `<button class="btn" type="button" disabled title="${hasIncrease ? 'No accounts loaded yet' : 'Set INCREASE_API_KEY to enable'}">Move Money</button>`;

    actionsHtml = '';

    const events = await listRecentEventsForUser(req.user.id, 8);

    let totalDisplay = '$0.00';
    let statusLine = 'Connect your Increase accounts to show live balances and activity.';

    if (!hasIncrease) {
      statusLine = 'Set INCREASE_API_KEY in your .env to connect Increase.';
    } else if (increaseError) {
      statusLine = 'Unable to load Increase data. Check your API key and try again.';
    } else if (!userAccountId) {
      totalDisplay = '—';
      statusLine = 'Finish compliance to provision your account.';
    } else if (totalBalanceCents != null) {
      totalDisplay = formatUsdFromCents(totalBalanceCents);
      statusLine = 'Connected to Increase.';
    }

    const increaseErrorHtml = increaseError
      ? `<div class="alert" role="alert"><strong>Increase:</strong> ${esc(String(increaseError.message || 'error'))}</div>`
      : '';

    const modalsHtml = `
      <div class="modal" data-modal="create-account" hidden>
        <div class="modal-backdrop" data-close-modal></div>
        <div class="modal-card" role="dialog" aria-modal="true" aria-label="Create account">
          <div class="modal-head">
            <h2>Create account</h2>
            <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
          </div>

          <form class="form" data-form="create-account">
            <label class="field">
              <span>Account name</span>
              <input name="name" type="text" placeholder="e.g. Operating" required />
            </label>

            <div class="modal-actions">
              <button class="btn" type="button" data-close-modal>Cancel</button>
              <button class="btn-primary" type="submit">Create</button>
            </div>

            <div class="modal-error small" data-modal-error hidden></div>
          </form>

          <p class="small" style="margin: 10px 2px 0;">
            Uses your configured <code>INCREASE_ENTITY_ID</code> + <code>INCREASE_PROGRAM_ID</code>.
          </p>
        </div>
      </div>

      <div class="modal" data-modal="send-money" hidden>
        <div class="modal-backdrop" data-close-modal></div>
        <div class="modal-card" role="dialog" aria-modal="true" aria-label="Send money">
          <div class="modal-head">
            <h2>Send money (ACH)</h2>
            <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
          </div>

          <form class="form" data-form="ach-transfer">
            <input type="hidden" name="direction" value="credit" />

            <label class="field">
              <span>From account</span>
              <select name="account_id" required>
                <option value="">Select an account</option>
                ${accountOptionsHtml}
              </select>
            </label>

            <label class="field">
              <span>Routing number</span>
              <input name="routing_number" type="text" inputmode="numeric" placeholder="011000015" required />
            </label>

            <label class="field">
              <span>Account number</span>
              <input name="account_number" type="text" inputmode="numeric" placeholder="000123456789" required />
            </label>

            <label class="field">
              <span>Amount (USD)</span>
              <input name="amount_usd" type="number" step="0.01" min="0.01" placeholder="10.00" required />
            </label>

            <label class="field">
              <span>Statement descriptor</span>
              <input name="statement_descriptor" type="text" placeholder="Dodo Checks" value="Dodo Checks" />
            </label>

            <div class="modal-actions">
              <button class="btn" type="button" data-close-modal>Cancel</button>
              <button class="btn-primary" type="submit">Send</button>
            </div>

            <div class="modal-error small" data-modal-error hidden></div>
          </form>
        </div>
      </div>

      <div class="modal" data-modal="debit-money" hidden>
        <div class="modal-backdrop" data-close-modal></div>
        <div class="modal-card" role="dialog" aria-modal="true" aria-label="Debit money">
          <div class="modal-head">
            <h2>Debit money (ACH)</h2>
            <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
          </div>

          <form class="form" data-form="ach-transfer">
            <input type="hidden" name="direction" value="debit" />

            <label class="field">
              <span>To account</span>
              <select name="account_id" required>
                <option value="">Select an account</option>
                ${accountOptionsHtml}
              </select>
            </label>

            <label class="field">
              <span>Routing number</span>
              <input name="routing_number" type="text" inputmode="numeric" placeholder="011000015" required />
            </label>

            <label class="field">
              <span>Account number</span>
              <input name="account_number" type="text" inputmode="numeric" placeholder="000123456789" required />
            </label>

            <label class="field">
              <span>Amount (USD)</span>
              <input name="amount_usd" type="number" step="0.01" min="0.01" placeholder="10.00" required />
            </label>

            <label class="field">
              <span>Statement descriptor</span>
              <input name="statement_descriptor" type="text" placeholder="Dodo Checks" value="Dodo Checks" />
            </label>

            <div class="modal-actions">
              <button class="btn" type="button" data-close-modal>Cancel</button>
              <button class="btn-primary" type="submit">Debit</button>
            </div>

            <div class="modal-error small" data-modal-error hidden></div>
          </form>
        </div>
      </div>

      <div class="modal" data-modal="internal-transfer" hidden>
        <div class="modal-backdrop" data-close-modal></div>
        <div class="modal-card" role="dialog" aria-modal="true" aria-label="Transfer between accounts">
          <div class="modal-head">
            <h2>Transfer between accounts</h2>
            <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
          </div>

          <form class="form" data-form="internal-transfer">
            <label class="field">
              <span>From account</span>
              <select name="from_account_id" required>
                <option value="">Select an account</option>
                ${accountOptionsHtml}
              </select>
            </label>

            <label class="field">
              <span>To account</span>
              <select name="to_account_id" required>
                <option value="">Select an account</option>
                ${accountOptionsHtml}
              </select>
            </label>

            <label class="field">
              <span>Amount (USD)</span>
              <input name="amount_usd" type="number" step="0.01" min="0.01" placeholder="25.00" required />
            </label>

            <label class="field">
              <span>Description (optional)</span>
              <input name="description" type="text" placeholder="Internal transfer" />
            </label>

            <div class="modal-actions">
              <button class="btn" type="button" data-close-modal>Cancel</button>
              <button class="btn-primary" type="submit">Transfer</button>
            </div>

            <div class="modal-error small" data-modal-error hidden></div>
          </form>

          <p class="small" style="margin: 10px 2px 0;">Creates an Increase account transfer instantly.</p>
        </div>
      </div>

      <div class="modal" data-modal="check-deposit" hidden>
        <div class="modal-backdrop" data-close-modal></div>
        <div class="modal-card" role="dialog" aria-modal="true" aria-label="Deposit a check">
          <div class="modal-head">
            <h2>Deposit a check</h2>
            <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
          </div>

          <form class="form" data-form="check-deposit" enctype="multipart/form-data">
            <label class="field">
              <span>Account</span>
              <select name="account_id" required>
                <option value="">Select an account</option>
                ${accountOptionsHtml}
              </select>
            </label>

            <label class="field">
              <span>Amount (USD)</span>
              <input name="amount_usd" type="number" step="0.01" min="0.01" placeholder="100.00" required />
            </label>

            <label class="field">
              <span>Description (optional)</span>
              <input name="description" type="text" placeholder="Check deposit" />
            </label>

            <label class="field">
              <span>Front image</span>
              <input name="front" type="file" accept="image/*" required />
            </label>

            <label class="field">
              <span>Back image</span>
              <input name="back" type="file" accept="image/*" required />
            </label>

            <div class="modal-actions">
              <button class="btn" type="button" data-close-modal>Cancel</button>
              <button class="btn-primary" type="submit">Deposit</button>
            </div>

            <div class="modal-error small" data-modal-error hidden></div>
          </form>

          <p class="small" style="margin: 10px 2px 0;">Uploads front and back images to create a real deposit via Increase.</p>
        </div>
      </div>
    `;

    const primaryAccountNumber =
      accountNumbers.find((an) => String(an?.id || '').trim() === userAccountNumberId) ||
      accountNumbers[0] ||
      null;
    const routingNumber = primaryAccountNumber ? String(primaryAccountNumber.routing_number || '').trim() : '';
    const accountNumber = primaryAccountNumber ? String(primaryAccountNumber.account_number || '').trim() : '';

    const bankDetailsHtml = userAccountId
      ? routingNumber && accountNumber
        ? `
          <div style="margin-top: 12px;">
            <div class="small">Routing number</div>
            <div class="value" style="font-size: 22px;"><code>${esc(routingNumber)}</code></div>

            <div class="small" style="margin-top: 10px;">Account number</div>
            <div class="value" style="font-size: 22px;"><code>${esc(accountNumber)}</code></div>

            <p class="small" style="margin: 10px 0 0;">
              Use these details to receive inbound ACH / direct deposit.
            </p>
          </div>
        `
        : `<p class="muted" style="margin: 10px 0 0;">Account number not available yet.</p>`
      : `<p class="muted" style="margin: 10px 0 0;">Finish compliance to provision your account.</p>`;

    content = `
      ${increaseErrorHtml}
      <div class="grid">
        <section class="card">
          <h2>Balance</h2>
          <div class="small">Balance</div>
          <div class="value">${esc(totalDisplay)}</div>
          <p class="small" style="margin: 10px 0 0;">
            ${esc(statusLine)}
          </p>
        </section>

        <section class="card">
          <h2>Account details</h2>
          ${bankDetailsHtml}
        </section>

        <section class="card" style="grid-column: 1 / -1;">
          <h2>Balance trend</h2>
          <div class="chart">
            <svg width="100%" height="200" viewBox="0 0 900 200" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Balance chart placeholder">
              <rect x="0" y="0" width="900" height="200" fill="none" />
              <g stroke="rgba(11,34,57,0.10)" stroke-width="1">
                <line x1="0" y1="40" x2="900" y2="40" />
                <line x1="0" y1="80" x2="900" y2="80" />
                <line x1="0" y1="120" x2="900" y2="120" />
                <line x1="0" y1="160" x2="900" y2="160" />
              </g>
              <path d="M0 160 C 150 160, 250 160, 360 160 S 560 160, 660 140 S 780 90, 900 40" fill="none" stroke="#0b2239" stroke-width="3" />
            </svg>
          </div>
        </section>

        <section class="card" style="grid-column: 1 / -1;">
          <h2>Recent events</h2>
          <ul class="events">${renderEvents(events)}</ul>
        </section>
      </div>
    `;
  } else if (section === 'accounts') {
    subtitle = 'Your Increase accounts';

    if (!hasIncrease) {
      content = `
        <section class="card">
          <h2>Accounts</h2>
          <p class="muted" style="margin: 0;">
            Set <code>INCREASE_API_KEY</code> in your .env to load accounts.
          </p>
        </section>
      `;
    } else if (increaseError) {
      content = `
        <section class="card">
          <h2>Accounts</h2>
          <div class="alert" role="alert"><strong>Increase:</strong> ${esc(String(increaseError.message || 'error'))}</div>
          <p class="muted" style="margin: 0;">Check your API key and try again.</p>
        </section>
      `;
    } else {
      const items = increaseAccounts
        .map((a) => {
          const cents = balancesById.get(a.id);
          const bal = typeof cents === 'number' ? formatUsdFromCents(cents) : '—';
          return `
            <li class="event">
              <div>
                <div class="type">${esc(String(a.name || a.id))}</div>
                <div class="meta">${esc(String(a.id || ''))}</div>
              </div>
              <span class="pill">${esc(bal)}</span>
            </li>
          `;
        })
        .join('');

      content = `
        <section class="card">
          <h2>Accounts</h2>
          <ul class="events">${items || '<li class="small">No accounts found.</li>'}</ul>
        </section>
      `;
    }
  } else if (section === 'transactions') {
    subtitle = 'Account activity';

    const canMoveMoney = hasIncrease && !increaseError && increaseAccounts.length > 0;
    const moveMoneyButton = canMoveMoney
      ? `
        <details class="menu">
          <summary class="btn">Move Money</summary>
          <div class="menu-panel" role="menu" aria-label="Move money">
            <button class="menu-item" type="button" role="menuitem" data-open-modal="send-money">
              <div class="menu-title">Send money</div>
              <div class="menu-desc">Push funds to an external account.</div>
            </button>
            <button class="menu-item" type="button" role="menuitem" data-open-modal="debit-money">
              <div class="menu-title">Debit money</div>
              <div class="menu-desc">Pull funds from an external account.</div>
            </button>
            <button class="menu-item" type="button" role="menuitem" data-open-modal="internal-transfer">
              <div class="menu-title">Transfer between accounts</div>
              <div class="menu-desc">Move funds between your Increase accounts.</div>
            </button>
            <button class="menu-item" type="button" role="menuitem" data-open-modal="check-deposit">
              <div class="menu-title">Deposit a check</div>
              <div class="menu-desc">Upload images of a physical check.</div>
            </button>
          </div>
        </details>
      `
      : `<button class="btn" type="button" disabled title="${hasIncrease ? 'No accounts loaded yet' : 'Set INCREASE_API_KEY to enable'}">Move Money</button>`;

    actionsHtml = '';

    if (!hasIncrease) {
      content = `
        <section class="card">
          <h2>Transactions</h2>
          <p class="muted" style="margin: 0;">
            Set <code>INCREASE_API_KEY</code> in your .env to load transactions.
          </p>
        </section>
      `;
    } else if (increaseError) {
      content = `
        <section class="card">
          <h2>Transactions</h2>
          <div class="alert" role="alert"><strong>Increase:</strong> ${esc(String(increaseError.message || 'error'))}</div>
          <p class="muted" style="margin: 0;">Check your API key and try again.</p>
        </section>
      `;
    } else {
      const selectedAccountId = '';
      const exportHref = '/api/transactions/export.csv';

      const accountOptionsWithAllHtml = `
        <option value=""${selectedAccountId ? '' : ' selected'}>All accounts</option>
        ${increaseAccounts
          .map((a) => {
            const label = String(a.name || a.id || 'Account');
            const id = String(a.id || '');
            const selected = id && id === selectedAccountId ? ' selected' : '';
            return `<option value="${esc(id)}"${selected}>${esc(label)}</option>`;
          })
          .join('')}
      `;

      const filterHtml = `
        <details class="menu">
          <summary class="btn">Filter <span class="kbd" aria-hidden="true">F</span></summary>
          <div class="menu-panel" role="menu" aria-label="Filter transactions">
            <form class="form tx-filter" method="get" action="/app/transactions">
              <label class="field">
                <span>Account</span>
                <select name="account_id">${accountOptionsWithAllHtml}</select>
              </label>

              <div class="tx-filter-actions">
                <a class="btn" href="/app/transactions">Clear</a>
                <button class="btn-primary" type="submit">Apply</button>
              </div>
            </form>
          </div>
        </details>
      `;

      const exportHtml = `<a class="btn" href="${esc(exportHref)}">Export <span class="kbd" aria-hidden="true">E</span></a>`;

      const accountNameById = new Map(
        increaseAccounts.map((a) => [String(a.id || ''), String(a.name || a.id || '')])
      );

      function renderTxRow(tx, status) {
        const created = formatShortDateTime(tx.created_at || tx.created || '');
        const id = String(tx.id || '').trim();
        const desc = String(tx.description || tx.memo || tx.id || '');
        const acctId = String(tx.account_id || '');
        const acctName = accountNameById.get(acctId) || acctId || '—';
        const category = getTxCategory(tx);
        const amountCents = getTxAmountCents(tx);
        const amount = amountCents == null ? '—' : formatUsdFromCents(amountCents);
        const neg = typeof amountCents === 'number' && amountCents < 0;

        const dotClass = status === 'pending' ? 'tx-dot pending' : 'tx-dot completed';
        const href = id ? `/app/transactions/${encodeURIComponent(id)}` : '';

        const inner = `
          <div class=\"tx-created\"><span class=\"${dotClass}\" aria-hidden=\"true\"></span>${esc(created)}</div>
          <div class=\"tx-desc\">${esc(desc)}</div>
          <div class=\"tx-acct\">${esc(acctName)}</div>
          <div class=\"tx-cat\">${esc(category)}</div>
          <div class=\"tx-amt${neg ? ' neg' : ''}\">${esc(amount)}</div>
        `;

        if (!href) {
          return `<div class=\"tx-row\">${inner}</div>`;
        }

        return `<a class=\"tx-row tx-row-link\" href=\"${esc(href)}\" aria-label=\"View transaction ${esc(desc || id)}\">${inner}</a>`;
      }

      const pendingRows = pendingTransactions.map((t) => renderTxRow(t, 'pending')).join('');
      const completedRows = transactions.map((t) => renderTxRow(t, 'completed')).join('');

      const pendingSection = pendingRows
        ? `
          <div class="tx-section">
            <span class="tx-section-title">Pending transactions</span>
          </div>
          ${pendingRows}
        `
        : '';

      const completedSection = completedRows
        ? `
          <div class="tx-section">
            <span class="tx-check" aria-hidden="true">✓</span>
            <span class="tx-section-title">Completed transactions</span>
          </div>
          ${completedRows}
        `
        : '';

      const emptyState = !pendingRows && !completedRows ? '<div class="tx-empty">No transactions found.</div>' : '';

      const transferModalsHtml = canMoveMoney
        ? `
          <div class="modal" data-modal="send-money" hidden>
            <div class="modal-backdrop" data-close-modal></div>
            <div class="modal-card" role="dialog" aria-modal="true" aria-label="Send money">
              <div class="modal-head">
                <h2>Send money (ACH)</h2>
                <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
              </div>

              <form class="form" data-form="ach-transfer">
                <input type="hidden" name="direction" value="credit" />

                <label class="field">
                  <span>From account</span>
                  <select name="account_id" required>
                    <option value="">Select an account</option>
                    ${accountOptionsHtml}
                  </select>
                </label>

                <label class="field">
                  <span>Routing number</span>
                  <input name="routing_number" type="text" inputmode="numeric" placeholder="011000015" required />
                </label>

                <label class="field">
                  <span>Account number</span>
                  <input name="account_number" type="text" inputmode="numeric" placeholder="000123456789" required />
                </label>

                <label class="field">
                  <span>Amount (USD)</span>
                  <input name="amount_usd" type="number" step="0.01" min="0.01" placeholder="10.00" required />
                </label>

                <label class="field">
                  <span>Statement descriptor</span>
                  <input name="statement_descriptor" type="text" placeholder="Dodo Checks" value="Dodo Checks" />
                </label>

                <div class="modal-actions">
                  <button class="btn" type="button" data-close-modal>Cancel</button>
                  <button class="btn-primary" type="submit">Send</button>
                </div>

                <div class="modal-error small" data-modal-error hidden></div>
              </form>
            </div>
          </div>

          <div class="modal" data-modal="debit-money" hidden>
            <div class="modal-backdrop" data-close-modal></div>
            <div class="modal-card" role="dialog" aria-modal="true" aria-label="Debit money">
              <div class="modal-head">
                <h2>Debit money (ACH)</h2>
                <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
              </div>

              <form class="form" data-form="ach-transfer">
                <input type="hidden" name="direction" value="debit" />

                <label class="field">
                  <span>To account</span>
                  <select name="account_id" required>
                    <option value="">Select an account</option>
                    ${accountOptionsHtml}
                  </select>
                </label>

                <label class="field">
                  <span>Routing number</span>
                  <input name="routing_number" type="text" inputmode="numeric" placeholder="011000015" required />
                </label>

                <label class="field">
                  <span>Account number</span>
                  <input name="account_number" type="text" inputmode="numeric" placeholder="000123456789" required />
                </label>

                <label class="field">
                  <span>Amount (USD)</span>
                  <input name="amount_usd" type="number" step="0.01" min="0.01" placeholder="10.00" required />
                </label>

                <label class="field">
                  <span>Statement descriptor</span>
                  <input name="statement_descriptor" type="text" placeholder="Dodo Checks" value="Dodo Checks" />
                </label>

                <div class="modal-actions">
                  <button class="btn" type="button" data-close-modal>Cancel</button>
                  <button class="btn-primary" type="submit">Debit</button>
                </div>

                <div class="modal-error small" data-modal-error hidden></div>
              </form>
            </div>
          </div>

          <div class="modal" data-modal="internal-transfer" hidden>
            <div class="modal-backdrop" data-close-modal></div>
            <div class="modal-card" role="dialog" aria-modal="true" aria-label="Transfer between accounts">
              <div class="modal-head">
                <h2>Transfer between accounts</h2>
                <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
              </div>

              <form class="form" data-form="internal-transfer">
                <label class="field">
                  <span>From account</span>
                  <select name="from_account_id" required>
                    <option value="">Select an account</option>
                    ${accountOptionsHtml}
                  </select>
                </label>

                <label class="field">
                  <span>To account</span>
                  <select name="to_account_id" required>
                    <option value="">Select an account</option>
                    ${accountOptionsHtml}
                  </select>
                </label>

                <label class="field">
                  <span>Amount (USD)</span>
                  <input name="amount_usd" type="number" step="0.01" min="0.01" placeholder="25.00" required />
                </label>

                <label class="field">
                  <span>Description (optional)</span>
                  <input name="description" type="text" placeholder="Internal transfer" />
                </label>

                <div class="modal-actions">
                  <button class="btn" type="button" data-close-modal>Cancel</button>
                  <button class="btn-primary" type="submit">Transfer</button>
                </div>

                <div class="modal-error small" data-modal-error hidden></div>
              </form>

              <p class="small" style="margin: 10px 2px 0;">Creates an Increase account transfer instantly.</p>
            </div>
          </div>

          <div class="modal" data-modal="check-deposit" hidden>
            <div class="modal-backdrop" data-close-modal></div>
            <div class="modal-card" role="dialog" aria-modal="true" aria-label="Deposit a check">
              <div class="modal-head">
                <h2>Deposit a check</h2>
                <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
              </div>

              <form class="form" data-form="check-deposit" enctype="multipart/form-data">
                <label class="field">
                  <span>Account</span>
                  <select name="account_id" required>
                    <option value="">Select an account</option>
                    ${accountOptionsHtml}
                  </select>
                </label>

                <label class="field">
                  <span>Amount (USD)</span>
                  <input name="amount_usd" type="number" step="0.01" min="0.01" placeholder="100.00" required />
                </label>

                <label class="field">
                  <span>Description (optional)</span>
                  <input name="description" type="text" placeholder="Check deposit" />
                </label>

                <label class="field">
                  <span>Front image</span>
                  <input name="front" type="file" accept="image/*" required />
                </label>

                <label class="field">
                  <span>Back image</span>
                  <input name="back" type="file" accept="image/*" required />
                </label>

                <div class="modal-actions">
                  <button class="btn" type="button" data-close-modal>Cancel</button>
                  <button class="btn-primary" type="submit">Deposit</button>
                </div>

                <div class="modal-error small" data-modal-error hidden></div>
              </form>

              <p class="small" style="margin: 10px 2px 0;">Uploads front and back images to create a real deposit via Increase.</p>
            </div>
          </div>
        `
        : '';

      content = `
        <section class="card">
          <div class="tx-toolbar">
            ${exportHtml}
          </div>

          <div class="tx-table" role="table" aria-label="Transactions">
            <div class="tx-head" role="row">
              <div role="columnheader">Created</div>
              <div role="columnheader">Description</div>
              <div role="columnheader">Account</div>
              <div role="columnheader">Category</div>
              <div role="columnheader" style="text-align:right;">Amount</div>
            </div>

            ${pendingSection}
            ${completedSection}
            ${emptyState}
          </div>
        </section>
      `;
    }
  } else if (section === 'transfers') {
    const tab = (() => {
      const raw = String(req.query?.tab || '').trim().toLowerCase();
      const allowed = new Set(['originated', 'received', 'scheduled']);
      return allowed.has(raw) ? raw : 'originated';
    })();

    subtitle = tab === 'received' ? 'Received' : tab === 'scheduled' ? 'Scheduled' : 'Originated';

    const tabsHtml = `
      <div class="tabs-row">
        <div class="tabs" role="tablist" aria-label="Transfers tabs">
          <a class="tab${tab === 'originated' ? ' active' : ''}" href="/app/transfers?tab=originated" role="tab" aria-selected="${
            tab === 'originated' ? 'true' : 'false'
          }">Originated</a>
          <a class="tab${tab === 'received' ? ' active' : ''}" href="/app/transfers?tab=received" role="tab" aria-selected="${
            tab === 'received' ? 'true' : 'false'
          }">Received</a>
          <a class="tab${tab === 'scheduled' ? ' active' : ''}" href="/app/transfers?tab=scheduled" role="tab" aria-selected="${
            tab === 'scheduled' ? 'true' : 'false'
          }">Scheduled</a>
        </div>
      </div>
    `;

    const canCreate = hasIncrease && !increaseError && Boolean(userAccountId);

    actionsHtml = canCreate
      ? `
        <details class="menu">
          <summary class="btn-primary">New</summary>
          <div class="menu-panel" role="menu" aria-label="Create transfer">
            <button class="menu-item" type="button" role="menuitem" data-open-modal="send-ach">
              <div class="menu-title">Send (ACH)</div>
              <div class="menu-desc">Push funds to an external bank account.</div>
            </button>
            <button class="menu-item" type="button" role="menuitem" data-open-modal="debit-ach">
              <div class="menu-title">Add funds (ACH)</div>
              <div class="menu-desc">Pull funds from an external bank account.</div>
            </button>
            <button class="menu-item" type="button" role="menuitem" data-open-modal="send-wire">
              <div class="menu-title">Send (Wire)</div>
              <div class="menu-desc">Send a domestic wire transfer.</div>
            </button>
            <button class="menu-item" type="button" role="menuitem" data-open-modal="mail-check">
              <div class="menu-title">Mail a check</div>
              <div class="menu-desc">Send a physical check to a recipient.</div>
            </button>
            <button class="menu-item" type="button" role="menuitem" data-open-modal="check-deposit">
              <div class="menu-title">Deposit a check</div>
              <div class="menu-desc">Upload front and back images.</div>
            </button>
          </div>
        </details>
      `
      : `<button class="btn" type="button" disabled title="${
          hasIncrease
            ? 'Finish compliance and provision your account to enable transfers'
            : 'Set INCREASE_API_KEY to enable'
        }">New</button>`;

    if (!hasIncrease) {
      content = `
        <section class="card">
          ${tabsHtml}
          <h2>Transfers</h2>
          <p class="muted" style="margin: 0;">Set <code>INCREASE_API_KEY</code> in your .env to load transfers.</p>
        </section>
      `;
    } else if (increaseError) {
      content = `
        <section class="card">
          ${tabsHtml}
          <h2>Transfers</h2>
          <div class="alert" role="alert"><strong>Increase:</strong> ${esc(String(increaseError.message || 'error'))}</div>
          <p class="muted" style="margin: 0;">Check your API key and try again.</p>
        </section>
      `;
    } else if (!userAccountId) {
      content = `
        <section class="card">
          ${tabsHtml}
          <h2>Transfers</h2>
          <p class="muted" style="margin: 0;">Finish compliance and provision your account to enable transfers.</p>
          <div style="margin-top: 12px; display: flex; gap: 10px; flex-wrap: wrap;">
            <a class="btn-primary" href="/app/compliance">Go to Compliance</a>
            <a class="btn" href="/app/overview">Back to Overview</a>
          </div>
        </section>
      `;
    } else {
      const increase = createIncreaseClient();

      const [wireResp, checkResp, inboundAchResp, inboundWireResp, depositsResp] = await Promise.all([
        increase.listWireTransfers({ limit: 50, account_id: userAccountId }).catch(() => null),
        increase.listCheckTransfers({ limit: 50, account_id: userAccountId }).catch(() => null),
        increase.listInboundAchTransfers({ limit: 50, account_id: userAccountId }).catch(() => null),
        increase.listInboundWireTransfers({ limit: 50, account_id: userAccountId }).catch(() => null),
        increase.listCheckDeposits({ limit: 50, account_id: userAccountId }).catch(() => null),
      ]);

      const wireTransfers = extractDataArray(wireResp);
      const checkTransfers = extractDataArray(checkResp);
      const inboundAchTransfers = extractDataArray(inboundAchResp);
      const inboundWireTransfers = extractDataArray(inboundWireResp);
      const checkDeposits = extractDataArray(depositsResp);

      function isTerminalStatus(statusRaw) {
        const s = String(statusRaw || '').trim().toLowerCase();
        if (!s) return false;
        return [
          'complete',
          'completed',
          'canceled',
          'cancelled',
          'rejected',
          'returned',
          'reversed',
          'failed',
          'mailed',
          'posted',
        ].includes(s);
      }

      function safeString(v) {
        return String(v == null ? '' : v).trim();
      }

      function normalizeBase({ kind, createdAt, description, statusRaw, amountCents }) {
        return {
          kind,
          created_at: createdAt,
          description,
          status_raw: statusRaw,
          amount_cents: amountCents,
        };
      }

      function normalizeAch(t) {
        const createdAt = safeString(t?.created_at || t?.created);
        const desc = getTransferDescription(t) || safeString(t?.id) || 'ACH transfer';
        const statusRaw = getTransferStatus(t) || safeString(t?.status);
        const amountCents = getTxAmountCents(t);
        return normalizeBase({ kind: 'ACH', createdAt, description: desc, statusRaw, amountCents });
      }

      function normalizeWire(t) {
        const createdAt = safeString(t?.created_at || t?.created);
        const creditorName = safeString(t?.creditor?.name);
        const last4 = safeString(t?.account_number_last4 || t?.account_number_last_4);
        const desc = [creditorName, last4 ? `•••• ${last4}` : ''].filter(Boolean).join(' · ') || safeString(t?.id) || 'Wire transfer';
        const statusRaw = safeString(t?.status);
        const amountCents = getTxAmountCents(t);
        return normalizeBase({ kind: 'Wire', createdAt, description: desc, statusRaw, amountCents });
      }

      function normalizeCheck(t) {
        const createdAt = safeString(t?.created_at || t?.created);
        const recipient = safeString(t?.physical_check?.recipient_name);
        const desc = recipient ? `To ${recipient}` : safeString(t?.id) || 'Check transfer';
        const statusRaw = safeString(t?.status);
        const amountCents = getTxAmountCents(t);
        return normalizeBase({ kind: 'Check', createdAt, description: desc, statusRaw, amountCents });
      }

      function normalizeCheckDeposit(t) {
        const createdAt = safeString(t?.created_at || t?.created);
        const desc = safeString(t?.description) || safeString(t?.id) || 'Check deposit';
        const statusRaw = safeString(t?.status);
        const amountCents = getTxAmountCents(t);
        return normalizeBase({ kind: 'Deposit', createdAt, description: desc, statusRaw, amountCents });
      }

      function normalizeInboundAch(t) {
        const createdAt = safeString(t?.created_at || t?.created);
        const statusRaw = safeString(t?.status);
        const amountCents = getTxAmountCents(t);
        const desc = safeString(t?.addenda) || safeString(t?.id) || 'Inbound ACH';
        return normalizeBase({ kind: 'Inbound ACH', createdAt, description: desc, statusRaw, amountCents });
      }

      function normalizeInboundWire(t) {
        const createdAt = safeString(t?.created_at || t?.created);
        const statusRaw = safeString(t?.status);
        const amountCents = getTxAmountCents(t);
        const sender = safeString(t?.sender?.name);
        const desc = sender ? `From ${sender}` : safeString(t?.id) || 'Inbound wire';
        return normalizeBase({ kind: 'Inbound wire', createdAt, description: desc, statusRaw, amountCents });
      }

      const originatedAll = ([]
        .concat(achTransfers.map(normalizeAch))
        .concat(wireTransfers.map(normalizeWire))
        .concat(checkTransfers.map(normalizeCheck))
        .concat(checkDeposits.map(normalizeCheckDeposit)))
        .filter(Boolean);

      const receivedAll = ([]
        .concat(inboundAchTransfers.map(normalizeInboundAch))
        .concat(inboundWireTransfers.map(normalizeInboundWire)))
        .filter(Boolean);

      const scheduledAll = originatedAll.filter((t) => !isTerminalStatus(t.status_raw));

      const list =
        tab === 'received' ? receivedAll : tab === 'scheduled' ? scheduledAll : originatedAll;

      list.sort((a, b) => {
        const at = new Date(a.created_at || 0).getTime();
        const bt = new Date(b.created_at || 0).getTime();
        return bt - at;
      });

      function renderRow(row) {
        const created = formatShortDateTime(row.created_at || '');
        const dotClass = `tx-dot ${transferStatusClass(row.status_raw)}`;

        const amountCents = row.amount_cents;
        const amount = amountCents == null ? '—' : formatUsdFromCents(amountCents);
        const neg = typeof amountCents === 'number' && amountCents < 0;

        const statusLabel = humanizeEnum(row.status_raw) || safeString(row.status_raw) || '—';

        return `
          <div class="tx-row">
            <div class="tx-created"><span class="${dotClass}" aria-hidden="true"></span>${esc(created || '—')}</div>
            <div class="tx-desc">${esc(row.kind || '—')}</div>
            <div class="tx-acct">${esc(row.description || '—')}</div>
            <div class="tx-cat"><span class="pill">${esc(statusLabel)}</span></div>
            <div class="tx-amt${neg ? ' neg' : ''}">${esc(amount)}</div>
          </div>
        `;
      }

      const rows = list.map((r) => renderRow(r)).join('');
      const emptyState = !rows ? '<div class="tx-empty">No transfers found.</div>' : '';

      const modalsHtml = canCreate
        ? `
          <div class="modal" data-modal="send-ach" hidden>
            <div class="modal-backdrop" data-close-modal></div>
            <div class="modal-card" role="dialog" aria-modal="true" aria-label="Send ACH">
              <div class="modal-head">
                <h2>Send (ACH)</h2>
                <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
              </div>
              <form class="form" data-form="ach-transfer">
                <input type="hidden" name="direction" value="credit" />

                <label class="field">
                  <span>Routing number</span>
                  <input name="routing_number" type="text" inputmode="numeric" placeholder="011000015" required />
                </label>

                <label class="field">
                  <span>Account number</span>
                  <input name="account_number" type="text" inputmode="numeric" placeholder="000123456789" required />
                </label>

                <label class="field">
                  <span>Amount (USD)</span>
                  <input name="amount_usd" type="number" step="0.01" min="0.01" placeholder="10.00" required />
                </label>

                <label class="field">
                  <span>Statement descriptor</span>
                  <input name="statement_descriptor" type="text" placeholder="Dodo Checks" value="Dodo Checks" />
                </label>

                <div class="modal-actions">
                  <button class="btn" type="button" data-close-modal>Cancel</button>
                  <button class="btn-primary" type="submit">Send</button>
                </div>

                <div class="modal-error small" data-modal-error hidden></div>
              </form>
            </div>
          </div>

          <div class="modal" data-modal="debit-ach" hidden>
            <div class="modal-backdrop" data-close-modal></div>
            <div class="modal-card" role="dialog" aria-modal="true" aria-label="Debit ACH">
              <div class="modal-head">
                <h2>Add funds (ACH)</h2>
                <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
              </div>
              <form class="form" data-form="ach-transfer">
                <input type="hidden" name="direction" value="debit" />

                <label class="field">
                  <span>Routing number</span>
                  <input name="routing_number" type="text" inputmode="numeric" placeholder="011000015" required />
                </label>

                <label class="field">
                  <span>Account number</span>
                  <input name="account_number" type="text" inputmode="numeric" placeholder="000123456789" required />
                </label>

                <label class="field">
                  <span>Amount (USD)</span>
                  <input name="amount_usd" type="number" step="0.01" min="0.01" placeholder="10.00" required />
                </label>

                <label class="field">
                  <span>Statement descriptor</span>
                  <input name="statement_descriptor" type="text" placeholder="Dodo Checks" value="Dodo Checks" />
                </label>

                <div class="modal-actions">
                  <button class="btn" type="button" data-close-modal>Cancel</button>
                  <button class="btn-primary" type="submit">Debit</button>
                </div>

                <div class="modal-error small" data-modal-error hidden></div>
              </form>
            </div>
          </div>

          <div class="modal" data-modal="send-wire" hidden>
            <div class="modal-backdrop" data-close-modal></div>
            <div class="modal-card" role="dialog" aria-modal="true" aria-label="Send wire">
              <div class="modal-head">
                <h2>Send (Wire)</h2>
                <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
              </div>
              <form class="form" data-form="wire-transfer">
                <label class="field">
                  <span>Beneficiary name</span>
                  <input name="creditor_name" type="text" placeholder="Recipient" required />
                </label>

                <label class="field">
                  <span>Routing number</span>
                  <input name="routing_number" type="text" inputmode="numeric" placeholder="026009593" required />
                </label>

                <label class="field">
                  <span>Account number</span>
                  <input name="account_number" type="text" inputmode="numeric" placeholder="000123456789" required />
                </label>

                <label class="field">
                  <span>Amount (USD)</span>
                  <input name="amount_usd" type="number" step="0.01" min="0.01" placeholder="25.00" required />
                </label>

                <label class="field">
                  <span>Message to recipient (optional)</span>
                  <input name="remittance_message" type="text" placeholder="Invoice 123" />
                </label>

                <div class="modal-actions">
                  <button class="btn" type="button" data-close-modal>Cancel</button>
                  <button class="btn-primary" type="submit">Send wire</button>
                </div>

                <div class="modal-error small" data-modal-error hidden></div>
              </form>
            </div>
          </div>

          <div class="modal" data-modal="mail-check" hidden>
            <div class="modal-backdrop" data-close-modal></div>
            <div class="modal-card" role="dialog" aria-modal="true" aria-label="Mail check">
              <div class="modal-head">
                <h2>Mail a check</h2>
                <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
              </div>

              <form class="form" data-form="check-transfer">
                <label class="field">
                  <span>Recipient name</span>
                  <input name="recipient_name" type="text" placeholder="John Doe" required />
                </label>

                <label class="field">
                  <span>Amount (USD)</span>
                  <input name="amount_usd" type="number" step="0.01" min="0.01" placeholder="50.00" required />
                </label>

                <label class="field">
                  <span>Memo (optional)</span>
                  <input name="memo" type="text" placeholder="Rent" />
                </label>

                <label class="field">
                  <span>Mailing address line 1</span>
                  <input name="mailing_line1" type="text" placeholder="123 Main St" required />
                </label>

                <label class="field">
                  <span>Mailing address line 2 (optional)</span>
                  <input name="mailing_line2" type="text" placeholder="Apt 4" />
                </label>

                <label class="field">
                  <span>City</span>
                  <input name="mailing_city" type="text" placeholder="New York" required />
                </label>

                <label class="field">
                  <span>State</span>
                  <input name="mailing_state" type="text" placeholder="NY" required />
                </label>

                <label class="field">
                  <span>ZIP</span>
                  <input name="mailing_postal_code" type="text" placeholder="10001" required />
                </label>

                <div class="modal-actions">
                  <button class="btn" type="button" data-close-modal>Cancel</button>
                  <button class="btn-primary" type="submit">Send check</button>
                </div>

                <div class="modal-error small" data-modal-error hidden></div>
              </form>
            </div>
          </div>

          <div class="modal" data-modal="check-deposit" hidden>
            <div class="modal-backdrop" data-close-modal></div>
            <div class="modal-card" role="dialog" aria-modal="true" aria-label="Deposit a check">
              <div class="modal-head">
                <h2>Deposit a check</h2>
                <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
              </div>

              <form class="form" data-form="check-deposit" enctype="multipart/form-data">
                <label class="field">
                  <span>Amount (USD)</span>
                  <input name="amount_usd" type="number" step="0.01" min="0.01" placeholder="100.00" required />
                </label>

                <label class="field">
                  <span>Description (optional)</span>
                  <input name="description" type="text" placeholder="Check deposit" />
                </label>

                <label class="field">
                  <span>Front image</span>
                  <input name="front" type="file" accept="image/*" required />
                </label>

                <label class="field">
                  <span>Back image</span>
                  <input name="back" type="file" accept="image/*" required />
                </label>

                <div class="modal-actions">
                  <button class="btn" type="button" data-close-modal>Cancel</button>
                  <button class="btn-primary" type="submit">Deposit</button>
                </div>

                <div class="modal-error small" data-modal-error hidden></div>
              </form>
            </div>
          </div>
        `
        : '';

      content = `
        <section class="card">
          ${tabsHtml}

          <div class="tx-table" role="table" aria-label="Transfers">
            <div class="tx-head" role="row">
              <div role="columnheader">Created</div>
              <div role="columnheader">Type</div>
              <div role="columnheader">Description</div>
              <div role="columnheader">Status</div>
              <div role="columnheader" style="text-align:right;">Amount</div>
            </div>

            ${rows}
            ${emptyState}
          </div>
        </section>

        ${modalsHtml}
      `;
    }
  } else if (section === 'cards') {
    subtitle = 'Cards linked to your accounts';

    const canCreateCard = hasIncrease && !increaseError && increaseAccounts.length > 0;
    const createCardButton = canCreateCard
      ? '<button class="btn-primary" type="button" data-open-modal="create-card">Create Card</button>'
      : `<button class="btn-primary" type="button" disabled title="${
          hasIncrease ? 'No accounts loaded yet' : 'Set INCREASE_API_KEY to enable'
        }">Create Card</button>`;

    actionsHtml = `${createCardButton}`;

    if (!hasIncrease) {
      content = `
        <section class="card">
          <h2>Cards</h2>
          <p class="muted" style="margin: 0;">
            Set <code>INCREASE_API_KEY</code> in your .env to load cards.
          </p>
        </section>
      `;
    } else if (increaseError) {
      content = `
        <section class="card">
          <h2>Cards</h2>
          <div class="alert" role="alert"><strong>Increase:</strong> ${esc(String(increaseError.message || 'error'))}</div>
          <p class="muted" style="margin: 0;">Check your API key and try again.</p>
        </section>
      `;
    } else {
      const selectedAccountId = String(req.query?.account_id || '').trim() || '';

      const accountOptionsWithAllHtml = `
        <option value=""${selectedAccountId ? '' : ' selected'}>All accounts</option>
        ${increaseAccounts
          .map((a) => {
            const label = String(a.name || a.id || 'Account');
            const id = String(a.id || '');
            const selected = id && id === selectedAccountId ? ' selected' : '';
            return `<option value="${esc(id)}"${selected}>${esc(label)}</option>`;
          })
          .join('')}
      `;

      const filterHtml = `
        <details class="menu">
          <summary class="btn">Filter <span class="kbd" aria-hidden="true">F</span></summary>
          <div class="menu-panel" role="menu" aria-label="Filter cards">
            <form class="form tx-filter" method="get" action="/app/cards">
              <label class="field">
                <span>Account</span>
                <select name="account_id">${accountOptionsWithAllHtml}</select>
              </label>

              <div class="tx-filter-actions">
                <a class="btn" href="/app/cards">Clear</a>
                <button class="btn-primary" type="submit">Apply</button>
              </div>
            </form>
          </div>
        </details>
      `;

      const accountNameById = new Map(
        increaseAccounts.map((a) => [String(a.id || ''), String(a.name || a.id || '')])
      );

      function renderCardRow(card) {
        const created = formatShortDateTime(card.created_at || card.created || '');
        const id = String(card.id || '').trim();
        const desc = String(card.description || '');
        const acctId = String(card.account_id || '');
        const acctName = accountNameById.get(acctId) || acctId || '—';
        const statusRaw = String(card.status || '').trim();
        const statusLabel = humanizeEnum(statusRaw) || statusRaw || '—';
        const statusClass = cardStatusClass(statusRaw);
        const dotClass = `tx-dot ${statusClass}`;
        const summary = formatCardSummary(card);

        const href = id ? `/app/cards/${encodeURIComponent(id)}` : '';

        const inner = `
          <div class="tx-created"><span class="${dotClass}" aria-hidden="true"></span>${esc(created)}</div>
          <div class="tx-desc">${esc(desc || '—')}</div>
          <div class="tx-acct">${esc(acctName)}</div>
          <div class="tx-cat"><span class="pill">${esc(statusLabel)}</span></div>
          <div class="tx-amt">${esc(summary)}</div>
        `;

        if (!href) {
          return `<div class="tx-row">${inner}</div>`;
        }

        return `<a class="tx-row tx-row-link" href="${esc(href)}" aria-label="View card ${esc(desc || id || '')}">${inner}</a>`;
      }

      const rows = cards.map((c) => renderCardRow(c)).join('');
      const emptyState = !rows ? '<div class="tx-empty">No cards found.</div>' : '';

      const createCardModalHtml = `
        <div class="modal" data-modal="create-card" hidden>
          <div class="modal-backdrop" data-close-modal></div>
          <div class="modal-card" role="dialog" aria-modal="true" aria-label="Create card">
            <div class="modal-head">
              <h2>Create card</h2>
              <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
            </div>

            <form class="form" data-form="create-card">
              <label class="field">
                <span>Account</span>
                <select name="account_id" required>
                  <option value="">Select an account</option>
                  ${accountOptionsHtml}
                </select>
              </label>

              <label class="field">
                <span>Description (optional)</span>
                <input name="description" type="text" placeholder="e.g. Office expenses" />
              </label>

              <label class="field">
                <span>Billing address line 1 (optional)</span>
                <input name="billing_line1" type="text" placeholder="123 Main St" />
              </label>

              <label class="field">
                <span>Billing address line 2 (optional)</span>
                <input name="billing_line2" type="text" placeholder="Apt 4" />
              </label>

              <label class="field">
                <span>City (optional)</span>
                <input name="billing_city" type="text" placeholder="New York" />
              </label>

              <label class="field">
                <span>State (optional)</span>
                <input name="billing_state" type="text" placeholder="NY" />
              </label>

              <label class="field">
                <span>Postal code (optional)</span>
                <input name="billing_postal_code" type="text" placeholder="10001" />
              </label>

              <div class="modal-actions">
                <button class="btn" type="button" data-close-modal>Cancel</button>
                <button class="btn-primary" type="submit">Create</button>
              </div>

              <div class="modal-error small" data-modal-error hidden></div>
            </form>

            <p class="small" style="margin: 10px 2px 0;">
              Tip: billing address is optional — if you provide any billing fields, you must provide line 1, city, state, and postal code.
            </p>
          </div>
        </div>
      `;

      content = `
        <section class="card">
          <div class="tx-toolbar">
            ${filterHtml}
          </div>

          <div class="tx-table" role="table" aria-label="Cards">
            <div class="tx-head" role="row">
              <div role="columnheader">Created</div>
              <div role="columnheader">Description</div>
              <div role="columnheader">Account</div>
              <div role="columnheader">Status</div>
              <div role="columnheader" style="text-align:right;">Card</div>
            </div>

            ${rows}
            ${emptyState}
          </div>
        </section>

        ${createCardModalHtml}
      `;
    }
  } else if (section === 'account-numbers') {
    subtitle = 'Routing and account numbers for inbound payments';

    const canCreate = hasIncrease && !increaseError && increaseAccounts.length > 0;
    const createBtn = canCreate
      ? '<button class="btn-primary" type="button" data-open-modal="create-account-number">Create Account Number</button>'
      : `<button class="btn-primary" type="button" disabled title="${
          hasIncrease ? 'No accounts loaded yet' : 'Set INCREASE_API_KEY to enable'
        }">Create Account Number</button>`;

    actionsHtml = `${createBtn}`;

    if (!hasIncrease) {
      content = `
        <section class="card">
          <h2>Account Numbers</h2>
          <p class="muted" style="margin: 0;">
            Set <code>INCREASE_API_KEY</code> in your .env to load account numbers.
          </p>
        </section>
      `;
    } else if (increaseError) {
      content = `
        <section class="card">
          <h2>Account Numbers</h2>
          <div class="alert" role="alert"><strong>Increase:</strong> ${esc(String(increaseError.message || 'error'))}</div>
          <p class="muted" style="margin: 0;">Check your API key and try again.</p>
        </section>
      `;
    } else {
      const selectedAccountId = String(req.query?.account_id || '').trim() || '';

      const accountOptionsWithAllHtml = `
        <option value=""${selectedAccountId ? '' : ' selected'}>All accounts</option>
        ${increaseAccounts
          .map((a) => {
            const label = String(a.name || a.id || 'Account');
            const id = String(a.id || '');
            const selected = id && id === selectedAccountId ? ' selected' : '';
            return `<option value="${esc(id)}"${selected}>${esc(label)}</option>`;
          })
          .join('')}
      `;

      const filterHtml = `
        <details class="menu">
          <summary class="btn">Filter <span class="kbd" aria-hidden="true">F</span></summary>
          <div class="menu-panel" role="menu" aria-label="Filter account numbers">
            <form class="form tx-filter" method="get" action="/app/account-numbers">
              <label class="field">
                <span>Account</span>
                <select name="account_id">${accountOptionsWithAllHtml}</select>
              </label>

              <div class="tx-filter-actions">
                <a class="btn" href="/app/account-numbers">Clear</a>
                <button class="btn-primary" type="submit">Apply</button>
              </div>
            </form>
          </div>
        </details>
      `;

      const accountNameById = new Map(
        increaseAccounts.map((a) => [String(a.id || ''), String(a.name || a.id || '')])
      );

      function renderAcctNumRow(an) {
        const created = formatShortDateTime(an.created_at || an.created || '');
        const id = String(an.id || '').trim();
        const name = String(an.name || '');
        const acctId = String(an.account_id || '');
        const acctName = accountNameById.get(acctId) || acctId || '—';
        const statusRaw = String(an.status || '').trim();
        const statusLabel = humanizeEnum(statusRaw) || statusRaw || '—';
        const dotClass = `tx-dot ${cardStatusClass(statusRaw)}`;

        const routing = String(an.routing_number || '');
        const number = String(an.account_number || '');

        const href = id ? `/app/account-numbers/${encodeURIComponent(id)}` : '';

        const inner = `
          <div class="tx-created"><span class="${dotClass}" aria-hidden="true"></span>${esc(created)}</div>
          <div class="tx-desc">${esc(name || '—')}</div>
          <div class="tx-acct">${esc(acctName)}</div>
          <div class="tx-cat"><span class="pill">${esc(statusLabel)}</span> <span class="muted">${esc(routing || '—')}</span></div>
          <div class="tx-amt">${esc(number || '—')}</div>
        `;

        if (!href) {
          return `<div class="tx-row">${inner}</div>`;
        }

        return `<a class="tx-row tx-row-link" href="${esc(href)}" aria-label="View account number ${esc(name || id || '')}">${inner}</a>`;
      }

      const rows = accountNumbers.map((an) => renderAcctNumRow(an)).join('');
      const emptyState = !rows ? '<div class="tx-empty">No account numbers found.</div>' : '';

      const createModal = `
        <div class="modal" data-modal="create-account-number" hidden>
          <div class="modal-backdrop" data-close-modal></div>
          <div class="modal-card" role="dialog" aria-modal="true" aria-label="Create account number">
            <div class="modal-head">
              <h2>Create account number</h2>
              <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
            </div>

            <form class="form" data-form="create-account-number">
              <label class="field">
                <span>Account</span>
                <select name="account_id" required>
                  <option value="">Select an account</option>
                  ${accountOptionsHtml}
                </select>
              </label>

              <label class="field">
                <span>Name</span>
                <input name="name" type="text" placeholder="e.g. Rent payments" required />
              </label>

              <div class="modal-actions">
                <button class="btn" type="button" data-close-modal>Cancel</button>
                <button class="btn-primary" type="submit">Create</button>
              </div>

              <div class="modal-error small" data-modal-error hidden></div>
            </form>

            <p class="small" style="margin: 10px 2px 0;">
              Tip: create one account number per vendor to reconcile inbound payments.
            </p>
          </div>
        </div>
      `;

      content = `
        <section class="card">
          <div class="tx-toolbar">
            ${filterHtml}
          </div>

          <div class="tx-table" role="table" aria-label="Account numbers">
            <div class="tx-head" role="row">
              <div role="columnheader">Created</div>
              <div role="columnheader">Name</div>
              <div role="columnheader">Account</div>
              <div role="columnheader">Status / Routing</div>
              <div role="columnheader" style="text-align:right;">Account number</div>
            </div>

            ${rows}
            ${emptyState}
          </div>
        </section>

        ${createModal}
      `;
    }
  } else if (section === 'external-accounts') {
    subtitle = 'External accounts used as ACH transfer destinations';

    const canCreateExternal = hasIncrease && !increaseError;
    const createExternalBtn = canCreateExternal
      ? '<button class="btn-primary" type="button" data-open-modal="create-external-account">Create External Account</button>'
      : `<button class="btn-primary" type="button" disabled title="${
          hasIncrease ? 'Unable to load Increase data' : 'Set INCREASE_API_KEY to enable'
        }">Create External Account</button>`;

    actionsHtml = `${createExternalBtn}`;

    if (!hasIncrease) {
      content = `
        <section class="card">
          <h2>External Accounts</h2>
          <p class="muted" style="margin: 0;">
            Set <code>INCREASE_API_KEY</code> in your .env to load external accounts.
          </p>
        </section>
      `;
    } else if (increaseError) {
      content = `
        <section class="card">
          <h2>External Accounts</h2>
          <div class="alert" role="alert"><strong>Increase:</strong> ${esc(String(increaseError.message || 'error'))}</div>
          <p class="muted" style="margin: 0;">Check your API key and try again.</p>
        </section>
      `;
    } else {
      const q = String(req.query?.q || '').trim();
      const qLower = q.toLowerCase();

      const filtered = q
        ? externalAccounts.filter((ea) => String(ea.description || '').toLowerCase().includes(qLower))
        : externalAccounts;

      const filterHtml = `
        <details class="menu">
          <summary class="btn">Filter <span class="kbd" aria-hidden="true">F</span></summary>
          <div class="menu-panel" role="menu" aria-label="Filter external accounts">
            <form class="form tx-filter" method="get" action="/app/external-accounts">
              <label class="field">
                <span>Description contains</span>
                <input name="q" type="text" placeholder="e.g. Vendor" value="${esc(q)}" />
              </label>

              <div class="tx-filter-actions">
                <a class="btn" href="/app/external-accounts">Clear</a>
                <button class="btn-primary" type="submit">Apply</button>
              </div>
            </form>
          </div>
        </details>
      `;

      function last4(value) {
        const s = String(value || '').trim();
        if (!s) return '';
        const digits = s.replace(/\D/g, '');
        if (!digits) return '';
        return digits.slice(-4);
      }

      function renderExternalRow(ea) {
        const created = formatShortDateTime(ea.created_at || ea.created || '');
        const desc = String(ea.description || ea.id || '');
        const statusRaw = String(ea.status || '').trim();
        const statusLabel = humanizeEnum(statusRaw) || statusRaw || '—';
        const dotClass = `tx-dot ${cardStatusClass(statusRaw)}`;

        const holderRaw = String(ea.account_holder || ea.account_holder_type || '').trim();
        const fundingRaw = String(ea.funding || '').trim();
        const meta = [holderRaw, fundingRaw]
          .filter(Boolean)
          .map(humanizeEnum)
          .join(' · ');

        const routing = String(ea.routing_number || '').trim();

        const l4 =
          last4(ea.account_number_last4) ||
          last4(ea.last4) ||
          last4(ea.account_number);
        const acctDisplay = l4 ? `•••• ${l4}` : '—';

        return `
          <div class="tx-row">
            <div class="tx-created"><span class="${dotClass}" aria-hidden="true"></span>${esc(created)}</div>
            <div class="tx-desc">${esc(desc || '—')}</div>
            <div class="tx-acct"><span class="pill">${esc(statusLabel)}</span> <span class="muted">${esc(meta)}</span></div>
            <div class="tx-cat">${esc(routing || '—')}</div>
            <div class="tx-amt">${esc(acctDisplay)}</div>
          </div>
        `;
      }

      const rows = filtered.map((ea) => renderExternalRow(ea)).join('');
      const emptyState = !rows ? '<div class="tx-empty">No external accounts found.</div>' : '';

      const createModal = `
        <div class="modal" data-modal="create-external-account" hidden>
          <div class="modal-backdrop" data-close-modal></div>
          <div class="modal-card" role="dialog" aria-modal="true" aria-label="Create external account">
            <div class="modal-head">
              <h2>Create external account</h2>
              <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
            </div>

            <form class="form" data-form="create-external-account">
              <label class="field">
                <span>Description</span>
                <input name="description" type="text" placeholder="e.g. Vendor payouts" required />
              </label>

              <label class="field">
                <span>Routing number</span>
                <input name="routing_number" type="text" inputmode="numeric" placeholder="011000015" required />
              </label>

              <label class="field">
                <span>Account number</span>
                <input name="account_number" type="text" inputmode="numeric" placeholder="000123456789" required />
              </label>

              <label class="field">
                <span>Account holder (optional)</span>
                <select name="account_holder">
                  <option value="">Not specified</option>
                  <option value="individual">Individual</option>
                  <option value="business">Business</option>
                </select>
              </label>

              <label class="field">
                <span>Funding (optional)</span>
                <select name="funding">
                  <option value="">Not specified</option>
                  <option value="checking">Checking</option>
                  <option value="savings">Savings</option>
                </select>
              </label>

              <div class="modal-actions">
                <button class="btn" type="button" data-close-modal>Cancel</button>
                <button class="btn-primary" type="submit">Create</button>
              </div>

              <div class="modal-error small" data-modal-error hidden></div>
            </form>

            <p class="small" style="margin: 10px 2px 0;">
              Tip: External accounts let you re-use bank details when sending or debiting money.
            </p>
          </div>
        </div>
      `;

      content = `
        <section class="card">
          <div class="tx-toolbar">
            ${filterHtml}
          </div>

          <div class="tx-table" role="table" aria-label="External accounts">
            <div class="tx-head" role="row">
              <div role="columnheader">Created</div>
              <div role="columnheader">Description</div>
              <div role="columnheader">Status</div>
              <div role="columnheader">Routing</div>
              <div role="columnheader" style="text-align:right;">Account</div>
            </div>

            ${rows}
            ${emptyState}
          </div>
        </section>

        ${createModal}
      `;
    }
  } else if (section === 'compliance') {
    if (true) {
      subtitle = 'Onboarding';
      actionsHtml = '';

      const compliance = await getUserCompliance(req.user.id);
      const docs = await listUserComplianceDocuments(req.user.id, 50);

      const fullNameVal = String(compliance?.full_name || '').trim();
      const phoneVal = String(compliance?.phone || '').trim();
      const dobVal = String(compliance?.date_of_birth || '').trim();

      const addr1Val = String(compliance?.address_line1 || '').trim();
      const addr2Val = String(compliance?.address_line2 || '').trim();
      const cityVal = String(compliance?.city || '').trim();
      const stateVal = String(compliance?.state || '').trim();
      const zipVal = String(compliance?.zip || '').trim();

      const hasSsn = Boolean(String(compliance?.ssn_ciphertext || '').trim());
      const ssnLast4Val = String(compliance?.ssn_last4 || '').trim();
      const ssnDisplay = ssnLast4Val ? `•••-••-${ssnLast4Val}` : '';

      const hasId = docs.some((d) => String(d?.kind || '') === 'id_card');
      const hasProof = docs.some((d) => String(d?.kind || '') === 'proof_of_address');

      const encryptionReady = Boolean(getDataEncryptionKey());
      const allowSharedEntityFallback = parseBool(env('INCREASE_ALLOW_SHARED_ENTITY_FALLBACK'), false);
      const increaseReady =
        hasIncrease &&
        Boolean(env('INCREASE_PROGRAM_ID')) &&
        (!allowSharedEntityFallback || Boolean(env('INCREASE_ENTITY_ID')));

      const docsRows = docs
        .map((d) => {
          const created = formatShortDateTime(d.created_at || '');
          const kind = String(d.kind || '').trim() || 'document';
          const filename = String(d.filename || '').trim();
          const fileId = String(d.file_id || '').trim();
          const meta = [fileId, filename].filter(Boolean).join(' · ');

          return `
            <li class="event">
              <div>
                <div class="type">${esc(humanizeEnum(kind) || kind)}</div>
                <div class="meta">${esc([created, meta].filter(Boolean).join(' · ') || '—')}</div>
              </div>
              <span class="pill">ok</span>
            </li>
          `;
        })
        .join('');

      const docsSummary = `
        <div style="display:flex; gap:10px; flex-wrap:wrap; margin-top:10px;">
          <span class="pill">ID card: ${hasId ? 'uploaded' : 'missing'}</span>
          <span class="pill">Proof of address: ${hasProof ? 'uploaded' : 'missing'}</span>
        </div>
      `;

      const provisioningSummary = `
        <div style="display:flex; gap:10px; flex-wrap:wrap; margin-top:10px;">
          <span class="pill">Entity: ${userEntityId ? esc(userEntityId) : 'not provisioned'}</span>
          <span class="pill">Account: ${userAccountId ? esc(userAccountId) : 'not provisioned'}</span>
          <span class="pill">Account number: ${userAccountNumberId ? esc(userAccountNumberId) : 'not provisioned'}</span>
          <span class="pill">Lockbox: ${userLockboxId ? esc(userLockboxId) : 'not provisioned'}</span>
        </div>
      `;

      const warnings = [
        !encryptionReady
          ? '<div class="alert" role="alert"><strong>Setup:</strong> Set <code>APP_DATA_ENCRYPTION_KEY</code> (base64 32 bytes) to store SSNs.</div>'
          : '',
        !increaseReady
          ? '<div class="alert" role="alert"><strong>Setup:</strong> Set <code>INCREASE_API_KEY</code> and <code>INCREASE_PROGRAM_ID</code> to provision accounts. If using the shared-entity fallback, also set <code>INCREASE_ENTITY_ID</code>.</div>'
          : '',
      ]
        .filter(Boolean)
        .join('');

      const ssnHelp = hasSsn
        ? `Stored (last 4: ${esc(ssnDisplay || '—')}). Leave blank to keep existing.`
        : 'Required. Stored encrypted.';

      content = `
        ${warnings}
        <div class="alert" data-inline-error hidden></div>

        <section class="grid">
          <section class="card">
            <h2>Personal details</h2>
            <p class="muted" style="margin: 0;">This information is required before we can provision your account.</p>

            <form class="form" data-form="compliance-save" style="margin-top: 14px;">
              <label class="field">
                <span>Full name</span>
                <input name="full_name" type="text" value="${esc(fullNameVal)}" required />
              </label>

              <label class="field">
                <span>Email</span>
                <input name="email" type="email" value="${esc(req.user.email || '')}" disabled />
              </label>

              <label class="field">
                <span>Phone number</span>
                <input name="phone" type="tel" value="${esc(phoneVal)}" required />
              </label>

              <label class="field">
                <span>Date of birth</span>
                <input name="date_of_birth" type="date" value="${esc(dobVal)}" required />
              </label>

              <label class="field">
                <span>Full SSN</span>
                <input name="ssn" type="password" inputmode="numeric" placeholder="${esc(
                  hasSsn ? `Stored (${ssnDisplay || '—'})` : '123-45-6789'
                )}" ${hasSsn ? '' : 'required'} />
                <div class="small" style="margin-top: 6px;">${ssnHelp}</div>
              </label>

              <label class="field">
                <span>Address line 1</span>
                <input name="address_line1" type="text" value="${esc(addr1Val)}" required />
              </label>

              <label class="field">
                <span>Address line 2 (optional)</span>
                <input name="address_line2" type="text" value="${esc(addr2Val)}" />
              </label>

              <div style="display:grid; grid-template-columns: 1fr 120px 140px; gap: 12px;">
                <label class="field" style="margin: 0;">
                  <span>City</span>
                  <input name="city" type="text" value="${esc(cityVal)}" required />
                </label>
                <label class="field" style="margin: 0;">
                  <span>State</span>
                  <input name="state" type="text" value="${esc(stateVal)}" maxlength="2" required />
                </label>
                <label class="field" style="margin: 0;">
                  <span>ZIP</span>
                  <input name="zip" type="text" value="${esc(zipVal)}" required />
                </label>
              </div>

              <div class="modal-actions" style="margin-top: 14px;">
                <button class="btn-primary" type="submit">Save</button>
              </div>

              <div class="modal-error small" data-modal-error hidden></div>
            </form>
          </section>

          <section class="card">
            <h2>Documents</h2>
            <p class="muted" style="margin: 0;">Upload an ID card and proof of address.</p>
            ${docsSummary}

            <div style="display:grid; gap: 14px; margin-top: 14px;">
              <form class="form" data-form="compliance-document" enctype="multipart/form-data">
                <input type="hidden" name="kind" value="id_card" />
                <label class="field">
                  <span>ID card</span>
                  <input name="file" type="file" ${hasIncrease ? 'required' : 'disabled'} />
                </label>
                <div class="modal-actions">
                  <button class="btn" type="submit" ${hasIncrease ? '' : 'disabled'}>Upload</button>
                </div>
                <div class="modal-error small" data-modal-error hidden></div>
              </form>

              <form class="form" data-form="compliance-document" enctype="multipart/form-data">
                <input type="hidden" name="kind" value="proof_of_address" />
                <label class="field">
                  <span>Proof of address</span>
                  <input name="file" type="file" ${hasIncrease ? 'required' : 'disabled'} />
                </label>
                <div class="modal-actions">
                  <button class="btn" type="submit" ${hasIncrease ? '' : 'disabled'}>Upload</button>
                </div>
                <div class="modal-error small" data-modal-error hidden></div>
              </form>
            </div>

            <h3 style="margin-top: 18px;">Uploaded</h3>
            <ul class="events">${docsRows || '<li class="small">No documents uploaded.</li>'}</ul>
          </section>

          <section class="card" style="grid-column: 1 / -1;">
            <h2>Provision account</h2>
            <p class="muted" style="margin: 0;">Creates your Increase account, account number, and lockbox.</p>
            ${provisioningSummary}

            <form class="form" data-form="onboarding-provision" style="margin-top: 14px;">
              <div class="modal-actions">
                <button class="btn-primary" type="submit" ${
                  increaseReady ? (userAccountId ? 'disabled' : '') : 'disabled'
                }>${userAccountId ? 'Provisioned' : 'Provision account'}</button>
              </div>
              <div class="modal-error small" data-modal-error hidden></div>
            </form>
          </section>
        </section>
      `;
    } else {
      subtitle = 'Entities and onboarding status';

    const canConfirm = hasIncrease && !increaseError && entities.length > 0;
    const confirmBtn = canConfirm
      ? '<button class="btn-primary" type="button" data-open-modal="confirm-entity">Confirm Entity Details</button>'
      : `<button class="btn-primary" type="button" disabled title="${
          hasIncrease ? 'No entities loaded yet' : 'Set INCREASE_API_KEY to enable'
        }">Confirm Entity Details</button>`;

    actionsHtml = `${confirmBtn}`;

    if (!hasIncrease) {
      content = `
        <section class="card">
          <h2>Compliance</h2>
          <p class="muted" style="margin: 0;">Set <code>INCREASE_API_KEY</code> in your .env to load compliance data.</p>
        </section>
      `;
    } else if (increaseError) {
      content = `
        <section class="card">
          <h2>Compliance</h2>
          <div class="alert" role="alert"><strong>Increase:</strong> ${esc(String(increaseError.message || 'error'))}</div>
          <p class="muted" style="margin: 0;">Check your API key and try again.</p>
        </section>
      `;
    } else {
      const selectedStatus = String(req.query?.status || '').trim();
      const selectedStructure = String(req.query?.structure || '').trim();
      const q = String(req.query?.q || '').trim();
      const qLower = q.toLowerCase();

      const statusOptionsHtml = `
        <option value=""${selectedStatus ? '' : ' selected'}>All statuses</option>
        <option value="active"${selectedStatus === 'active' ? ' selected' : ''}>Active</option>
        <option value="archived"${selectedStatus === 'archived' ? ' selected' : ''}>Archived</option>
        <option value="disabled"${selectedStatus === 'disabled' ? ' selected' : ''}>Disabled</option>
      `;

      const STRUCTURES = ['corporation', 'natural_person', 'joint', 'trust', 'government_authority'];
      const structureOptionsHtml = `
        <option value=""${selectedStructure ? '' : ' selected'}>All structures</option>
        ${STRUCTURES.map((s) => {
          const selected = s === selectedStructure ? ' selected' : '';
          return `<option value="${esc(s)}"${selected}>${esc(humanizeEnum(s))}</option>`;
        }).join('')}
      `;

      function entityDisplayName(e) {
        if (!e || typeof e !== 'object') return '';

        const corpName = e.corporation && typeof e.corporation === 'object' ? String(e.corporation.name || '') : '';
        if (corpName) return corpName;

        const npName =
          e.natural_person && typeof e.natural_person === 'object' ? String(e.natural_person.name || '') : '';
        if (npName) return npName;

        const trustName = e.trust && typeof e.trust === 'object' ? String(e.trust.name || '') : '';
        if (trustName) return trustName;

        const govtName =
          e.government_authority && typeof e.government_authority === 'object'
            ? String(e.government_authority.name || '')
            : '';
        if (govtName) return govtName;

        // Joint entities may not have a single name.
        const joint = e.joint && typeof e.joint === 'object' ? e.joint : null;
        const individuals = Array.isArray(joint?.individuals) ? joint.individuals : [];
        const joined = individuals
          .map((i) => (i && typeof i === 'object' ? String(i.name || '').trim() : ''))
          .filter(Boolean)
          .join(' & ');
        if (joined) return joined;

        const desc = String(e.description || '').trim();
        if (desc) return desc;

        return String(e.id || '').trim();
      }

      const filterHtml = `
        <details class="menu">
          <summary class="btn">Filter <span class="kbd" aria-hidden="true">F</span></summary>
          <div class="menu-panel" role="menu" aria-label="Filter entities">
            <form class="form tx-filter" method="get" action="/app/compliance">
              <label class="field">
                <span>Status</span>
                <select name="status">${statusOptionsHtml}</select>
              </label>

              <label class="field">
                <span>Structure</span>
                <select name="structure">${structureOptionsHtml}</select>
              </label>

              <label class="field">
                <span>Search</span>
                <input name="q" type="text" placeholder="Entity name or id" value="${esc(q)}" />
              </label>

              <div class="tx-filter-actions">
                <a class="btn" href="/app/compliance">Clear</a>
                <button class="btn-primary" type="submit">Apply</button>
              </div>
            </form>
          </div>
        </details>
      `;

      const filtered = entities.filter((e) => {
        const status = String(e?.status || '').trim();
        const structure = String(e?.structure || '').trim();

        if (selectedStatus && status !== selectedStatus) return false;
        if (selectedStructure && structure !== selectedStructure) return false;

        if (q) {
          const name = entityDisplayName(e);
          const id = String(e?.id || '');
          const hay = `${name} ${id}`.toLowerCase();
          if (!hay.includes(qLower)) return false;
        }

        return true;
      });

      function renderEntityRow(e) {
        const created = formatShortDateTime(e.created_at || '');
        const id = String(e.id || '').trim();
        const name = entityDisplayName(e) || '—';

        const structureRaw = String(e.structure || '').trim();
        const structureLabel = humanizeEnum(structureRaw) || structureRaw || '—';

        const statusRaw = String(e.status || '').trim();
        const statusLabel = humanizeEnum(statusRaw) || statusRaw || '—';
        const dotClass = `tx-dot ${entityStatusClass(statusRaw)}`;

        const risk = e.risk_rating && typeof e.risk_rating === 'object' ? String(e.risk_rating.rating || '') : '';
        const riskLabel = risk ? humanizeEnum(risk) : 'Not rated';
        const riskDot = `tx-dot ${riskRatingClass(risk)}`;

        const confirmedAt = String(e.details_confirmed_at || '').trim();
        const confirmedDisplay = confirmedAt ? formatShortDateTime(confirmedAt) : '';

        const ownersCount =
          e.corporation && Array.isArray(e.corporation.beneficial_owners)
            ? e.corporation.beneficial_owners.length
            : 0;
        const docsCount = Array.isArray(e.supplemental_documents) ? e.supplemental_documents.length : 0;

        const metaParts = [];
        if (ownersCount) metaParts.push(`${ownersCount} owner${ownersCount === 1 ? '' : 's'}`);
        if (docsCount) metaParts.push(`${docsCount} doc${docsCount === 1 ? '' : 's'}`);
        if (confirmedDisplay) metaParts.push(`Confirmed ${confirmedDisplay}`);
        const meta = metaParts.join(' · ');

        const secondary = [id, meta].filter(Boolean).join(' · ');

        const riskHtml = `<span class="pill" style="display:inline-flex;align-items:center;gap:8px;"><span class="${riskDot}" aria-hidden="true"></span>${esc(riskLabel)}</span>`;

        const href = id ? `/app/compliance/${encodeURIComponent(id)}` : '';

        if (!href) {
          return `
            <div class="tx-row">
              <div class="tx-created"><span class="${dotClass}" aria-hidden="true"></span>${esc(created || '—')}</div>
              <div class="tx-desc">
                <div>${esc(name)}</div>
                ${secondary ? `<div class="small">${esc(secondary)}</div>` : ''}
              </div>
              <div class="tx-acct">${esc(structureLabel)}</div>
              <div class="tx-cat"><span class="pill">${esc(statusLabel)}</span></div>
              <div class="tx-amt" style="text-align:right;">${riskHtml}</div>
            </div>
          `;
        }

        return `
          <a class="tx-row tx-row-link" href="${esc(href)}" aria-label="View entity ${esc(name)}">
            <div class="tx-created"><span class="${dotClass}" aria-hidden="true"></span>${esc(created || '—')}</div>
            <div class="tx-desc">
              <div>${esc(name)}</div>
              ${secondary ? `<div class="small">${esc(secondary)}</div>` : ''}
            </div>
            <div class="tx-acct">${esc(structureLabel)}</div>
            <div class="tx-cat"><span class="pill">${esc(statusLabel)}</span></div>
            <div class="tx-amt" style="text-align:right;">${riskHtml}</div>
          </a>
        `;
      }

      const rows = filtered.map((e) => renderEntityRow(e)).join('');
      const emptyState = !rows ? '<div class="tx-empty">No entities found.</div>' : '';

      const entityOptionsHtml = entities
        .map((e) => {
          const id = String(e.id || '').trim();
          const label = entityDisplayName(e) || id || 'Entity';
          return `<option value="${esc(id)}">${esc(label)}${id ? ` · ${esc(id)}` : ''}</option>`;
        })
        .join('');

      const confirmModal = `
        <div class="modal" data-modal="confirm-entity" hidden>
          <div class="modal-backdrop" data-close-modal></div>
          <div class="modal-card" role="dialog" aria-modal="true" aria-label="Confirm entity details">
            <div class="modal-head">
              <h2>Confirm entity details</h2>
              <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
            </div>

            <form class="form" data-form="confirm-entity">
              <label class="field">
                <span>Entity</span>
                <select name="entity_id" required>
                  <option value="">Select an entity</option>
                  ${entityOptionsHtml}
                </select>
              </label>

              <div class="modal-actions">
                <button class="btn" type="button" data-close-modal>Cancel</button>
                <button class="btn-primary" type="submit">Confirm</button>
              </div>

              <div class="modal-error small" data-modal-error hidden></div>
            </form>

            <p class="small" style="margin: 10px 2px 0;">Depending on your program, you may need to re-confirm entity details periodically.</p>
          </div>
        </div>
      `;

      content = `
        <section class="card">
          <div class="tx-toolbar">
            ${filterHtml}
          </div>

          <div class="tx-table" role="table" aria-label="Entities">
            <div class="tx-head" role="row">
              <div role="columnheader">Created</div>
              <div role="columnheader">Entity</div>
              <div role="columnheader">Structure</div>
              <div role="columnheader">Status</div>
              <div role="columnheader" style="text-align:right;">Risk</div>
            </div>

            ${rows}
            ${emptyState}
          </div>
        </section>

        ${confirmModal}
      `;
    }
    }
  } else if (section === 'documents') {
    const tab = documentsTab || 'statements';
    const tabLabel =
      tab === 'statements'
        ? 'Statements'
        : tab === 'tax-forms'
          ? 'Tax Forms'
          : tab === 'fees'
            ? 'Fees'
            : 'Exports';

    subtitle = tabLabel;

    const tabsHtml = `
      <div class="tabs-row">
        <div class="tabs" role="tablist" aria-label="Documents tabs">
          <a class="tab${tab === 'statements' ? ' active' : ''}" href="/app/documents?tab=statements" role="tab" aria-selected="${tab === 'statements' ? 'true' : 'false'}">Statements</a>
          <a class="tab${tab === 'tax-forms' ? ' active' : ''}" href="/app/documents?tab=tax-forms" role="tab" aria-selected="${tab === 'tax-forms' ? 'true' : 'false'}">Tax Forms</a>
          <a class="tab${tab === 'fees' ? ' active' : ''}" href="/app/documents?tab=fees" role="tab" aria-selected="${tab === 'fees' ? 'true' : 'false'}">Fees</a>
          <a class="tab${tab === 'exports' ? ' active' : ''}" href="/app/documents?tab=exports" role="tab" aria-selected="${tab === 'exports' ? 'true' : 'false'}">Exports</a>
        </div>
      </div>
    `;

    if (tab === 'exports') {
      const canCreate = hasIncrease && !increaseError;
      actionsHtml = canCreate
        ? `
          <details class="menu">
            <summary class="btn">Create</summary>
            <div class="menu-panel" role="menu" aria-label="Create">
              <button class="menu-item" type="button" role="menuitem" data-open-modal="create-export">
                <div class="menu-title">Export</div>
                <div class="menu-desc">Generate a CSV or statement export.</div>
              </button>
              <button class="menu-item" type="button" role="menuitem" data-open-modal="upload-file">
                <div class="menu-title">Upload file</div>
                <div class="menu-desc">Send a document to Increase (limited purposes).</div>
              </button>
            </div>
          </details>
        `
        : `<button class="btn" type="button" disabled title="${
            hasIncrease ? 'Unable to load Increase data' : 'Set INCREASE_API_KEY to enable'
          }">Create</button>`;
    } else {
      actionsHtml = '';
    }

    if (!hasIncrease) {
      content = `
        <section class="card">
          ${tabsHtml}
          <h2>Documents</h2>
          <p class="muted" style="margin: 0;">Set <code>INCREASE_API_KEY</code> in your .env to load documents.</p>
        </section>
      `;
    } else if (increaseError) {
      content = `
        <section class="card">
          ${tabsHtml}
          <h2>Documents</h2>
          <div class="alert" role="alert"><strong>Increase:</strong> ${esc(String(increaseError.message || 'error'))}</div>
          <p class="muted" style="margin: 0;">Check your API key and try again.</p>
        </section>
      `;
    } else if (tab === 'statements') {
      const selectedAccountId = '';

      const accountOptionsWithAllHtml = `
        <option value=""${selectedAccountId ? '' : ' selected'}>All accounts</option>
        ${increaseAccounts
          .map((a) => {
            const label = String(a.name || a.id || 'Account');
            const id = String(a.id || '');
            const selected = id && id === selectedAccountId ? ' selected' : '';
            return `<option value="${esc(id)}"${selected}>${esc(label)}</option>`;
          })
          .join('')}
      `;

      const filterHtml = `
        <details class="menu">
          <summary class="btn">Filter <span class="kbd" aria-hidden="true">F</span></summary>
          <div class="menu-panel" role="menu" aria-label="Filter statements">
            <form class="form tx-filter" method="get" action="/app/documents">
              <input type="hidden" name="tab" value="statements" />
              <label class="field">
                <span>Account</span>
                <select name="account_id">${accountOptionsWithAllHtml}</select>
              </label>

              <div class="tx-filter-actions">
                <a class="btn" href="/app/documents?tab=statements">Clear</a>
                <button class="btn-primary" type="submit">Apply</button>
              </div>
            </form>
          </div>
        </details>
      `;

      const accountNameById = new Map(
        increaseAccounts.map((a) => [String(a.id || ''), String(a.name || a.id || '')])
      );

      function renderStatementRow(s) {
        const start = formatShortDateTime(s.statement_period_start || '');
        const end = formatShortDateTime(s.statement_period_end || '');
        const createdAt = formatShortDateTime(s.created_at || '');

        const acctId = String(s.account_id || '');
        const acctName = accountNameById.get(acctId) || acctId || '—';

        const starting = typeof s.starting_balance === 'number' ? formatUsdFromCents(s.starting_balance) : '—';
        const ending = typeof s.ending_balance === 'number' ? formatUsdFromCents(s.ending_balance) : '—';

        const fileId = String(s.file_id || '').trim() || '—';

        const secondaryParts = [];
        if (end) secondaryParts.push(`Ends ${end}`);
        if (createdAt) secondaryParts.push(`Created ${createdAt}`);
        const secondary = secondaryParts.join(' · ');

        return `
          <div class="tx-row">
            <div class="tx-created"><span class="tx-dot completed" aria-hidden="true"></span>${esc(start || '—')}</div>
            <div class="tx-desc">
              <div>${esc(acctName)}</div>
              ${secondary ? `<div class="small">${esc(secondary)}</div>` : ''}
            </div>
            <div class="tx-acct">${esc(starting)}</div>
            <div class="tx-cat">${esc(fileId)}</div>
            <div class="tx-amt">${esc(ending)}</div>
          </div>
        `;
      }

      const rows = accountStatements.map((s) => renderStatementRow(s)).join('');
      const emptyState = !rows ? '<div class="tx-empty">No statements found.</div>' : '';

      content = `
        <section class="card">
          ${tabsHtml}

          <div class="tx-table" role="table" aria-label="Statements">
            <div class="tx-head" role="row">
              <div role="columnheader">Period start</div>
              <div role="columnheader">Account</div>
              <div role="columnheader">Starting</div>
              <div role="columnheader">File</div>
              <div role="columnheader" style="text-align:right;">Ending</div>
            </div>

            ${rows}
            ${emptyState}
          </div>
        </section>
      `;
    } else if (tab === 'tax-forms' || tab === 'fees') {
      function renderFileRow(file) {
        const created = formatShortDateTime(file.created_at || '');

        const id = String(file.id || '').trim();
        const filename = String(file.filename || '').trim();
        const description = String(file.description || '').trim();

        const purposeRaw = String(file.purpose || '').trim();
        const purposeLabel = humanizeEnum(purposeRaw) || purposeRaw || '—';

        const directionRaw = String(file.direction || '').trim();
        const directionLabel = humanizeEnum(directionRaw) || directionRaw || '—';
        const dotClass = `tx-dot ${fileDirectionClass(directionRaw)}`;

        const mime = String(file.mime_type || '').trim();

        const secondaryParts = [];
        if (description) secondaryParts.push(description);
        if (id) secondaryParts.push(id);
        const secondary = secondaryParts.join(' · ');

        return `
          <div class="tx-row">
            <div class="tx-created"><span class="${dotClass}" aria-hidden="true"></span>${esc(created || '—')}</div>
            <div class="tx-desc">
              <div>${esc(filename || '—')}</div>
              ${secondary ? `<div class="small">${esc(secondary)}</div>` : ''}
            </div>
            <div class="tx-acct"><span class="pill">${esc(purposeLabel)}</span></div>
            <div class="tx-cat"><span class="pill">${esc(directionLabel)}</span></div>
            <div class="tx-amt">${esc(mime || '—')}</div>
          </div>
        `;
      }

      const rows = files.map((f) => renderFileRow(f)).join('');
      const emptyState =
        !rows
          ? '<div class="tx-empty">Tax forms and fee statements are not available yet in this demo. Use Exports instead.</div>'
          : '';

      content = `
        <section class="card">
          ${tabsHtml}

          <div class="tx-table" role="table" aria-label="Documents">
            <div class="tx-head" role="row">
              <div role="columnheader">Created</div>
              <div role="columnheader">Filename</div>
              <div role="columnheader">Purpose</div>
              <div role="columnheader">Direction</div>
              <div role="columnheader" style="text-align:right;">MIME</div>
            </div>

            ${rows}
            ${emptyState}
          </div>
        </section>
      `;
    } else {
      function renderExportRow(ex) {
        const categoryRaw = String(ex.category || '').trim();
        const typeLabel = humanizeEnum(categoryRaw) || categoryRaw || '—';

        const statusRaw = String(ex.status || '').trim();
        const statusLabel = humanizeEnum(statusRaw) || statusRaw || '—';
        const statusClass = transferStatusClass(statusRaw);
        const dotClass = `tx-dot ${statusClass}`;

        const created = formatShortDateTime(ex.created_at || '');
        const exportId = String(ex.id || '').trim();
        const fileId = String(ex.file_id || '').trim();
        const downloadUrl = String(ex.file_download_url || '').trim();

        const downloadHtml =
          statusRaw === 'complete' && downloadUrl
            ? `<a class="btn" href="${esc(downloadUrl)}" target="_blank" rel="noreferrer">Download</a>`
            : '';

        const descLine = fileId || exportId || '—';
        const secondary = exportId && fileId && exportId !== fileId ? exportId : '';

        return `
          <div class="tx-row">
            <div class="tx-created"><span class="${dotClass}" aria-hidden="true"></span>${esc(typeLabel)}</div>
            <div class="tx-desc">
              <div>${esc(descLine)}</div>
              ${downloadHtml ? `<div style="margin-top: 8px;">${downloadHtml}</div>` : secondary ? `<div class="small">${esc(secondary)}</div>` : ''}
            </div>
            <div class="tx-acct">${esc(req.user.email || 'Me')}</div>
            <div class="tx-cat"><span class="pill">${esc(statusLabel)}</span></div>
            <div class="tx-amt">${esc(created || '—')}</div>
          </div>
        `;
      }

      const rows = exportsList.map((ex) => renderExportRow(ex)).join('');
      const emptyState = !rows
        ? `
          <div class="tx-empty">
            <div style="font-weight: 900;">No Exports</div>
            <div class="small" style="margin-top: 6px;">You can export transactions, balances, and statements. The downloadable files will appear here.</div>
          </div>
        `
        : '';

      const createExportModal = `
        <div class="modal" data-modal="create-export" hidden>
          <div class="modal-backdrop" data-close-modal></div>
          <div class="modal-card" role="dialog" aria-modal="true" aria-label="Create export">
            <div class="modal-head">
              <h2>Create export</h2>
              <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
            </div>

            <form class="form" data-form="create-export">
              <label class="field">
                <span>Category</span>
                <select name="category" required>
                  <option value="transaction_csv">Transaction CSV</option>
                  <option value="balance_csv">Balance CSV</option>
                  <option value="account_statement_ofx">Account statement (OFX)</option>
                  <option value="account_statement_bai2">Account statement (BAI2)</option>
                </select>
              </label>

              <p class="small" style="margin: 6px 2px 0;">
                Exports are created for your account. If you haven't provisioned an account yet, finish Compliance first.
              </p>

              <div class="modal-actions">
                <button class="btn" type="button" data-close-modal>Cancel</button>
                <button class="btn-primary" type="submit">Create</button>
              </div>

              <div class="modal-error small" data-modal-error hidden></div>
            </form>

            <p class="small" style="margin: 10px 2px 0;">
              Tip: exports are often <strong>pending</strong> for a moment — refresh to see them complete.
            </p>
          </div>
        </div>
      `;

      const CREATE_FILE_PURPOSES = [
        'card_dispute_attachment',
        'check_image_front',
        'check_image_back',
        'mailed_check_image',
        'check_attachment',
        'check_voucher_image',
        'form_ss_4',
        'identity_document',
        'loan_application_supplemental_document',
        'other',
        'trust_formation_document',
        'digital_wallet_artwork',
        'digital_wallet_app_icon',
        'physical_card_front',
        'physical_card_carrier',
        'document_request',
        'entity_supplemental_document',
        'unusual_activity_report_attachment',
        'proof_of_authorization_request_submission',
      ];

      const uploadPurposeOptionsHtml = CREATE_FILE_PURPOSES.map((p) => {
        const selected = p === 'entity_supplemental_document' ? ' selected' : '';
        return `<option value="${esc(p)}"${selected}>${esc(humanizeEnum(p))}</option>`;
      }).join('');

      const uploadModal = `
        <div class="modal" data-modal="upload-file" hidden>
          <div class="modal-backdrop" data-close-modal></div>
          <div class="modal-card" role="dialog" aria-modal="true" aria-label="Upload file">
            <div class="modal-head">
              <h2>Upload file</h2>
              <button class="icon-btn" type="button" data-close-modal aria-label="Close">×</button>
            </div>

            <form class="form" data-form="upload-file">
              <label class="field">
                <span>File</span>
                <input name="file" type="file" required />
              </label>

              <label class="field">
                <span>Purpose</span>
                <select name="purpose" required>
                  ${uploadPurposeOptionsHtml}
                </select>
              </label>

              <label class="field">
                <span>Description (optional)</span>
                <input name="description" type="text" maxlength="200" placeholder="e.g. Bank letter" />
              </label>

              <div class="modal-actions">
                <button class="btn" type="button" data-close-modal>Cancel</button>
                <button class="btn-primary" type="submit">Upload</button>
              </div>

              <div class="modal-error small" data-modal-error hidden></div>
            </form>

            <p class="small" style="margin: 10px 2px 0;">Some file purposes (like statements) are generated by Increase and cannot be uploaded.</p>
          </div>
        </div>
      `;

      content = `
        <section class="card">
          ${tabsHtml}

          <div class="tx-table" role="table" aria-label="Exports">
            <div class="tx-head" role="row">
              <div role="columnheader">Type</div>
              <div role="columnheader">Description</div>
              <div role="columnheader">Created by</div>
              <div role="columnheader">Status</div>
              <div role="columnheader" style="text-align:right;">Created</div>
            </div>

            ${rows}
            ${emptyState}
          </div>
        </section>

        ${createExportModal}
        ${uploadModal}
      `;
    }
  } else if (section === 'lockboxes') {
    subtitle = 'Lockboxes for inbound check payments';

    // Consumer UX: one default lockbox per user, created during onboarding provisioning.
    const hasLockbox = Boolean(userLockboxId);

    actionsHtml = !hasIncrease
      ? ''
      : hasLockbox
        ? ''
        : `<button class="btn" type="button" disabled title="Finish compliance and provision your account to enable lockboxes">Lockboxes</button>`;

    if (!hasIncrease) {
      content = `
        <section class="card">
          <h2>Lockboxes</h2>
          <p class="muted" style="margin: 0;">
            Set <code>INCREASE_API_KEY</code> in your .env to load lockboxes.
          </p>
        </section>
      `;
    } else if (increaseError) {
      content = `
        <section class="card">
          <h2>Lockboxes</h2>
          <div class="alert" role="alert"><strong>Increase:</strong> ${esc(String(increaseError.message || 'error'))}</div>
          <p class="muted" style="margin: 0;">Check your API key and try again.</p>
        </section>
      `;
    } else if (!hasLockbox) {
      content = `
        <section class="card">
          <h2>Lockboxes</h2>
          <p class="muted" style="margin: 0;">Finish compliance and provision your account to enable lockboxes.</p>
          <div style="margin-top: 12px; display: flex; gap: 10px; flex-wrap: wrap;">
            <a class="btn-primary" href="/app/compliance">Go to Compliance</a>
            <a class="btn" href="/app/overview">Back to Overview</a>
          </div>
        </section>
      `;
    } else {
      function formatLockboxAddress(addr, fallbackRecipient) {
        const a = addr && typeof addr === 'object' ? addr : {};
        const recipient = String(a.recipient || fallbackRecipient || '').trim();
        const line1 = String(a.line1 || '').trim();
        const line2 = String(a.line2 || '').trim();
        const city = String(a.city || '').trim();
        const state = String(a.state || '').trim();
        const postal = String(a.postal_code || '').trim();

        const parts = [];
        if (recipient) parts.push(recipient);

        const street = [line1, line2].filter(Boolean).join(' ');
        if (street) parts.push(street);

        const locality = [city, state, postal].filter(Boolean).join(' ');
        if (locality) parts.push(locality);

        return parts.join('\n');
      }

      const lb = lockboxes.find((x) => String(x?.id || '').trim() === userLockboxId) || lockboxes[0] || null;

      const created = lb ? formatShortDateTime(lb.created_at || lb.created || '') : '';
      const behaviorRaw = lb ? String(lb.check_deposit_behavior || '').trim() : '';
      const behaviorLabel = humanizeEnum(behaviorRaw) || behaviorRaw || '—';
      const addressStr = lb ? formatLockboxAddress(lb.address, lb.recipient_name) : '';

      content = `
        <section class="card">
          <h2>Your lockbox</h2>
          <p class="muted" style="margin: 0;">Use this mailing address to receive inbound checks.</p>

          <div style="margin-top: 14px; display: grid; gap: 10px;">
            <div>
              <div class="small">Mailing address</div>
              <pre style="margin: 6px 0 0; white-space: pre-wrap;">${esc(addressStr || '—')}</pre>
            </div>

            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px;">
              <div>
                <div class="small">Deposit behavior</div>
                <div style="margin-top: 6px;"><span class="pill">${esc(behaviorLabel)}</span></div>
              </div>
              <div>
                <div class="small">Lockbox ID</div>
                <div style="margin-top: 6px;">${esc(userLockboxId)}</div>
              </div>
              <div>
                <div class="small">Created</div>
                <div style="margin-top: 6px;">${esc(created || '—')}</div>
              </div>
            </div>
          </div>
        </section>

        <section class="card" style="margin-top: 12px;">
          <h2>Inbox</h2>
          <p class="muted" style="margin: 0;">Inbound mail items will appear here next.</p>
        </section>
      `;
    }
  } else {
    content = `
      <section class="card">
        <h2>${esc(pageDef.title)}</h2>
        <p class="muted" style="margin: 0;">This page is scaffolded. We’ll wire it to SQL + Increase API next.</p>
      </section>
    `;
  }

  res.type('html').send(
    renderAppLayout({
      title: pageDef.title,
      subtitle,
      activeKey: pageDef.key,
      user: req.user,
      content,
      actionsHtml,
    })
  );
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`Dodo Checks server running on http://localhost:${port}`);
});
