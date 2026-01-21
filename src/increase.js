'use strict';

const DEFAULT_INCREASE_BASE_URL = 'https://api.increase.com';

function parseBool(value, defaultValue = false) {
  if (value == null) return defaultValue;
  const s = String(value).trim().toLowerCase();
  if (!s) return defaultValue;
  return ['1', 'true', 'yes', 'y', 'on'].includes(s);
}

function getApiKey(explicitKey) {
  const key = explicitKey ?? process.env.INCREASE_API_KEY;
  if (!key || !String(key).trim()) return null;
  return String(key).trim();
}

function getBaseUrl(explicitBaseUrl) {
  const raw =
    explicitBaseUrl ??
    process.env.INCREASE_URL ??
    process.env.INCREASE_BASE_URL ??
    process.env.INCREASE_API_URL;
  if (!raw || !String(raw).trim()) return DEFAULT_INCREASE_BASE_URL;

  // Normalize trailing slash.
  return String(raw).trim().replace(/\/+$/, '');
}

function getDebug(explicitDebug) {
  if (typeof explicitDebug === 'boolean') return explicitDebug;
  if (explicitDebug != null) return Boolean(explicitDebug);
  return parseBool(process.env.INCREASE_DEBUG, false);
}

function redact(value, path = []) {
  if (value == null) return value;

  if (Array.isArray(value)) {
    return value.map((v) => redact(v, path));
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
        out[key] = redact(v, nextPath);
      }
    }
    return out;
  }

  return value;
}

function buildUrl(baseUrl, pathname, query) {
  const url = new URL(pathname, baseUrl);
  if (query && typeof query === 'object') {
    for (const [k, v] of Object.entries(query)) {
      if (v == null) continue;
      url.searchParams.set(k, String(v));
    }
  }
  return url.toString();
}

function createIncreaseClient({ apiKey, baseUrl, debug } = {}) {
  const key = getApiKey(apiKey);
  const base = getBaseUrl(baseUrl);
  const dbg = getDebug(debug);

  if (dbg) {
    // eslint-disable-next-line no-console
    console.log(`[increase] baseUrl=${base}`);
  }

  async function request({ method, pathname, query, body, headers }) {
    if (!key) {
      throw new Error('INCREASE_API_KEY is not set (required to call Increase API)');
    }

    const url = buildUrl(base, pathname, query);

    if (dbg) {
      // eslint-disable-next-line no-console
      console.log('[increase] request', {
        method,
        url,
        body: body == null ? undefined : redact(body),
      });
    }

    const res = await fetch(url, {
      method,
      headers: {
        Authorization: `Bearer ${key}`,
        ...(body == null ? {} : { 'Content-Type': 'application/json' }),
        ...(headers && typeof headers === 'object' ? headers : {}),
      },
      body: body == null ? undefined : JSON.stringify(body),
    });

    if (dbg) {
      // eslint-disable-next-line no-console
      console.log('[increase] response', { method, url, status: res.status });
    }

    const text = await res.text();
    let json;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = text;
    }

    if (!res.ok) {
      if (dbg) {
        // eslint-disable-next-line no-console
        console.log('[increase] error', {
          method,
          url,
          status: res.status,
          body: redact(json),
        });
      }

      const msg = typeof json === 'object' && json && json.error ? json.error : res.statusText;
      const err = new Error(`Increase API error (${res.status}): ${msg}`);
      err.status = res.status;
      err.body = json;
      err.url = url;
      err.baseUrl = base;
      throw err;
    }

    return json;
  }

  async function requestMultipart({ method, pathname, query, formData, headers }) {
    if (!key) {
      throw new Error('INCREASE_API_KEY is not set (required to call Increase API)');
    }

    const url = buildUrl(base, pathname, query);

    if (dbg) {
      const fields = [];
      try {
        // Avoid logging binary bodies; just log field keys.
        for (const pair of formData.entries()) {
          fields.push(String(pair[0]));
        }
      } catch {
        // ignore
      }

      // eslint-disable-next-line no-console
      console.log('[increase] request', { method, url, multipart: true, fields });
    }

    const res = await fetch(url, {
      method,
      headers: {
        Authorization: `Bearer ${key}`,
        ...(headers && typeof headers === 'object' ? headers : {}),
      },
      body: formData,
    });

    if (dbg) {
      // eslint-disable-next-line no-console
      console.log('[increase] response', { method, url, status: res.status });
    }

    const text = await res.text();
    let json;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = text;
    }

    if (!res.ok) {
      if (dbg) {
        // eslint-disable-next-line no-console
        console.log('[increase] error', {
          method,
          url,
          status: res.status,
          body: redact(json),
        });
      }

      const msg = typeof json === 'object' && json && json.error ? json.error : res.statusText;
      const err = new Error(`Increase API error (${res.status}): ${msg}`);
      err.status = res.status;
      err.body = json;
      err.url = url;
      err.baseUrl = base;
      throw err;
    }

    return json;
  }

  return {
    request,

    // Accounts
    listAccounts: (query) => request({ method: 'GET', pathname: '/accounts', query }),
    retrieveAccount: ({ accountId }) => request({ method: 'GET', pathname: `/accounts/${encodeURIComponent(accountId)}` }),
    createAccount: ({ name, entityId, informationalEntityId, programId, idempotencyKey }) =>
      request({
        method: 'POST',
        pathname: '/accounts',
        headers: idempotencyKey ? { 'Idempotency-Key': String(idempotencyKey) } : undefined,
        body: {
          name,
          entity_id: entityId,
          ...(informationalEntityId ? { informational_entity_id: informationalEntityId } : {}),
          program_id: programId,
        },
      }),
    getAccountBalance: ({ accountId }) =>
      request({ method: 'GET', pathname: `/accounts/${encodeURIComponent(accountId)}/balance` }),

    // Transactions
    listTransactions: (query) => request({ method: 'GET', pathname: '/transactions', query }),
    retrieveTransaction: ({ transactionId }) =>
      request({ method: 'GET', pathname: `/transactions/${encodeURIComponent(transactionId)}` }),

    listPendingTransactions: (query) => request({ method: 'GET', pathname: '/pending_transactions', query }),
    retrievePendingTransaction: ({ pendingTransactionId }) =>
      request({ method: 'GET', pathname: `/pending_transactions/${encodeURIComponent(pendingTransactionId)}` }),
    releasePendingTransaction: ({ pendingTransactionId }) =>
      request({ method: 'POST', pathname: `/pending_transactions/${encodeURIComponent(pendingTransactionId)}/release` }),

    // Cards
    listCards: (query) => request({ method: 'GET', pathname: '/cards', query }),
    retrieveCard: ({ cardId }) => request({ method: 'GET', pathname: `/cards/${encodeURIComponent(cardId)}` }),
    createCard: ({ accountId, description, billingAddress }) =>
      request({
        method: 'POST',
        pathname: '/cards',
        body: {
          account_id: accountId,
          ...(description ? { description } : {}),
          ...(billingAddress ? { billing_address: billingAddress } : {}),
        },
      }),
    updateCard: ({ cardId, body }) =>
      request({
        method: 'PATCH',
        pathname: `/cards/${encodeURIComponent(cardId)}`,
        body: body || {},
      }),

    // Account Numbers
    listAccountNumbers: (query) => request({ method: 'GET', pathname: '/account_numbers', query }),
    retrieveAccountNumber: ({ accountNumberId }) =>
      request({ method: 'GET', pathname: `/account_numbers/${encodeURIComponent(accountNumberId)}` }),
    createAccountNumber: ({ accountId, name }) =>
      request({
        method: 'POST',
        pathname: '/account_numbers',
        body: {
          account_id: accountId,
          name,
        },
      }),
    updateAccountNumber: ({ accountNumberId, body }) =>
      request({
        method: 'PATCH',
        pathname: `/account_numbers/${encodeURIComponent(accountNumberId)}`,
        body: body || {},
      }),

    // Inbound ACH Transfers
    listInboundAchTransfers: (query) => request({ method: 'GET', pathname: '/inbound_ach_transfers', query }),
    returnInboundAchTransfer: ({ inboundAchTransferId, reason }) =>
      request({
        method: 'POST',
        pathname: `/inbound_ach_transfers/${encodeURIComponent(inboundAchTransferId)}/transfer_return`,
        body: {
          reason,
        },
      }),

    // External Accounts
    listExternalAccounts: (query) => request({ method: 'GET', pathname: '/external_accounts', query }),
    retrieveExternalAccount: ({ externalAccountId }) =>
      request({ method: 'GET', pathname: `/external_accounts/${encodeURIComponent(externalAccountId)}` }),
    createExternalAccount: ({ description, routingNumber, accountNumber, accountHolder, funding, idempotencyKey }) =>
      request({
        method: 'POST',
        pathname: '/external_accounts',
        headers: idempotencyKey ? { 'Idempotency-Key': String(idempotencyKey) } : undefined,
        body: {
          description,
          routing_number: routingNumber,
          account_number: accountNumber,
          ...(accountHolder ? { account_holder: accountHolder } : {}),
          ...(funding ? { funding } : {}),
        },
      }),

    // Lockboxes
    listLockboxes: (query) => request({ method: 'GET', pathname: '/lockboxes', query }),
    createLockbox: ({ accountId, description, recipientName, idempotencyKey }) =>
      request({
        method: 'POST',
        pathname: '/lockboxes',
        headers: idempotencyKey ? { 'Idempotency-Key': String(idempotencyKey) } : undefined,
        body: {
          account_id: accountId,
          ...(description ? { description } : {}),
          ...(recipientName ? { recipient_name: recipientName } : {}),
        },
      }),

    // Inbound Mail Items
    listInboundMailItems: (query) => request({ method: 'GET', pathname: '/inbound_mail_items', query }),

    // Files
    listFiles: (query) => request({ method: 'GET', pathname: '/files', query }),
    retrieveFile: ({ fileId }) =>
      request({ method: 'GET', pathname: `/files/${encodeURIComponent(fileId)}` }),
    createFile: ({ fileBuffer, filename, mimeType, purpose, description }) => {
      const p = String(purpose || '').trim();
      if (!p) throw new Error('purpose is required to create a file');
      if (!fileBuffer) throw new Error('fileBuffer is required to create a file');

      const fd = new FormData();
      const blob = new Blob([fileBuffer], { type: mimeType || 'application/octet-stream' });
      fd.append('file', blob, filename || 'document');
      fd.append('purpose', p);
      if (description) fd.append('description', String(description));

      return requestMultipart({ method: 'POST', pathname: '/files', formData: fd });
    },
    // Check Deposits
    listCheckDeposits: (query) => request({ method: 'GET', pathname: '/check_deposits', query }),
    createCheckDeposit: ({ accountId, amountCents, frontFileId, backFileId, description, idempotencyKey }) =>
      request({
        method: 'POST',
        pathname: '/check_deposits',
        headers: idempotencyKey ? { 'Idempotency-Key': String(idempotencyKey) } : undefined,
        body: {
          account_id: accountId,
          amount: amountCents,
          front_image_file_id: frontFileId,
          back_image_file_id: backFileId,
          ...(description ? { description } : {}),
        },
      }),

    // Internal (book) transfers between Increase accounts
    createAccountTransfer: ({ fromAccountId, toAccountId, amountCents, description }) =>
      request({
        method: 'POST',
        pathname: '/account_transfers',
        body: {
          account_id: fromAccountId,
          destination_account_id: toAccountId,
          amount: amountCents,
          ...(description ? { description } : {}),
        },
      }),

    // Account Statements
    listAccountStatements: (query) => request({ method: 'GET', pathname: '/account_statements', query }),
    retrieveAccountStatement: ({ accountStatementId }) =>
      request({
        method: 'GET',
        pathname: `/account_statements/${encodeURIComponent(accountStatementId)}`,
      }),

    // Exports
    listExports: (query) => request({ method: 'GET', pathname: '/exports', query }),
    retrieveExport: ({ exportId }) =>
      request({ method: 'GET', pathname: `/exports/${encodeURIComponent(exportId)}` }),
    createExport: ({ body, idempotencyKey }) =>
      request({
        method: 'POST',
        pathname: '/exports',
        headers: idempotencyKey ? { 'Idempotency-Key': String(idempotencyKey) } : undefined,
        body: body || {},
      }),

    // Entities
    listEntities: (query) => request({ method: 'GET', pathname: '/entities', query }),
    retrieveEntity: ({ entityId }) =>
      request({ method: 'GET', pathname: `/entities/${encodeURIComponent(entityId)}` }),
    createEntity: ({ body, idempotencyKey }) =>
      request({
        method: 'POST',
        pathname: '/entities',
        headers: idempotencyKey ? { 'Idempotency-Key': String(idempotencyKey) } : undefined,
        body: body || {},
      }),

    // Entity Supplemental Documents
    listEntitySupplementalDocuments: (query) =>
      request({ method: 'GET', pathname: '/entity_supplemental_documents', query }),
    createEntitySupplementalDocument: ({ entityId, fileId }) =>
      request({
        method: 'POST',
        pathname: '/entity_supplemental_documents',
        body: {
          entity_id: entityId,
          file_id: fileId,
        },
      }),

    // Transfers
    listAchTransfers: (query) => request({ method: 'GET', pathname: '/ach_transfers', query }),
    cancelAchTransfer: ({ achTransferId }) =>
      request({ method: 'POST', pathname: `/ach_transfers/${encodeURIComponent(achTransferId)}/cancel` }),
    createAchTransfer: ({
      accountId,
      routingNumber,
      accountNumber,
      amountCents,
      statementDescriptor,
      idempotencyKey,
    }) =>
      request({
        method: 'POST',
        pathname: '/ach_transfers',
        headers: idempotencyKey ? { 'Idempotency-Key': String(idempotencyKey) } : undefined,
        body: {
          account_id: accountId,
          routing_number: routingNumber,
          account_number: accountNumber,
          amount: amountCents,
          statement_descriptor: statementDescriptor,
        },
      }),

    cancelCheckTransfer: ({ checkTransferId }) =>
      request({ method: 'POST', pathname: `/check_transfers/${encodeURIComponent(checkTransferId)}/cancel` }),

    cancelWireTransfer: ({ wireTransferId }) =>
      request({ method: 'POST', pathname: `/wire_transfers/${encodeURIComponent(wireTransferId)}/cancel` }),

    cancelRealTimePaymentsTransfer: ({ realTimePaymentsTransferId }) =>
      request({
        method: 'POST',
        pathname: `/real_time_payments_transfers/${encodeURIComponent(realTimePaymentsTransferId)}/cancel`,
      }),

    // Check transfers (mail checks)
    listCheckTransfers: (query) => request({ method: 'GET', pathname: '/check_transfers', query }),
    createCheckTransfer: ({
      accountId,
      sourceAccountNumberId,
      amountCents,
      recipientName,
      memo,
      mailingAddress,
      idempotencyKey,
    }) =>
      request({
        method: 'POST',
        pathname: '/check_transfers',
        headers: idempotencyKey ? { 'Idempotency-Key': String(idempotencyKey) } : undefined,
        body: {
          account_id: accountId,
          amount: amountCents,
          ...(sourceAccountNumberId ? { source_account_number_id: sourceAccountNumberId } : {}),
          fulfillment_method: 'physical_check',
          physical_check: {
            recipient_name: recipientName,
            memo,
            mailing_address: mailingAddress,
          },
        },
      }),

    // Wire transfers
    listWireTransfers: (query) => request({ method: 'GET', pathname: '/wire_transfers', query }),
    createWireTransfer: ({
      accountId,
      amountCents,
      routingNumber,
      accountNumber,
      creditorName,
      remittanceMessage,
      idempotencyKey,
    }) =>
      request({
        method: 'POST',
        pathname: '/wire_transfers',
        headers: idempotencyKey ? { 'Idempotency-Key': String(idempotencyKey) } : undefined,
        body: {
          account_id: accountId,
          amount: amountCents,
          routing_number: routingNumber,
          account_number: accountNumber,
          creditor: {
            name: creditorName,
          },
          remittance: {
            category: 'unstructured',
            unstructured: {
              message: remittanceMessage,
            },
          },
        },
      }),

    // Inbound wire transfers
    listInboundWireTransfers: (query) => request({ method: 'GET', pathname: '/inbound_wire_transfers', query }),
  };
}

module.exports = {
  createIncreaseClient,
};
