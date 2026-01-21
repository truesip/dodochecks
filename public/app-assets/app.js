(function () {
  function qs(sel, root) {
    return (root || document).querySelector(sel);
  }

  function qsa(sel, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(sel));
  }

  // Search focus (Ctrl/Cmd + K)
  var searchInput = qs('.search input');
  window.addEventListener('keydown', function (e) {
    var key = String(e.key || '').toLowerCase();
    if ((e.ctrlKey || e.metaKey) && key === 'k') {
      e.preventDefault();
      if (searchInput) searchInput.focus();
    }
  });

  function openModal(name) {
    var modal = qs('.modal[data-modal="' + name + '"]');
    if (!modal) return;
    modal.hidden = false;
    var first = qs('input, select, button', modal);
    if (first) first.focus();
  }

  function closeModal(modal) {
    if (!modal) return;
    modal.hidden = true;
    var err = qs('[data-modal-error]', modal);
    if (err) {
      err.textContent = '';
      err.hidden = true;
    }
  }

  qsa('[data-open-modal]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var name = btn.getAttribute('data-open-modal');
      var parentDetails = btn.closest('details');
      if (parentDetails) parentDetails.removeAttribute('open');
      openModal(name);
    });
  });

  qsa('[data-close-modal]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      closeModal(btn.closest('.modal'));
    });
  });

  qsa('.modal').forEach(function (modal) {
    modal.addEventListener('click', function (e) {
      if (e.target && e.target.classList && e.target.classList.contains('modal-backdrop')) {
        closeModal(modal);
      }
    });
  });

  async function postJson(url, body) {
    var res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {}),
    });

    var text = await res.text();
    var json;
    try {
      json = text ? JSON.parse(text) : null;
    } catch (e) {
      json = { error: text };
    }

    if (!res.ok) {
      var msg = (json && json.error) ? json.error : ('Request failed (' + res.status + ')');
      var err = new Error(msg);
      err.status = res.status;
      err.body = json;
      throw err;
    }

    return json;
  }

  async function postFormData(url, formData) {
    var res = await fetch(url, {
      method: 'POST',
      body: formData,
    });

    var text = await res.text();
    var json;
    try {
      json = text ? JSON.parse(text) : null;
    } catch (e) {
      json = { error: text };
    }

    if (!res.ok) {
      var msg = (json && json.error) ? json.error : ('Request failed (' + res.status + ')');
      var err = new Error(msg);
      err.status = res.status;
      err.body = json;
      throw err;
    }

    return json;
  }

  function setModalError(modal, message) {
    var el = qs('[data-modal-error]', modal);
    if (!el) return;
    el.textContent = message;
    el.hidden = false;
  }

  function clearInlineError() {
    var el = qs('[data-inline-error]');
    if (!el) return;
    el.textContent = '';
    el.hidden = true;
  }

  function setInlineError(message) {
    var el = qs('[data-inline-error]');
    if (!el) {
      window.alert(message);
      return;
    }
    el.textContent = message;
    el.hidden = false;
  }

  // Create Account
  var createForm = qs('form[data-form="create-account"]');
  if (createForm) {
    createForm.addEventListener('submit', async function (e) {
      e.preventDefault();

      var modal = createForm.closest('.modal');
      var submit = qs('button[type="submit"]', createForm);
      var name = String(qs('input[name="name"]', createForm).value || '').trim();

      if (!name) {
        setModalError(modal, 'Account name is required.');
        return;
      }

      if (submit) submit.disabled = true;

      try {
        await postJson('/api/accounts', { name: name });
        window.location.reload();
      } catch (err) {
        setModalError(modal, err.message || 'Something went wrong.');
        if (submit) submit.disabled = false;
      }
    });
  }

  // Create Card
  var createCardForm = qs('form[data-form="create-card"]');
  if (createCardForm) {
    createCardForm.addEventListener('submit', async function (e) {
      e.preventDefault();

      var modal = createCardForm.closest('.modal');
      var submit = qs('button[type="submit"]', createCardForm);

      var accountId = String(qs('[name="account_id"]', createCardForm).value || '').trim();
      var description = String(qs('[name="description"]', createCardForm).value || '').trim();

      var line1 = String(qs('[name="billing_line1"]', createCardForm).value || '').trim();
      var line2 = String(qs('[name="billing_line2"]', createCardForm).value || '').trim();
      var city = String(qs('[name="billing_city"]', createCardForm).value || '').trim();
      var state = String(qs('[name="billing_state"]', createCardForm).value || '').trim();
      var postal = String(qs('[name="billing_postal_code"]', createCardForm).value || '').trim();

      if (!accountId) {
        setModalError(modal, 'Account is required.');
        return;
      }

      var anyBilling = Boolean(line1 || line2 || city || state || postal);
      var billing;

      if (anyBilling) {
        if (!line1 || !city || !state || !postal) {
          setModalError(modal, 'Billing address requires line 1, city, state, and postal code (or leave all billing fields blank).');
          return;
        }

        billing = {
          line1: line1,
          line2: line2 || undefined,
          city: city,
          state: state,
          postal_code: postal,
        };
      }

      if (submit) submit.disabled = true;

      try {
        await postJson('/api/cards', {
          account_id: accountId,
          description: description || undefined,
          billing_address: billing || undefined,
        });
        window.location.reload();
      } catch (err) {
        setModalError(modal, err.message || 'Something went wrong.');
        if (submit) submit.disabled = false;
      }
    });
  }

  // Card detail: status toggle
  qsa('input[data-toggle="card-status"]').forEach(function (input) {
    input.addEventListener('change', async function () {
      clearInlineError();

      var cardId = String(input.getAttribute('data-card-id') || '').trim();
      if (!cardId) return;

      var checked = Boolean(input.checked);
      input.disabled = true;

      try {
        await postJson('/api/cards/' + encodeURIComponent(cardId) + '/update-status', {
          status: checked ? 'active' : 'disabled',
        });
        window.location.reload();
      } catch (err) {
        input.checked = !checked;
        setInlineError(err.message || 'Something went wrong.');
        input.disabled = false;
      }
    });
  });

  // Card detail: edit description
  var cardUpdateDescriptionForm = qs('form[data-form="card-update-description"]');
  if (cardUpdateDescriptionForm) {
    cardUpdateDescriptionForm.addEventListener('submit', async function (e) {
      e.preventDefault();

      var modal = cardUpdateDescriptionForm.closest('.modal');
      var submit = qs('button[type="submit"]', cardUpdateDescriptionForm);

      var cardId = String(qs('[name="card_id"]', cardUpdateDescriptionForm).value || '').trim();
      var description = String(qs('[name="description"]', cardUpdateDescriptionForm).value || '').trim();

      if (!cardId) {
        setModalError(modal, 'Card is required.');
        return;
      }

      if (description.length > 200) {
        setModalError(modal, 'Description must be 200 characters or fewer.');
        return;
      }

      if (submit) submit.disabled = true;

      try {
        await postJson('/api/cards/' + encodeURIComponent(cardId) + '/update-description', {
          description: description,
        });
        window.location.reload();
      } catch (err) {
        setModalError(modal, err.message || 'Something went wrong.');
        if (submit) submit.disabled = false;
      }
    });
  }

  // Card detail: edit billing address
  var cardUpdateBillingForm = qs('form[data-form="card-update-billing-address"]');
  if (cardUpdateBillingForm) {
    cardUpdateBillingForm.addEventListener('submit', async function (e) {
      e.preventDefault();

      var modal = cardUpdateBillingForm.closest('.modal');
      var submit = qs('button[type="submit"]', cardUpdateBillingForm);

      var cardId = String(qs('[name="card_id"]', cardUpdateBillingForm).value || '').trim();
      var line1 = String(qs('[name="line1"]', cardUpdateBillingForm).value || '').trim();
      var line2 = String(qs('[name="line2"]', cardUpdateBillingForm).value || '').trim();
      var city = String(qs('[name="city"]', cardUpdateBillingForm).value || '').trim();
      var state = String(qs('[name="state"]', cardUpdateBillingForm).value || '').trim();
      var postal = String(qs('[name="postal_code"]', cardUpdateBillingForm).value || '').trim();

      if (!cardId) {
        setModalError(modal, 'Card is required.');
        return;
      }

      var anyBilling = Boolean(line1 || line2 || city || state || postal);
      if (anyBilling && (!line1 || !city || !state || !postal)) {
        setModalError(modal, 'Billing address requires line 1, city, state, and postal code (or leave all fields blank).');
        return;
      }

      if (submit) submit.disabled = true;

      try {
        await postJson('/api/cards/' + encodeURIComponent(cardId) + '/update-billing-address', {
          line1: line1,
          line2: line2,
          city: city,
          state: state,
          postal_code: postal,
        });
        window.location.reload();
      } catch (err) {
        setModalError(modal, err.message || 'Something went wrong.');
        if (submit) submit.disabled = false;
      }
    });
  }

  // Create Account Number
  var createAcctNumForm = qs('form[data-form="create-account-number"]');
  if (createAcctNumForm) {
    createAcctNumForm.addEventListener('submit', async function (e) {
      e.preventDefault();

      var modal = createAcctNumForm.closest('.modal');
      var submit = qs('button[type="submit"]', createAcctNumForm);

      var accountId = String(qs('[name="account_id"]', createAcctNumForm).value || '').trim();
      var name = String(qs('[name="name"]', createAcctNumForm).value || '').trim();

      if (!accountId || !name) {
        setModalError(modal, 'Account and name are required.');
        return;
      }

      if (submit) submit.disabled = true;

      try {
        await postJson('/api/account-numbers', { account_id: accountId, name: name });
        window.location.reload();
      } catch (err) {
        setModalError(modal, err.message || 'Something went wrong.');
        if (submit) submit.disabled = false;
      }
    });
  }

  // Account Number detail: status toggle
  qsa('input[data-toggle="account-number-status"]').forEach(function (input) {
    input.addEventListener('change', async function () {
      clearInlineError();

      var accountNumberId = String(input.getAttribute('data-account-number-id') || '').trim();
      if (!accountNumberId) return;

      var checked = Boolean(input.checked);
      input.disabled = true;

      try {
        await postJson('/api/account-numbers/' + encodeURIComponent(accountNumberId) + '/update-status', {
          status: checked ? 'active' : 'disabled',
        });
        window.location.reload();
      } catch (err) {
        input.checked = !checked;
        setInlineError(err.message || 'Something went wrong.');
        input.disabled = false;
      }
    });
  });

  // Account Number detail: ACH debits toggle
  qsa('input[data-toggle="account-number-ach-debits"]').forEach(function (input) {
    input.addEventListener('change', async function () {
      clearInlineError();

      var accountNumberId = String(input.getAttribute('data-account-number-id') || '').trim();
      if (!accountNumberId) return;

      var checked = Boolean(input.checked);
      input.disabled = true;

      try {
        await postJson(
          '/api/account-numbers/' + encodeURIComponent(accountNumberId) + '/update-inbound-ach-debit-status',
          {
            debit_status: checked ? 'allowed' : 'blocked',
          }
        );
        window.location.reload();
      } catch (err) {
        input.checked = !checked;
        setInlineError(err.message || 'Something went wrong.');
        input.disabled = false;
      }
    });
  });

  // Account Number detail: edit name
  var acctNumEditNameForm = qs('form[data-form="account-number-update-name"]');
  if (acctNumEditNameForm) {
    acctNumEditNameForm.addEventListener('submit', async function (e) {
      e.preventDefault();

      var modal = acctNumEditNameForm.closest('.modal');
      var submit = qs('button[type="submit"]', acctNumEditNameForm);

      var accountNumberId = String(qs('[name="account_number_id"]', acctNumEditNameForm).value || '').trim();
      var name = String(qs('[name="name"]', acctNumEditNameForm).value || '').trim();

      if (!accountNumberId) {
        setModalError(modal, 'Account number is required.');
        return;
      }

      if (!name) {
        setModalError(modal, 'Name is required.');
        return;
      }

      if (submit) submit.disabled = true;

      try {
        await postJson('/api/account-numbers/' + encodeURIComponent(accountNumberId) + '/update-name', {
          name: name,
        });
        window.location.reload();
      } catch (err) {
        setModalError(modal, err.message || 'Something went wrong.');
        if (submit) submit.disabled = false;
      }
    });
  }

  // Account Number detail: edit inbound checks status
  var acctNumInboundChecksForm = qs('form[data-form="account-number-update-inbound-checks"]');
  if (acctNumInboundChecksForm) {
    acctNumInboundChecksForm.addEventListener('submit', async function (e) {
      e.preventDefault();

      var modal = acctNumInboundChecksForm.closest('.modal');
      var submit = qs('button[type="submit"]', acctNumInboundChecksForm);

      var accountNumberId = String(qs('[name="account_number_id"]', acctNumInboundChecksForm).value || '').trim();
      var status = String(qs('[name="status"]', acctNumInboundChecksForm).value || '').trim();

      if (!accountNumberId) {
        setModalError(modal, 'Account number is required.');
        return;
      }

      if (!status) {
        setModalError(modal, 'Status is required.');
        return;
      }

      if (submit) submit.disabled = true;

      try {
        await postJson('/api/account-numbers/' + encodeURIComponent(accountNumberId) + '/update-inbound-checks-status', {
          status: status,
        });
        window.location.reload();
      } catch (err) {
        setModalError(modal, err.message || 'Something went wrong.');
        if (submit) submit.disabled = false;
      }
    });
  }

  // Create External Account
  var createExternalForm = qs('form[data-form="create-external-account"]');
  if (createExternalForm) {
    createExternalForm.addEventListener('submit', async function (e) {
      e.preventDefault();

      var modal = createExternalForm.closest('.modal');
      var submit = qs('button[type="submit"]', createExternalForm);

      var description = String(qs('[name="description"]', createExternalForm).value || '').trim();
      var routing = String(qs('[name="routing_number"]', createExternalForm).value || '').trim();
      var acct = String(qs('[name="account_number"]', createExternalForm).value || '').trim();
      var holder = String(qs('[name="account_holder"]', createExternalForm).value || '').trim();
      var funding = String(qs('[name="funding"]', createExternalForm).value || '').trim();

      if (!description || !routing || !acct) {
        setModalError(modal, 'Description, routing number, and account number are required.');
        return;
      }

      if (submit) submit.disabled = true;

      try {
        await postJson('/api/external-accounts', {
          description: description,
          routing_number: routing,
          account_number: acct,
          account_holder: holder || undefined,
          funding: funding || undefined,
        });
        window.location.reload();
      } catch (err) {
        setModalError(modal, err.message || 'Something went wrong.');
        if (submit) submit.disabled = false;
      }
    });
  }

  // Create Lockbox
  var createLockboxForm = qs('form[data-form="create-lockbox"]');
  if (createLockboxForm) {
    createLockboxForm.addEventListener('submit', async function (e) {
      e.preventDefault();

      var modal = createLockboxForm.closest('.modal');
      var submit = qs('button[type="submit"]', createLockboxForm);

      var accountId = String(qs('[name="account_id"]', createLockboxForm).value || '').trim();
      var description = String(qs('[name="description"]', createLockboxForm).value || '').trim();
      var recipientName = String(qs('[name="recipient_name"]', createLockboxForm).value || '').trim();

      if (!accountId) {
        setModalError(modal, 'Account is required.');
        return;
      }

      if (submit) submit.disabled = true;

      try {
        await postJson('/api/lockboxes', {
          account_id: accountId,
          description: description || undefined,
          recipient_name: recipientName || undefined,
        });
        window.location.reload();
      } catch (err) {
        setModalError(modal, err.message || 'Something went wrong.');
        if (submit) submit.disabled = false;
      }
    });
  }

  // Upload Document (Files)
  var uploadFileForm = qs('form[data-form="upload-file"]');
  if (uploadFileForm) {
    uploadFileForm.addEventListener('submit', async function (e) {
      e.preventDefault();

      var modal = uploadFileForm.closest('.modal');
      var submit = qs('button[type="submit"]', uploadFileForm);

      var fileInput = qs('input[name="file"]', uploadFileForm);
      var file = fileInput && fileInput.files ? fileInput.files[0] : null;
      var purpose = String(qs('[name="purpose"]', uploadFileForm).value || '').trim();
      var description = String(qs('[name="description"]', uploadFileForm).value || '').trim();

      if (!file) {
        setModalError(modal, 'File is required.');
        return;
      }

      if (!purpose) {
        setModalError(modal, 'Purpose is required.');
        return;
      }

      if (submit) submit.disabled = true;

      try {
        var fd = new FormData();
        fd.append('file', file);
        fd.append('purpose', purpose);
        if (description) fd.append('description', description);

        await postFormData('/api/files', fd);
        window.location.reload();
      } catch (err) {
        setModalError(modal, err.message || 'Something went wrong.');
        if (submit) submit.disabled = false;
      }
    });
  }

  // Create Export
  var createExportForm = qs('form[data-form="create-export"]');
  if (createExportForm) {
    createExportForm.addEventListener('submit', async function (e) {
      e.preventDefault();

      var modal = createExportForm.closest('.modal');
      var submit = qs('button[type="submit"]', createExportForm);

      var category = String(qs('[name="category"]', createExportForm).value || '').trim();

      if (!category) {
        setModalError(modal, 'Category is required.');
        return;
      }

      if (submit) submit.disabled = true;

      try {
        await postJson('/api/exports', {
          category: category,
        });
        window.location.reload();
      } catch (err) {
        setModalError(modal, err.message || 'Something went wrong.');
        if (submit) submit.disabled = false;
      }
    });
  }

  // Confirm Entity Details
  var confirmEntityForm = qs('form[data-form="confirm-entity"]');
  if (confirmEntityForm) {
    confirmEntityForm.addEventListener('submit', async function (e) {
      e.preventDefault();

      var modal = confirmEntityForm.closest('.modal');
      var submit = qs('button[type="submit"]', confirmEntityForm);

      var entityId = String(qs('[name="entity_id"]', confirmEntityForm).value || '').trim();
      if (!entityId) {
        setModalError(modal, 'Entity is required.');
        return;
      }

      if (submit) submit.disabled = true;

      try {
        await postJson('/api/entities/' + encodeURIComponent(entityId) + '/confirm', {});
        window.location.reload();
      } catch (err) {
        setModalError(modal, err.message || 'Something went wrong.');
        if (submit) submit.disabled = false;
      }
    });
  }

  // Entity: Update address
  var entityUpdateAddressForm = qs('form[data-form="entity-update-address"]');
  if (entityUpdateAddressForm) {
    entityUpdateAddressForm.addEventListener('submit', async function (e) {
      e.preventDefault();

      var modal = entityUpdateAddressForm.closest('.modal');
      var submit = qs('button[type="submit"]', entityUpdateAddressForm);

      var entityId = String(qs('[name="entity_id"]', entityUpdateAddressForm).value || '').trim();
      var line1 = String(qs('[name="line1"]', entityUpdateAddressForm).value || '').trim();
      var line2 = String(qs('[name="line2"]', entityUpdateAddressForm).value || '').trim();
      var city = String(qs('[name="city"]', entityUpdateAddressForm).value || '').trim();
      var state = String(qs('[name="state"]', entityUpdateAddressForm).value || '').trim();
      var zip = String(qs('[name="zip"]', entityUpdateAddressForm).value || '').trim();

      if (!entityId) {
        setModalError(modal, 'Entity is required.');
        return;
      }

      if (!line1 || !city || !state || !zip) {
        setModalError(modal, 'Line 1, city, state, and ZIP are required.');
        return;
      }

      if (submit) submit.disabled = true;

      try {
        await postJson('/api/entities/' + encodeURIComponent(entityId) + '/update-address', {
          line1: line1,
          line2: line2 || undefined,
          city: city,
          state: state,
          zip: zip,
        });
        window.location.reload();
      } catch (err) {
        setModalError(modal, err.message || 'Something went wrong.');
        if (submit) submit.disabled = false;
      }
    });
  }

  // Entity: Update industry code
  var entityUpdateIndustryCodeForm = qs('form[data-form="entity-update-industry-code"]');
  if (entityUpdateIndustryCodeForm) {
    entityUpdateIndustryCodeForm.addEventListener('submit', async function (e) {
      e.preventDefault();

      var modal = entityUpdateIndustryCodeForm.closest('.modal');
      var submit = qs('button[type="submit"]', entityUpdateIndustryCodeForm);

      var entityId = String(qs('[name="entity_id"]', entityUpdateIndustryCodeForm).value || '').trim();
      var industryCode = String(qs('[name="industry_code"]', entityUpdateIndustryCodeForm).value || '').trim();

      if (!entityId) {
        setModalError(modal, 'Entity is required.');
        return;
      }

      if (!industryCode) {
        setModalError(modal, 'Industry code is required.');
        return;
      }

      if (submit) submit.disabled = true;

      try {
        await postJson('/api/entities/' + encodeURIComponent(entityId) + '/update-industry-code', {
          industry_code: industryCode,
        });
        window.location.reload();
      } catch (err) {
        setModalError(modal, err.message || 'Something went wrong.');
        if (submit) submit.disabled = false;
      }
    });
  }

  // Entity: Upload supplemental document
  var entityUploadDocumentForm = qs('form[data-form="entity-upload-document"]');
  if (entityUploadDocumentForm) {
    entityUploadDocumentForm.addEventListener('submit', async function (e) {
      e.preventDefault();

      var modal = entityUploadDocumentForm.closest('.modal');
      var submit = qs('button[type="submit"]', entityUploadDocumentForm);

      var entityId = String(qs('[name="entity_id"]', entityUploadDocumentForm).value || '').trim();
      var fileInput = qs('input[name="file"]', entityUploadDocumentForm);
      var file = fileInput && fileInput.files ? fileInput.files[0] : null;
      var description = String(qs('[name="description"]', entityUploadDocumentForm).value || '').trim();

      if (!entityId) {
        setModalError(modal, 'Entity is required.');
        return;
      }

      if (!file) {
        setModalError(modal, 'File is required.');
        return;
      }

      if (submit) submit.disabled = true;

      try {
        var fd = new FormData();
        fd.append('file', file);
        if (description) fd.append('description', description);

        await postFormData('/api/entities/' + encodeURIComponent(entityId) + '/documents', fd);
        window.location.reload();
      } catch (err) {
        setModalError(modal, err.message || 'Something went wrong.');
        if (submit) submit.disabled = false;
      }
    });
  }

  // Entity: Archive
  var entityArchiveForm = qs('form[data-form="entity-archive"]');
  if (entityArchiveForm) {
    entityArchiveForm.addEventListener('submit', async function (e) {
      e.preventDefault();

      var modal = entityArchiveForm.closest('.modal');
      var submit = qs('button[type="submit"]', entityArchiveForm);

      var entityId = String(qs('[name="entity_id"]', entityArchiveForm).value || '').trim();
      if (!entityId) {
        setModalError(modal, 'Entity is required.');
        return;
      }

      if (submit) submit.disabled = true;

      try {
        await postJson('/api/entities/' + encodeURIComponent(entityId) + '/archive', {});
        window.location.reload();
      } catch (err) {
        setModalError(modal, err.message || 'Something went wrong.');
        if (submit) submit.disabled = false;
      }
    });
  }

  // ACH transfer (Send/Debit)
  qsa('form[data-form="ach-transfer"]').forEach(function (form) {
    form.addEventListener('submit', async function (e) {
      e.preventDefault();

      var modal = form.closest('.modal');
      var submit = qs('button[type="submit"]', form);

      var accountIdField = qs('[name="account_id"]', form);
      var accountId = accountIdField ? String(accountIdField.value || '').trim() : '';
      var routing = String(qs('[name="routing_number"]', form).value || '').trim();
      var acct = String(qs('[name="account_number"]', form).value || '').trim();
      var amountUsd = String(qs('[name="amount_usd"]', form).value || '').trim();
      var direction = String(qs('[name="direction"]', form).value || 'credit').trim();
      var descriptor = String(qs('[name="statement_descriptor"]', form).value || 'Dodo Checks').trim();

      var amount = Number(amountUsd);
      if (!routing || !acct) {
        setModalError(modal, 'Routing number and account number are required.');
        return;
      }

      if (!isFinite(amount) || amount <= 0) {
        setModalError(modal, 'Enter a valid amount greater than 0.');
        return;
      }

      var cents = Math.round(amount * 100);
      if (!isFinite(cents) || cents <= 0) {
        setModalError(modal, 'Enter a valid amount.');
        return;
      }

      if (submit) submit.disabled = true;

      try {
        await postJson('/api/transfers', {
          // account_id is user-scoped on the server; include it only for backwards compatibility.
          account_id: accountId || undefined,
          routing_number: routing,
          account_number: acct,
          amount_cents: cents,
          direction: direction,
          statement_descriptor: descriptor,
        });
        window.location.reload();
      } catch (err) {
        setModalError(modal, err.message || 'Something went wrong.');
        if (submit) submit.disabled = false;
      }
    });
  });

  // Internal transfer (account to account)
  qsa('form[data-form="internal-transfer"]').forEach(function (form) {
    form.addEventListener('submit', async function (e) {
      e.preventDefault();

      var modal = form.closest('.modal');
      var submit = qs('button[type="submit"]', form);

      var fromAccountId = String(qs('[name="from_account_id"]', form).value || '').trim();
      var toAccountId = String(qs('[name="to_account_id"]', form).value || '').trim();
      var amountUsd = String(qs('[name="amount_usd"]', form).value || '').trim();
      var description = String(qs('[name="description"]', form).value || '').trim();

      var amount = Number(amountUsd);
      if (!fromAccountId || !toAccountId) {
        setModalError(modal, 'From account and destination account are required.');
        return;
      }
      if (!isFinite(amount) || amount <= 0) {
        setModalError(modal, 'Enter a valid amount greater than 0.');
        return;
      }

      var cents = Math.round(amount * 100);
      if (!isFinite(cents) || cents <= 0) {
        setModalError(modal, 'Enter a valid amount.');
        return;
      }

      if (submit) submit.disabled = true;

      try {
        await postJson('/api/internal-transfers', {
          from_account_id: fromAccountId,
          to_account_id: toAccountId,
          amount_cents: cents,
          description: description || undefined,
        });
        window.location.reload();
      } catch (err) {
        setModalError(modal, err.message || 'Something went wrong.');
        if (submit) submit.disabled = false;
      }
    });
  });

  // Check deposit
  qsa('form[data-form="check-deposit"]').forEach(function (form) {
    form.addEventListener('submit', async function (e) {
      e.preventDefault();

      var modal = form.closest('.modal');
      var submit = qs('button[type="submit"]', form);

      var accountIdField = qs('[name="account_id"]', form);
      var accountId = accountIdField ? String(accountIdField.value || '').trim() : '';
      var amountUsd = String(qs('[name="amount_usd"]', form).value || '').trim();
      var description = String(qs('[name="description"]', form).value || '').trim();

      var front = qs('input[name="front"]', form)?.files?.[0];
      var back = qs('input[name="back"]', form)?.files?.[0];

      var amount = Number(amountUsd);
      if (!front || !back) {
        setModalError(modal, 'Front image and back image are required.');
        return;
      }
      if (!isFinite(amount) || amount <= 0) {
        setModalError(modal, 'Enter a valid amount greater than 0.');
        return;
      }

      var cents = Math.round(amount * 100);
      if (!isFinite(cents) || cents <= 0) {
        setModalError(modal, 'Enter a valid amount.');
        return;
      }

      if (submit) submit.disabled = true;

      try {
        var fd = new FormData();
        // account_id is user-scoped on the server; include it only for backwards compatibility.
        if (accountId) fd.append('account_id', accountId);
        fd.append('amount_cents', cents);
        if (description) fd.append('description', description);
        fd.append('front', front);
        fd.append('back', back);

        await postFormData('/api/check-deposits', fd);
        window.location.reload();
      } catch (err) {
        setModalError(modal, err.message || 'Something went wrong.');
        if (submit) submit.disabled = false;
      }
    });
  });

  // Compliance: Save personal details
  var complianceSaveForm = qs('form[data-form="compliance-save"]');
  if (complianceSaveForm) {
    complianceSaveForm.addEventListener('submit', async function (e) {
      e.preventDefault();
      clearInlineError();

      var submit = qs('button[type="submit"]', complianceSaveForm);

      var fullName = String(qs('[name="full_name"]', complianceSaveForm).value || '').trim();
      var phone = String(qs('[name="phone"]', complianceSaveForm).value || '').trim();
      var dob = String(qs('[name="date_of_birth"]', complianceSaveForm).value || '').trim();
      var ssn = String(qs('[name="ssn"]', complianceSaveForm).value || '').trim();

      var line1 = String(qs('[name="address_line1"]', complianceSaveForm).value || '').trim();
      var line2 = String(qs('[name="address_line2"]', complianceSaveForm).value || '').trim();
      var city = String(qs('[name="city"]', complianceSaveForm).value || '').trim();
      var state = String(qs('[name="state"]', complianceSaveForm).value || '').trim();
      var zip = String(qs('[name="zip"]', complianceSaveForm).value || '').trim();

      if (!fullName || !phone || !dob || !line1 || !city || !state || !zip) {
        setInlineError('Please fill out all required fields.');
        return;
      }

      if (submit) submit.disabled = true;

      try {
        await postJson('/api/compliance', {
          full_name: fullName,
          phone: phone,
          date_of_birth: dob,
          ssn: ssn || undefined,
          address_line1: line1,
          address_line2: line2 || undefined,
          city: city,
          state: state,
          zip: zip,
        });
        window.location.reload();
      } catch (err) {
        setInlineError(err.message || 'Something went wrong.');
        if (submit) submit.disabled = false;
      }
    });
  }

  // Compliance: Upload documents
  qsa('form[data-form="compliance-document"]').forEach(function (form) {
    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      clearInlineError();

      var submit = qs('button[type="submit"]', form);
      var kind = String(qs('[name="kind"]', form).value || '').trim();
      var file = qs('input[name="file"]', form)?.files?.[0];

      if (!kind) {
        setInlineError('Document kind is required.');
        return;
      }
      if (!file) {
        setInlineError('Select a file to upload.');
        return;
      }

      if (submit) submit.disabled = true;

      try {
        var fd = new FormData();
        fd.append('kind', kind);
        fd.append('file', file);
        await postFormData('/api/compliance/documents', fd);
        window.location.reload();
      } catch (err) {
        setInlineError(err.message || 'Something went wrong.');
        if (submit) submit.disabled = false;
      }
    });
  });

  // Onboarding: Provision
  var provisionForm = qs('form[data-form="onboarding-provision"]');
  if (provisionForm) {
    provisionForm.addEventListener('submit', async function (e) {
      e.preventDefault();
      clearInlineError();

      var submit = qs('button[type="submit"]', provisionForm);
      if (submit) submit.disabled = true;

      try {
        await postJson('/api/onboarding/provision', {});
        window.location.reload();
      } catch (err) {
        setInlineError(err.message || 'Something went wrong.');
        if (submit) submit.disabled = false;
      }
    });
  }

  // Send wire
  qsa('form[data-form="wire-transfer"]').forEach(function (form) {
    form.addEventListener('submit', async function (e) {
      e.preventDefault();

      var modal = form.closest('.modal');
      var submit = qs('button[type="submit"]', form);

      var creditorName = String(qs('[name="creditor_name"]', form).value || '').trim();
      var routing = String(qs('[name="routing_number"]', form).value || '').trim();
      var acct = String(qs('[name="account_number"]', form).value || '').trim();
      var amountUsd = String(qs('[name="amount_usd"]', form).value || '').trim();
      var message = String(qs('[name="remittance_message"]', form).value || '').trim();

      var amount = Number(amountUsd);
      if (!creditorName || !routing || !acct) {
        setModalError(modal, 'Beneficiary name, routing number, and account number are required.');
        return;
      }
      if (!isFinite(amount) || amount <= 0) {
        setModalError(modal, 'Enter a valid amount greater than 0.');
        return;
      }

      var cents = Math.round(amount * 100);
      if (!isFinite(cents) || cents <= 0) {
        setModalError(modal, 'Enter a valid amount.');
        return;
      }

      if (submit) submit.disabled = true;

      try {
        await postJson('/api/wire-transfers', {
          creditor_name: creditorName,
          routing_number: routing,
          account_number: acct,
          amount_cents: cents,
          remittance_message: message || undefined,
        });
        window.location.reload();
      } catch (err) {
        setModalError(modal, err.message || 'Something went wrong.');
        if (submit) submit.disabled = false;
      }
    });
  });

  // Mail check
  qsa('form[data-form="check-transfer"]').forEach(function (form) {
    form.addEventListener('submit', async function (e) {
      e.preventDefault();

      var modal = form.closest('.modal');
      var submit = qs('button[type="submit"]', form);

      var recipientName = String(qs('[name="recipient_name"]', form).value || '').trim();
      var amountUsd = String(qs('[name="amount_usd"]', form).value || '').trim();
      var memo = String(qs('[name="memo"]', form).value || '').trim();

      var line1 = String(qs('[name="mailing_line1"]', form).value || '').trim();
      var line2 = String(qs('[name="mailing_line2"]', form).value || '').trim();
      var city = String(qs('[name="mailing_city"]', form).value || '').trim();
      var state = String(qs('[name="mailing_state"]', form).value || '').trim();
      var postal = String(qs('[name="mailing_postal_code"]', form).value || '').trim();

      var amount = Number(amountUsd);
      if (!recipientName || !line1 || !city || !state || !postal) {
        setModalError(modal, 'Recipient name and complete mailing address are required.');
        return;
      }
      if (!isFinite(amount) || amount <= 0) {
        setModalError(modal, 'Enter a valid amount greater than 0.');
        return;
      }

      var cents = Math.round(amount * 100);
      if (!isFinite(cents) || cents <= 0) {
        setModalError(modal, 'Enter a valid amount.');
        return;
      }

      if (submit) submit.disabled = true;

      try {
        await postJson('/api/check-transfers', {
          recipient_name: recipientName,
          amount_cents: cents,
          memo: memo || undefined,
          mailing_line1: line1,
          mailing_line2: line2 || undefined,
          mailing_city: city,
          mailing_state: state,
          mailing_postal_code: postal,
        });
        window.location.reload();
      } catch (err) {
        setModalError(modal, err.message || 'Something went wrong.');
        if (submit) submit.disabled = false;
      }
    });
  });

  // Transaction detail: release pending transaction
  qsa('form[data-form="tx-release"]').forEach(function (form) {
    form.addEventListener('submit', async function (e) {
      e.preventDefault();

      var modal = form.closest('.modal');
      var submit = qs('button[type="submit"]', form);

      var pendingId = String(qs('[name="pending_transaction_id"]', form).value || '').trim();
      if (!pendingId) {
        setModalError(modal, 'Pending transaction is required.');
        return;
      }

      if (submit) submit.disabled = true;

      try {
        await postJson('/api/pending-transactions/' + encodeURIComponent(pendingId) + '/release', {});
        window.location.reload();
      } catch (err) {
        setModalError(modal, err.message || 'Something went wrong.');
        if (submit) submit.disabled = false;
      }
    });
  });

  // Transaction detail: cancel underlying transfer
  qsa('form[data-form="tx-cancel"]').forEach(function (form) {
    form.addEventListener('submit', async function (e) {
      e.preventDefault();

      var modal = form.closest('.modal');
      var submit = qs('button[type="submit"]', form);

      var transactionId = String(qs('[name="transaction_id"]', form).value || '').trim();
      if (!transactionId) {
        setModalError(modal, 'Transaction is required.');
        return;
      }

      if (submit) submit.disabled = true;

      try {
        await postJson('/api/transactions/' + encodeURIComponent(transactionId) + '/cancel', {});
        window.location.reload();
      } catch (err) {
        setModalError(modal, err.message || 'Something went wrong.');
        if (submit) submit.disabled = false;
      }
    });
  });

  // Transaction detail: return inbound ACH
  qsa('form[data-form="tx-return-inbound-ach"]').forEach(function (form) {
    form.addEventListener('submit', async function (e) {
      e.preventDefault();

      var modal = form.closest('.modal');
      var submit = qs('button[type="submit"]', form);

      var transactionId = String(qs('[name="transaction_id"]', form).value || '').trim();
      var reason = String(qs('[name="reason"]', form).value || '').trim();

      if (!transactionId) {
        setModalError(modal, 'Transaction is required.');
        return;
      }

      if (!reason) {
        setModalError(modal, 'Reason is required.');
        return;
      }

      if (submit) submit.disabled = true;

      try {
        await postJson('/api/transactions/' + encodeURIComponent(transactionId) + '/return-inbound-ach', {
          reason: reason,
        });
        window.location.reload();
      } catch (err) {
        setModalError(modal, err.message || 'Something went wrong.');
        if (submit) submit.disabled = false;
      }
    });
  });
})();
