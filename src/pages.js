'use strict';

function esc(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function page({ title, bodyClass, head = '', body }) {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${esc(title)}</title>
    ${head}
  </head>
  <body${bodyClass ? ` class="${esc(bodyClass)}"` : ''}>
    ${body}
  </body>
</html>`;
}

function appCss() {
  return '<link rel="stylesheet" href="/app-assets/app.css" />';
}

function appJs() {
  return '<script src="/app-assets/app.js" defer></script>';
}

function icon(name) {
  // Minimal inline icons (stroke matches the screenshot style).
  const common = 'width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"';
  const s = 'stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"';

  switch (name) {
    case 'overview':
      return `<svg ${common}><path ${s} d="M4 13h7V4H4v9Z"/><path ${s} d="M13 20h7V11h-7v9Z"/><path ${s} d="M13 4h7v5h-7V4Z"/><path ${s} d="M4 15h7v5H4v-5Z"/></svg>`;
    case 'accounts':
      return `<svg ${common}><path ${s} d="M4 7h16"/><path ${s} d="M6 7V5h12v2"/><path ${s} d="M6 7v12h12V7"/><path ${s} d="M9 11h6"/><path ${s} d="M9 15h6"/></svg>`;
    case 'transactions':
      return `<svg ${common}><path ${s} d="M7 7h10"/><path ${s} d="M7 12h10"/><path ${s} d="M7 17h10"/><path ${s} d="M4 5v14"/><path ${s} d="M20 5v14"/></svg>`;
    case 'transfers':
      return `<svg ${common}><path ${s} d="M7 7h12"/><path ${s} d="M7 7l3-3"/><path ${s} d="M7 7l3 3"/><path ${s} d="M17 17H5"/><path ${s} d="M17 17l-3-3"/><path ${s} d="M17 17l-3 3"/></svg>`;
    case 'cards':
      return `<svg ${common}><rect ${s} x="4" y="7" width="16" height="12" rx="2"/><path ${s} d="M4 11h16"/><path ${s} d="M8 16h4"/></svg>`;
    case 'account_numbers':
      return `<svg ${common}><path ${s} d="M4 6h16"/><path ${s} d="M4 10h16"/><path ${s} d="M4 14h10"/><path ${s} d="M4 18h10"/></svg>`;
    case 'external_accounts':
      return `<svg ${common}><path ${s} d="M4 12h12"/><path ${s} d="M12 6l4 6-4 6"/><path ${s} d="M4 6v12"/></svg>`;
    case 'lockboxes':
      return `<svg ${common}><rect ${s} x="4" y="10" width="16" height="10" rx="2"/><path ${s} d="M8 10V8a4 4 0 0 1 8 0v2"/><path ${s} d="M12 15v2"/></svg>`;
    case 'documents':
      return `<svg ${common}><path ${s} d="M8 3h8l4 4v14H8V3Z"/><path ${s} d="M16 3v5h5"/><path ${s} d="M10 12h8"/><path ${s} d="M10 16h8"/></svg>`;
    case 'compliance':
      return `<svg ${common}><path ${s} d="M12 3l8 4v6c0 5-3.5 9-8 10-4.5-1-8-5-8-10V7l8-4Z"/><path ${s} d="M9 12l2 2 4-5"/></svg>`;
    case 'settings':
      return `<svg ${common}><path ${s} d="M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Z"/><path ${s} d="M19.4 15a8.7 8.7 0 0 0 .1-2l2-1.2-2-3.4-2.2.8a7.7 7.7 0 0 0-1.7-1L15 4h-6l-.6 3.2a7.7 7.7 0 0 0-1.7 1l-2.2-.8-2 3.4 2 1.2a8.7 8.7 0 0 0 .1 2l-2 1.2 2 3.4 2.2-.8c.5.4 1.1.7 1.7 1L9 20h6l.6-3.2c.6-.3 1.2-.6 1.7-1l2.2.8 2-3.4-2-1.2Z"/></svg>`;
    default:
      return `<svg ${common}><circle ${s} cx="12" cy="12" r="9"/></svg>`;
  }
}

const NAV_ITEMS = [
  { key: 'overview', label: 'Overview', href: '/app/overview', icon: icon('overview') },
  { key: 'accounts', label: 'Accounts', href: '/app/accounts', icon: icon('accounts') },
  { key: 'transactions', label: 'Transactions', href: '/app/transactions', icon: icon('transactions') },
  { key: 'transfers', label: 'Transfers', href: '/app/transfers', icon: icon('transfers') },
  { key: 'cards', label: 'Cards', href: '/app/cards', icon: icon('cards') },
  { key: 'account-numbers', label: 'Account Numbers', href: '/app/account-numbers', icon: icon('account_numbers') },
  { key: 'external-accounts', label: 'External Accounts', href: '/app/external-accounts', icon: icon('external_accounts') },
  { key: 'lockboxes', label: 'Lockboxes', href: '/app/lockboxes', icon: icon('lockboxes') },
  { key: 'documents', label: 'Documents', href: '/app/documents', icon: icon('documents') },
  { key: 'compliance', label: 'Compliance', href: '/app/compliance', icon: icon('compliance') },
  { key: 'settings', label: 'Settings', href: '/app/settings', icon: icon('settings') },
];

function renderAuthPage({ mode, error, next = '', email = '' }) {
  const isSignup = mode === 'signup';
  const title = isSignup ? 'Create your account | Dodo Checks' : 'Log in | Dodo Checks';

  const nextField = next ? `<input type="hidden" name="next" value="${esc(next)}" />` : '';
  const errorHtml = error
    ? `<div class="alert" role="alert"><strong>Unable to ${isSignup ? 'sign up' : 'log in'}:</strong> ${esc(error)}</div>`
    : '';

  return page({
    title,
    bodyClass: 'auth-body',
    head: `${appCss()}`,
    body: `
      <div class="auth-shell">
        <a class="auth-brand" href="/" aria-label="Dodo Checks home">
          <span class="mark" aria-hidden="true">D</span>
          <span>Dodo Checks</span>
        </a>

        <div class="auth-card">
          <h1>${isSignup ? 'Create your account' : 'Log in'}</h1>
          <p class="muted">${isSignup ? 'Start sending and depositing checks with a modern workflow.' : 'Welcome back. Continue to your dashboard.'}</p>
          ${errorHtml}

          <form method="post" action="/${isSignup ? 'signup' : 'login'}" class="form">
            ${nextField}

            <label class="field">
              <span>Email</span>
              <input name="email" type="email" autocomplete="email" required value="${esc(email)}" />
            </label>

            <label class="field">
              <span>Password</span>
              <input name="password" type="password" autocomplete="${isSignup ? 'new-password' : 'current-password'}" required />
            </label>

            <button class="btn-primary" type="submit">${isSignup ? 'Create account' : 'Log in'}</button>
          </form>

          <p class="small" style="margin-top: 14px;">
            ${isSignup
              ? `Already have an account? <a href="/login${next ? `?next=${encodeURIComponent(next)}` : ''}">Log in</a>.`
              : `New to Dodo Checks? <a href="/signup${next ? `?next=${encodeURIComponent(next)}` : ''}">Create an account</a>.`}
          </p>
        </div>
      </div>
    `,
  });
}

function renderAppLayout({ title, subtitle = '', activeKey, user, content, actionsHtml = '' }) {
  const navHtml = NAV_ITEMS.map((item) => {
    const active = item.key === activeKey;
    return `
      <a class="nav-item${active ? ' active' : ''}" href="${item.href}">
        <span class="nav-icon" aria-hidden="true">${item.icon}</span>
        <span class="nav-label">${esc(item.label)}</span>
      </a>
    `;
  }).join('');

  const subtitleHtml = subtitle ? `<div class="page-subtitle">${esc(subtitle)}</div>` : '';

  return page({
    title: `${esc(title)} | Dodo Checks`,
    bodyClass: 'app-body',
    head: `${appCss()}
      <meta name="color-scheme" content="light" />
    `,
    body: `
      <div class="app-shell">
        <aside class="sidebar" aria-label="Sidebar navigation">
          <div class="sidebar-head">
            <a class="sidebar-brand" href="/app/overview" aria-label="Dodo Checks dashboard">
              <span class="mark" aria-hidden="true">D</span>
              <span class="brand-text">Dodo Checks</span>
            </a>
          </div>

          <nav class="sidebar-nav">${navHtml}</nav>

          <div class="sidebar-foot">
            <div class="user-chip" title="Signed in">${esc(user.email || '')}</div>
            <form method="post" action="/logout">
              <button class="link" type="submit">Log out</button>
            </form>
          </div>
        </aside>

        <div class="main">
          <header class="topbar">
            <div class="topbar-left">
              <div class="page-title">${esc(title)}</div>
              ${subtitleHtml}
            </div>

            <div class="topbar-right">
              <div class="search" role="search">
                <span class="search-icon" aria-hidden="true">${icon('transactions')}</span>
                <input type="search" placeholder="Search" aria-label="Search" />
                <span class="kbd" aria-hidden="true">Ctrl K</span>
              </div>
              ${actionsHtml}
            </div>
          </header>

          <main class="content">${content}</main>
        </div>
      </div>
      ${appJs()}
    `,
  });
}

module.exports = {
  esc,
  renderAuthPage,
  renderAppLayout,
};
