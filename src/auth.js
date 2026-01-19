'use strict';

const jwt = require('jsonwebtoken');
const cookie = require('cookie');

const COOKIE_NAME = 'dc_session';

function getCookieSecret() {
  const secret = process.env.APP_COOKIE_SECRET;
  if (!secret || !String(secret).trim()) {
    throw new Error('APP_COOKIE_SECRET is required');
  }
  return String(secret);
}

function cookieOptions() {
  const isProd = process.env.NODE_ENV === 'production';
  return {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax',
    path: '/',
    maxAge: 60 * 60 * 24 * 7, // 7 days
  };
}

function appendSetCookie(res, cookieValue) {
  const existing = res.getHeader('Set-Cookie');
  if (!existing) {
    res.setHeader('Set-Cookie', cookieValue);
    return;
  }
  if (Array.isArray(existing)) {
    res.setHeader('Set-Cookie', [...existing, cookieValue]);
    return;
  }
  res.setHeader('Set-Cookie', [existing, cookieValue]);
}

function setAuthCookie(res, { userId, email }) {
  const token = jwt.sign(
    { sub: String(userId), email },
    getCookieSecret(),
    { expiresIn: '7d' }
  );

  const serialized = cookie.serialize(COOKIE_NAME, token, cookieOptions());
  appendSetCookie(res, serialized);
}

function clearAuthCookie(res) {
  const serialized = cookie.serialize(COOKIE_NAME, '', {
    ...cookieOptions(),
    maxAge: 0,
  });
  appendSetCookie(res, serialized);
}

function getAuthToken(req) {
  const raw = req.headers.cookie;
  if (!raw) return null;

  const parsed = cookie.parse(raw);
  return parsed[COOKIE_NAME] || null;
}

function getAuthPayload(req) {
  const token = getAuthToken(req);
  if (!token) return null;

  try {
    return jwt.verify(token, getCookieSecret());
  } catch {
    return null;
  }
}

function requireAuth(req, res, next) {
  const payload = getAuthPayload(req);
  if (!payload?.sub) {
    const nextUrl = encodeURIComponent(req.originalUrl || '/app/overview');
    res.redirect(`/login?next=${nextUrl}`);
    return;
  }

  req.user = {
    id: Number(payload.sub),
    email: String(payload.email || ''),
  };

  next();
}

module.exports = {
  setAuthCookie,
  clearAuthCookie,
  getAuthPayload,
  requireAuth,
};
