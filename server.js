'use strict';
/**
 * Net365 WhatsApp Banking bot
 *
 * WhatsApp  ->  this server  ->  Net365 (Flask) API
 *
 * What users can do (after linking their WhatsApp number to their Net365 account):
 *   Buy airtime (wallet + PIN, or a card payment link) · Wallet balance · Fund wallet ·
 *   Last 5 transactions · Link / unlink account · Help
 *
 * Security model
 *   - Every webhook is verified with Meta's X-Hub-Signature-256 (HMAC of the raw body).
 *   - Linking needs an emailed one-time code; spending/balance/history need the user's 4-digit PIN
 *     (5 wrong tries = 30 minute lock, enforced by Net365, not by this bot).
 *   - The bot never stores a Net365 session: it asks Net365 for a 5-minute token per action and
 *     revokes it straight away.
 *   - PINs, OTP codes and message text are never written to the logs.
 */
require('dotenv').config();

const express = require('express');
const crypto = require('crypto');
const axios = require('axios');

// ---------------------------------------------------------------------------
// CONFIG
// ---------------------------------------------------------------------------
const env = (k, d) => (process.env[k] !== undefined && process.env[k] !== '' ? process.env[k] : d);

const PORT = Number(env('PORT', 3000));
const VERIFY_TOKEN = process.env.WHATSAPP_VERIFY_TOKEN;
const APP_SECRET = process.env.WHATSAPP_APP_SECRET;
const ACCESS_TOKEN = process.env.WHATSAPP_ACCESS_TOKEN;
const PHONE_NUMBER_ID = process.env.WHATSAPP_PHONE_NUMBER_ID;
const BOT_SECRET = process.env.WHATSAPP_BOT_SECRET;

const GRAPH_VERSION = env('WHATSAPP_GRAPH_VERSION', 'v26.0');
const GRAPH_BASE = env('WHATSAPP_GRAPH_BASE', 'https://graph.facebook.com');
const NET365_API_URL = env('NET365_API_URL', 'http://127.0.0.1:5557').replace(/\/+$/, '');
const NET365_PUBLIC_URL = env('NET365_PUBLIC_URL', NET365_API_URL).replace(/\/+$/, '');

const AIRTIME_MIN = Number(env('AIRTIME_MIN', 50));
const AIRTIME_MAX = Number(env('AIRTIME_MAX', 50000));
const AIRTIME_SERVICE_FEE = Number(env('AIRTIME_SERVICE_FEE', 100)); // keep equal to the app's NGN fee
const FUND_MIN = Number(env('FUND_MIN', 100));
const SUPPORT_EMAIL = env('SUPPORT_EMAIL', 'support@net365co.com');
const SUPPORT_WHATSAPP = env('SUPPORT_WHATSAPP', '');

const SESSION_TTL_MS = 10 * 60 * 1000;
const MSG_PER_MINUTE = Number(env('MSG_PER_MINUTE', 25));

const missing = Object.entries({
  WHATSAPP_VERIFY_TOKEN: VERIFY_TOKEN,
  WHATSAPP_APP_SECRET: APP_SECRET,
  WHATSAPP_ACCESS_TOKEN: ACCESS_TOKEN,
  WHATSAPP_PHONE_NUMBER_ID: PHONE_NUMBER_ID,
  WHATSAPP_BOT_SECRET: BOT_SECRET,
}).filter(([, v]) => !v || /^your_|_here$/.test(v)).map(([k]) => k);

if (missing.length && require.main === module) {
  console.error('❌ Missing or placeholder env vars:', missing.join(', '));
  console.error('   Copy .env.example to .env, fill in the real values, then restart.');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// LOGGING (no message text, no PINs, numbers masked)
// ---------------------------------------------------------------------------
const mask = (n) => (n ? `***${String(n).slice(-4)}` : '?');
const log = (...a) => console.log(new Date().toISOString(), ...a);

// ---------------------------------------------------------------------------
// NET365 API CLIENT
// ---------------------------------------------------------------------------
const net365 = axios.create({
  baseURL: NET365_API_URL,
  timeout: 70000, // wallet airtime waits for the operator
  validateStatus: () => true,
  headers: { 'Content-Type': 'application/json' },
});

async function bot(path, body) {
  const r = await net365.post(path, body, { headers: { 'X-Bot-Secret': BOT_SECRET } });
  return { status: r.status, data: r.data || {} };
}
async function asUser(token, method, path, body) {
  const r = await net365.request({
    method, url: path, data: body,
    headers: { Authorization: `Bearer ${token}` },
  });
  return { status: r.status, data: r.data || {} };
}
async function revoke(token) {
  try { await asUser(token, 'POST', '/api/auth/logout'); } catch (_) { /* token expires in 5 min anyway */ }
}

// ---------------------------------------------------------------------------
// WHATSAPP SENDING
// ---------------------------------------------------------------------------
async function graph(payload) {
  const url = `${GRAPH_BASE}/${GRAPH_VERSION}/${PHONE_NUMBER_ID}/messages`;
  return axios.post(url, { messaging_product: 'whatsapp', recipient_type: 'individual', ...payload }, {
    headers: { Authorization: `Bearer ${ACCESS_TOKEN}`, 'Content-Type': 'application/json' },
    timeout: 15000,
  });
}

async function sendText(to, body) {
  try {
    await graph({ to, type: 'text', text: { body: String(body).slice(0, 4000), preview_url: true } });
  } catch (e) {
    log('❌ send failed', mask(to), e.response?.data?.error?.message || e.message);
  }
}

async function sendButtons(to, body, buttons) {
  // WhatsApp allows up to 3 reply buttons, titles up to 20 characters
  try {
    await graph({
      to, type: 'interactive',
      interactive: {
        type: 'button',
        body: { text: String(body).slice(0, 1024) },
        action: { buttons: buttons.slice(0, 3).map((b) => ({ type: 'reply', reply: { id: b.id, title: b.title.slice(0, 20) } })) },
      },
    });
  } catch (e) {
    log('⚠️ buttons failed, using text', mask(to), e.response?.data?.error?.message || e.message);
    await sendText(to, `${body}\n\n${buttons.map((b) => `• ${b.title}`).join('\n')}`);
  }
}

async function sendMenu(to, intro) {
  const rows = [
    { id: 'AIRTIME', title: '📱 Buy airtime', description: 'Top up any Nigerian network' },
    { id: 'BALANCE', title: '💰 Wallet balance', description: 'See what you have (PIN)' },
    { id: 'FUND', title: '➕ Fund wallet', description: 'Add money by card or transfer' },
    { id: 'HISTORY', title: '🧾 Last transactions', description: 'Your 5 most recent (PIN)' },
    { id: 'LINK', title: '🔗 Link my account', description: 'Connect WhatsApp to Net365' },
    { id: 'HELP', title: '🆘 Help', description: 'Talk to our team' },
  ];
  try {
    await graph({
      to, type: 'interactive',
      interactive: {
        type: 'list',
        body: { text: String(intro).slice(0, 1024) },
        action: { button: 'Open menu', sections: [{ title: 'Net365', rows }] },
      },
    });
  } catch (e) {
    log('⚠️ list failed, using text', mask(to), e.response?.data?.error?.message || e.message);
    await sendText(to, `${intro}\n\nReply with:\n*1* Buy airtime\n*2* Wallet balance\n*3* Fund wallet\n*4* Last transactions\n*5* Link my account\n*6* Help`);
  }
}

// ---------------------------------------------------------------------------
// SESSION STATE (in memory; use Redis if you run more than one bot instance)
// ---------------------------------------------------------------------------
const sessions = new Map();
const seen = new Map();        // message id -> time (Meta retries deliveries)
const rate = new Map();        // number -> [timestamps]
const queues = new Map();      // number -> promise chain (one message at a time per user)

function getSession(wa) {
  let s = sessions.get(wa);
  if (!s || Date.now() - s.t > SESSION_TTL_MS) s = { state: 'IDLE', data: {}, t: Date.now() };
  s.t = Date.now();
  sessions.set(wa, s);
  return s;
}
const reset = (wa) => sessions.set(wa, { state: 'IDLE', data: {}, t: Date.now() });

setInterval(() => {
  const now = Date.now();
  for (const [k, s] of sessions) if (now - s.t > SESSION_TTL_MS) sessions.delete(k);
  for (const [k, t] of seen) if (now - t > 60 * 60 * 1000) seen.delete(k);
  for (const [k, arr] of rate) { const a = arr.filter((x) => now - x < 60000); a.length ? rate.set(k, a) : rate.delete(k); }
}, 60 * 1000).unref();

function tooFast(wa) {
  const now = Date.now();
  const arr = (rate.get(wa) || []).filter((t) => now - t < 60000);
  arr.push(now); rate.set(wa, arr);
  return arr.length > MSG_PER_MINUTE;
}

// ---------------------------------------------------------------------------
// HELPERS
// ---------------------------------------------------------------------------
const naira = (n) => `₦${Number(n || 0).toLocaleString('en-NG', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

/** 08031234567 | +2348031234567 | 2348031234567 | 8031234567  ->  8031234567 (10-digit national) */
function nigerianNational(input, selfWa) {
  let d = String(input).replace(/\D/g, '');
  if (/^(me|my number|this)$/i.test(String(input).trim()) && selfWa) d = selfWa;
  if (d.startsWith('234')) d = d.slice(3);
  if (d.startsWith('0')) d = d.slice(1);
  return /^[789][01]\d{8}$/.test(d) ? d : null;
}

function parseAmount(text) {
  const t = String(text).toLowerCase().replace(/[₦,\s]|ngn|naira/g, '');
  const m = t.match(/^(\d+(?:\.\d+)?)(k)?$/);
  if (!m) return null;
  const v = parseFloat(m[1]) * (m[2] ? 1000 : 1);
  return Number.isFinite(v) ? Math.round(v * 100) / 100 : null;
}

const MENU_WORDS = /^(hi|hello|hey|menu|start|home|hola|good (morning|afternoon|evening))\b/i;
function intentFrom(text) {
  const t = text.toLowerCase();
  if (/^(1|airtime|buy|buy airtime|recharge|top ?up)\b/.test(t)) return 'AIRTIME';
  if (/^(2|balance|wallet|bal)\b/.test(t)) return 'BALANCE';
  if (/^(3|fund|add money|deposit)\b/.test(t)) return 'FUND';
  if (/^(4|history|transactions?|statement)\b/.test(t)) return 'HISTORY';
  if (/^(5|link|register|sign ?up)\b/.test(t)) return 'LINK';
  if (/^(unlink|disconnect)\b/.test(t)) return 'UNLINK';
  if (/^(6|help|support|agent)\b/.test(t)) return 'HELP';
  return null;
}

function explainApiError(r, fallback) {
  const d = r.data || {};
  if (r.status === 401) return 'Your session could not be verified. Please try again.';
  return d.error || d.message || fallback;
}

// ---------------------------------------------------------------------------
// ACTIONS
// ---------------------------------------------------------------------------
async function pinAuth(wa, pin) {
  const r = await bot('/api/whatsapp/auth', { wa, pin, require_pin: true });
  return r;
}

async function startIntent(wa, intent) {
  const s = getSession(wa);
  const st = await bot('/api/whatsapp/status', { wa });
  const linked = st.status === 200 && st.data.linked;

  if (intent === 'HELP') {
    reset(wa);
    return sendText(wa,
      `🆘 *Net365 Help*\n\n📧 ${SUPPORT_EMAIL}\n${SUPPORT_WHATSAPP ? `💬 ${SUPPORT_WHATSAPP}\n` : ''}🌐 ${NET365_PUBLIC_URL}\n\n` +
      `Never share your PIN or email codes with anyone — Net365 staff will never ask for them.\n\nReply *menu* to go back.`);
  }
  if (intent === 'LINK') {
    if (linked) { reset(wa); return sendText(wa, `✅ This WhatsApp number is already linked to your Net365 account, ${st.data.first_name}.\n\nReply *menu* to continue, or *unlink* to disconnect it.`); }
    s.state = 'LINK_EMAIL'; s.data = {};
    return sendText(wa, '🔗 *Link your account*\n\nWhat is the email address you used to sign up on Net365?\n\n_No account yet? Create one free at ' + NET365_PUBLIC_URL + '_');
  }
  if (!linked) {
    s.state = 'IDLE';
    return sendButtons(wa,
      st.data.blocked
        ? '⚠️ This account is unavailable. Please contact support.'
        : '🔗 Please link your Net365 account first. It takes about a minute and keeps your money safe.',
      st.data.blocked ? [{ id: 'HELP', title: 'Contact support' }] : [{ id: 'LINK', title: 'Link my account' }, { id: 'HELP', title: 'Help' }]);
  }

  switch (intent) {
    case 'AIRTIME':
      s.state = 'AIR_PHONE'; s.data = {};
      return sendText(wa, `📱 *Buy airtime*\n\nWhich number should I top up?\nSend the number (e.g. 08012345678) or reply *me* to use this WhatsApp number.`);
    case 'BALANCE':
      s.state = 'PIN'; s.data = { next: 'BALANCE', tries: 0 };
      return sendText(wa, '🔐 Enter your 4-digit Net365 PIN to see your balance.');
    case 'HISTORY':
      s.state = 'PIN'; s.data = { next: 'HISTORY', tries: 0 };
      return sendText(wa, '🔐 Enter your 4-digit Net365 PIN to see your recent transactions.');
    case 'FUND':
      s.state = 'FUND_AMOUNT'; s.data = {};
      return sendText(wa, `➕ *Fund wallet*\n\nHow much would you like to add? (minimum ${naira(FUND_MIN)})\nExample: *5000* or *5k*`);
    case 'UNLINK':
      s.state = 'PIN'; s.data = { next: 'UNLINK', tries: 0 };
      return sendText(wa, '🔐 Enter your PIN to disconnect WhatsApp from your Net365 account.');
    default:
      return sendMenu(wa, 'What would you like to do?');
  }
}

async function handlePin(wa, text) {
  const s = getSession(wa);
  const pin = text.trim();
  if (!/^\d{4}$/.test(pin)) return sendText(wa, '❌ Your PIN is 4 digits. Please try again, or reply *cancel*.');
  const next = s.data.next;

  if (next === 'UNLINK') {
    const r = await bot('/api/whatsapp/unlink', { wa, pin });
    reset(wa);
    if (r.status === 200 && r.data.success) return sendText(wa, '✅ WhatsApp has been disconnected from your Net365 account.');
    return sendText(wa, r.data.error === 'locked' ? '🔒 Too many wrong PINs. Try again in 30 minutes.' : '❌ Wrong PIN. Nothing was changed.');
  }

  const a = await pinAuth(wa, pin);
  if (a.status === 423) { reset(wa); return sendText(wa, `🔒 Too many wrong PINs. Your WhatsApp banking is locked for about ${a.data.retry_minutes || 30} minutes. If this wasn't you, contact ${SUPPORT_EMAIL}.`); }
  if (a.status === 401) {
    s.data.tries = (s.data.tries || 0) + 1;
    return sendText(wa, `❌ Wrong PIN. ${a.data.attempts_left} attempt${a.data.attempts_left === 1 ? '' : 's'} left before a 30-minute lock.\n\nTry again or reply *cancel*.`);
  }
  if (a.status !== 200 || !a.data.token) { reset(wa); return sendText(wa, '⚠️ I could not verify you right now. Please try again in a moment.'); }

  const token = a.data.token;
  try {
    if (next === 'BALANCE') {
      const r = await asUser(token, 'GET', '/api/dashboard/summary');
      reset(wa);
      if (!r.data.success) return sendText(wa, '⚠️ I could not load your balance right now.');
      const wallets = (r.data.summary.wallet.wallets || []).filter((w) => Number(w.balance) > 0 || w.currency === 'NGN');
      const lines = wallets.map((w) => `• ${w.currency === 'NGN' ? naira(w.balance) : `${w.currency} ${Number(w.balance).toLocaleString(undefined, { minimumFractionDigits: 2 })}`}`);
      const rw = r.data.summary.rewards || {};
      return sendText(wa, `💰 *Your Net365 wallet*\n\n${lines.join('\n') || '• ₦0.00'}\n\n⭐ ${rw.level || 'Bronze'} · ${rw.points || 0} points\n\nReply *menu* for more.`);
    }
    if (next === 'HISTORY') {
      const r = await asUser(token, 'GET', '/api/user/transactions?limit=5');
      reset(wa);
      const list = r.data.transactions || [];
      if (!list.length) return sendText(wa, '🧾 No transactions yet. Reply *airtime* to make your first recharge!');
      const lines = list.map((t) => {
        const sym = t.currency === 'NGN' || !t.currency ? '₦' : `${t.currency} `;
        const when = String(t.created_at || '').slice(0, 10);
        const state = ['fulfilled', 'completed', 'success'].includes(t.status) ? '✅' : t.status === 'pending' ? '⏳' : '❌';
        return `${state} ${(t.description || t.tx_type || 'Transaction').toString().slice(0, 38)}\n    ${sym}${Number(t.amount).toLocaleString()} · ${when}`;
      });
      return sendText(wa, `🧾 *Recent transactions*\n\n${lines.join('\n\n')}\n\nReply *menu* for more.`);
    }
    if (next === 'AIR_WALLET') {
      const d = s.data;
      const r = await asUser(token, 'POST', '/api/payment/init', {
        type: 'topup', provider: 'wallet', currency: 'NGN', country_code: 'NG',
        amount: d.total, service_amount: d.amount, operator_id: d.operatorId, phone: d.national,
      });
      reset(wa);
      const x = r.data;
      if (r.status === 200 && x.success) {
        return sendText(wa, `✅ *Airtime sent!*\n\n${naira(x.service_amount || d.amount)} → 0${d.national}\nNetwork: ${d.operatorName}\nCharged: ${naira(x.amount || d.total)}\nBalance: ${naira(x.wallet_balance)}\nRef: ${x.reference}\n\nThank you for using Net365 💙`);
      }
      if (r.status === 202) {
        return sendText(wa, `⏳ *Your recharge is processing.*\n\nWe'll finish it automatically — there's no need to pay again. Check *history* in a few minutes.\nRef: ${x.reference || '—'}`);
      }
      if (x.code === 'INSUFFICIENT_WALLET_FUNDS') {
        return sendButtons(wa, `❌ Your wallet has ${naira(x.wallet_balance)} but this needs ${naira(x.required || d.total)}.`, [{ id: 'FUND', title: 'Fund wallet' }, { id: 'MENU', title: 'Main menu' }]);
      }
      return sendText(wa, `❌ ${explainApiError(r, 'The recharge could not be completed.')}\n\nYou were not charged unless a reference was shown. Reply *menu* to try again.`);
    }
  } finally {
    revoke(token);
  }
}

async function payByLink(wa) {
  const s = getSession(wa);
  const d = s.data;
  const a = await bot('/api/whatsapp/auth', { wa, require_pin: false });
  if (a.status !== 200 || !a.data.token) { reset(wa); return sendText(wa, '⚠️ I could not start the payment. Please try again.'); }
  try {
    const r = await asUser(a.data.token, 'POST', '/api/payment/init', {
      type: 'topup', provider: 'paystack', currency: 'NGN', country_code: 'NG',
      amount: d.total, service_amount: d.amount, operator_id: d.operatorId, phone: d.national,
      return_url: `${NET365_PUBLIC_URL}/payment/success`,
    });
    const url = r.data.authorization_url || r.data.checkout_url;
    reset(wa);
    if (r.data.success && url) {
      return sendText(wa, `💳 *Pay ${naira(d.total)} by card or bank transfer*\n\n${url}\n\nYour ${naira(d.amount)} airtime for 0${d.national} is sent as soon as payment succeeds. You'll also get an email receipt.`);
    }
    return sendText(wa, `❌ ${explainApiError(r, 'I could not create the payment link.')}`);
  } finally { revoke(a.data.token); }
}

async function handleFundAmount(wa, text) {
  const amount = parseAmount(text);
  if (!amount || amount < FUND_MIN || amount > 5000000) return sendText(wa, `❌ Enter an amount from ${naira(FUND_MIN)} to ${naira(5000000)}, e.g. *5000* or *5k*.`);
  const a = await bot('/api/whatsapp/auth', { wa, require_pin: false });
  if (a.status !== 200 || !a.data.token) { reset(wa); return sendText(wa, '⚠️ I could not start the payment. Please try again.'); }
  try {
    const r = await asUser(a.data.token, 'POST', '/api/wallet/fund', {
      amount, currency: 'NGN', return_url: `${NET365_PUBLIC_URL}/payment/success`,
    });
    const url = r.data.authorization_url || r.data.checkout_url;
    reset(wa);
    if (r.data.success && url) return sendText(wa, `➕ *Add ${naira(amount)} to your wallet*\n\n${url}\n\nYour balance updates as soon as the payment succeeds.`);
    return sendText(wa, `❌ ${explainApiError(r, 'I could not create the funding link.')}`);
  } finally { revoke(a.data.token); }
}

// ---------------------------------------------------------------------------
// CONVERSATION ENGINE
// ---------------------------------------------------------------------------
/** msg = { kind: 'text'|'reply'|'other', text, id } */
async function handleMessage(wa, msg) {
  const s = getSession(wa);
  const raw = (msg.text || '').trim();
  const lower = raw.toLowerCase();

  // Global commands win over any state (this fixes the old "buy anywhere restarts everything" bug)
  if (/^(cancel|stop|exit|quit)$/.test(lower) || msg.id === 'CANCEL') {
    reset(wa);
    return sendText(wa, '🛑 Cancelled. Reply *menu* whenever you are ready.');
  }
  if (msg.id === 'MENU' || MENU_WORDS.test(lower)) {
    reset(wa);
    return sendMenu(wa, '👋 Welcome to *Net365*. What would you like to do?');
  }
  if (msg.kind === 'other') {
    return sendText(wa, 'I can only read text messages for now. Reply *menu* to see what I can do.');
  }

  // Menu / button choices from IDLE (or when the user taps a menu row mid-flow)
  const picked = msg.kind === 'reply' ? msg.id : (s.state === 'IDLE' ? intentFrom(lower) : null);
  if (picked && ['AIRTIME', 'BALANCE', 'FUND', 'HISTORY', 'LINK', 'UNLINK', 'HELP'].includes(picked)) {
    return startIntent(wa, picked);
  }
  if (s.state === 'IDLE' && /^unlink\b/.test(lower)) return startIntent(wa, 'UNLINK');

  switch (s.state) {
    // ---------------- linking ----------------
    case 'LINK_EMAIL': {
      if (!EMAIL_RE.test(raw)) return sendText(wa, '❌ That does not look like an email address. Please send it again, or reply *cancel*.');
      const r = await bot('/api/whatsapp/link/start', { wa, email: raw });
      if (r.status === 429) { reset(wa); return sendText(wa, '⏳ Too many codes requested. Please try again in an hour.'); }
      if (r.status !== 200) return sendText(wa, '⚠️ I could not send the code right now. Please try again.');
      s.data = { email: raw.toLowerCase() }; s.state = 'LINK_CODE';
      return sendText(wa, `📧 If an account exists for *${r.data.masked_email}*, we've sent a 6-digit code there.\n\nType the code here. It expires in 10 minutes.`);
    }
    case 'LINK_CODE': {
      const code = raw.replace(/\D/g, '');
      if (code.length !== 6) return sendText(wa, '❌ The code has 6 digits. Please check your email and try again.');
      s.data.code = code; s.state = 'LINK_PIN';
      return sendText(wa, '🔐 Now choose a *4-digit PIN*. You will use it to pay from your wallet and see your balance.\n\nAvoid birthdays and simple patterns like 1234.\n\n_After sending, long-press your PIN message and tap *Delete* so it does not stay in this chat._');
    }
    case 'LINK_PIN': {
      if (!/^\d{4}$/.test(raw)) return sendText(wa, '❌ Your PIN must be exactly 4 digits.');
      const r = await bot('/api/whatsapp/link/confirm', { wa, email: s.data.email, code: s.data.code, pin: raw });
      if (r.status === 200 && r.data.success) {
        reset(wa);
        return sendText(wa, `🎉 *All set, ${r.data.first_name}!* WhatsApp is linked to your Net365 account.\n\nPlease delete your PIN message now (long-press → Delete).\n\nReply *menu* to start.`);
      }
      const e = r.data.error;
      if (e === 'weak_pin') return sendText(wa, '❌ That PIN is too easy to guess. Choose a different 4-digit PIN.');
      if (e === 'bad_code') { s.state = 'LINK_CODE'; delete s.data.code; return sendText(wa, `❌ That code was wrong or expired${r.data.attempts_left !== undefined ? ` (${r.data.attempts_left} tries left)` : ''}. Type the 6-digit code again, or reply *cancel*.`); }
      if (r.status === 429) { reset(wa); return sendText(wa, '⏳ Too many attempts. Please try again in 15 minutes.'); }
      reset(wa);
      return sendText(wa, '⚠️ I could not link your account. Please start again with *link*.');
    }

    // ---------------- airtime ----------------
    case 'AIR_PHONE': {
      const national = nigerianNational(raw, wa);
      if (!national) return sendText(wa, '❌ Please send a valid Nigerian number, e.g. *08012345678*, or reply *me*.');
      const r = await net365.get('/api/operators/auto-detect', { params: { phone: '0' + national, country_code: 'NG' } });
      const op = r.data && r.data.operator;
      if (r.status !== 200 || !r.data.success || !op || !(op.operatorId || op.id)) {
        return sendText(wa, '⚠️ I could not detect that network. Please check the number and try again, or buy on the app: ' + NET365_PUBLIC_URL);
      }
      s.data = {
        national, operatorId: String(op.operatorId || op.id), operatorName: op.name || 'Network',
        guessed: r.data.source === 'prefix_fallback' || r.data.source === 'sandbox_fallback',
      };
      s.state = 'AIR_AMOUNT';
      return sendText(wa, `✅ 0${national} · *${s.data.operatorName}*${s.data.guessed ? '\n_(network inferred from the number prefix)_' : ''}\n\nHow much airtime? (${naira(AIRTIME_MIN)} – ${naira(AIRTIME_MAX)})\nExample: *500* or *1k*`);
    }
    case 'AIR_AMOUNT': {
      const amount = parseAmount(raw);
      if (!amount || amount < AIRTIME_MIN || amount > AIRTIME_MAX) return sendText(wa, `❌ Enter an amount from ${naira(AIRTIME_MIN)} to ${naira(AIRTIME_MAX)}.`);
      s.data.amount = amount; s.data.total = Math.round((amount + AIRTIME_SERVICE_FEE) * 100) / 100;
      s.state = 'AIR_CONFIRM';
      return sendButtons(wa,
        `📋 *Confirm recharge*\n\nNumber: 0${s.data.national}\nNetwork: ${s.data.operatorName}\nAirtime: ${naira(amount)}\nService fee: ${naira(AIRTIME_SERVICE_FEE)}\n*Total: ${naira(s.data.total)}*\n\nHow would you like to pay?`,
        [{ id: 'PAY_WALLET', title: 'Net365 wallet' }, { id: 'PAY_LINK', title: 'Card / transfer' }, { id: 'CANCEL', title: 'Cancel' }]);
    }
    case 'AIR_CONFIRM': {
      const choice = msg.id || (/wallet/.test(lower) ? 'PAY_WALLET' : /(card|link|transfer|paystack)/.test(lower) ? 'PAY_LINK' : '');
      if (choice === 'PAY_WALLET') { s.state = 'PIN'; s.data.next = 'AIR_WALLET'; s.data.tries = 0; return sendText(wa, `🔐 Enter your 4-digit PIN to pay ${naira(s.data.total)} from your wallet.`); }
      if (choice === 'PAY_LINK') return payByLink(wa);
      return sendText(wa, 'Please tap *Net365 wallet* or *Card / transfer*, or reply *cancel*.');
    }

    // ---------------- PIN gate ----------------
    case 'PIN': return handlePin(wa, raw);

    // ---------------- funding ----------------
    case 'FUND_AMOUNT': return handleFundAmount(wa, raw);

    default:
      return sendMenu(wa, `I didn't quite get that. Here's what I can do:`);
  }
}

// ---------------------------------------------------------------------------
// WEBHOOK
// ---------------------------------------------------------------------------
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb', verify: (req, res, buf) => { req.rawBody = buf; } }));

function verifySignature(req, res, next) {
  const header = req.headers['x-hub-signature-256'];
  if (!header) { log('Rejected: missing signature'); return res.status(401).send('Missing Signature'); }
  const [algo, sig] = String(header).split('=');
  if (algo !== 'sha256' || !sig) return res.status(401).send('Invalid Algorithm');
  const expected = crypto.createHmac('sha256', APP_SECRET).update(req.rawBody || Buffer.alloc(0)).digest();
  let got; try { got = Buffer.from(sig, 'hex'); } catch (_) { got = Buffer.alloc(0); }
  if (got.length !== expected.length || !crypto.timingSafeEqual(got, expected)) {
    log('Rejected: signature mismatch'); return res.status(403).send('Invalid Signature');
  }
  next();
}

app.get('/health', (req, res) => res.json({ ok: true, service: 'net365-whatsapp', uptime: process.uptime() }));

app.get('/webhook/whatsapp', (req, res) => {
  const ok = req.query['hub.mode'] === 'subscribe' && req.query['hub.verify_token'] === VERIFY_TOKEN;
  log(ok ? '✅ Webhook verified by Meta' : '❌ Webhook verification failed (token mismatch)');
  return ok ? res.status(200).send(req.query['hub.challenge']) : res.sendStatus(403);
});

function normalise(m) {
  if (m.type === 'text') return { kind: 'text', text: m.text?.body || '' };
  if (m.type === 'interactive') {
    const r = m.interactive?.button_reply || m.interactive?.list_reply;
    if (r) return { kind: 'reply', id: r.id, text: r.title || '' };
  }
  if (m.type === 'button') return { kind: 'text', text: m.button?.text || '' };
  return { kind: 'other', text: '' };
}

function enqueue(wa, fn) {
  const prev = queues.get(wa) || Promise.resolve();
  const next = prev.then(fn).catch((e) => log('❌ handler error', mask(wa), e.message)).finally(() => { if (queues.get(wa) === next) queues.delete(wa); });
  queues.set(wa, next);
  return next;
}

app.post('/webhook/whatsapp', verifySignature, (req, res) => {
  res.sendStatus(200); // acknowledge fast so Meta does not retry
  try {
    for (const entry of req.body.entry || []) {
      for (const change of entry.changes || []) {
        for (const m of change.value?.messages || []) {
          if (m.id && seen.has(m.id)) continue;
          if (m.id) seen.set(m.id, Date.now());
          const wa = String(m.from || '').replace(/\D/g, '');
          if (!wa) continue;
          log(`📩 ${mask(wa)} type=${m.type} state=${getSession(wa).state}`);
          if (tooFast(wa)) { enqueue(wa, () => sendText(wa, '⏳ You are sending messages very quickly. Please slow down.')); continue; }
          enqueue(wa, () => handleMessage(wa, normalise(m)));
        }
      }
    }
  } catch (e) { log('❌ webhook error', e.message); }
});

if (require.main === module) {
  app.listen(PORT, () => {
    log(`🚀 Net365 WhatsApp bot on :${PORT}  (Graph ${GRAPH_VERSION}, Net365 API ${NET365_API_URL})`);
    log(`   Webhook  http://localhost:${PORT}/webhook/whatsapp`);
    log(`   Health   http://localhost:${PORT}/health`);
  });
}

module.exports = { app, handleMessage, nigerianNational, parseAmount, sessions };
