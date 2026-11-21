'use strict';
/**
 * Net365 Ask: a location-aware assistant layer for the Telegram and WhatsApp bot.
 *
 *  1. WHERE ARE YOU?  Works out the customer's country from (a) the country they typed here, (b) the location they chose to
 *     share (with consent, already handled by the bot's /api/whatsapp/geo/* routes) or (c) the country code of their
 *     WhatsApp number. Telegram chats have no number, so they stay "unknown" until the customer says where they are.
 *  2. NIGERIA-ONLY SERVICES (electricity, cable TV, exam pins, insurance, Nigerian data bundles) are never offered blindly to
 *     someone outside Nigeria. Instead of blocking, Net365 asks: "Are you paying for a meter in Nigeria?" because many
 *     customers abroad pay bills for family at home.
 *  3. SERVICES NET365 DOES NOT HAVE (Starlink, home broadband, betting wallets...) get an honest "not yet", the customer's
 *     interest is logged, and Net365 lists real alternatives in THEIR country from the live operator list.
 *  4. TRANSACTIONS VIEW: an analytics card (spend this month, trend, success rate, where the money goes, insights) that
 *     mirrors the website analytics page, drawn with text so it works on both Telegram and WhatsApp.
 *
 * Everything here fails open: if anything throws, the caller carries on with the normal bot behaviour.
 * It never moves money and never shows a provider name.
 */
const fs = require('fs');
const nodePath = require('path');

module.exports = function createAsk(d) {
  const { bot, net365Get, sendText, sendButtons, isTg, getSession, reset, log, COUNTRIES, regionName } = d;

  // ------------------------------------------------------------------ countries
  const NG = { cc: 'NG', name: 'Nigeria', flag: '🇳🇬', dial: '234' };
  const flagOf = (cc) => { try { return String.fromCodePoint(...[...String(cc).toUpperCase()].map((c) => 127397 + c.charCodeAt(0))); } catch (e) { return '🌍'; } };
  const byCc = (cc) => {
    cc = String(cc || '').toUpperCase();
    if (cc === 'NG') return NG;
    return COUNTRIES.find((c) => c.cc === cc) || { cc, name: regionName(cc), flag: flagOf(cc), dial: '' };
  };
  const NICK = { uk: 'GB', england: 'GB', britain: 'GB', 'great britain': 'GB', usa: 'US', america: 'US', 'united states of america': 'US', uae: 'AE', naija: 'NG' };
  let REV = null;
  function nameToCc(text) {
    const t = String(text || '').trim().toLowerCase();
    if (!t) return null;
    if (NICK[t]) return NICK[t];
    if (/^[a-z]{2}$/.test(t)) { try { if (regionName(t.toUpperCase()) !== t.toUpperCase()) return t.toUpperCase(); } catch (e) { /* ignore */ } }
    if (!REV) {
      REV = new Map();
      try {
        const dn = new Intl.DisplayNames(['en'], { type: 'region' });
        for (let a = 65; a < 91; a++) for (let b = 65; b < 91; b++) {
          const cc = String.fromCharCode(a, b);
          try { const n = dn.of(cc); if (n && n !== cc) REV.set(n.toLowerCase(), cc); } catch (e) { /* not a region */ }
        }
      } catch (e) { /* no Intl.DisplayNames */ }
    }
    return REV.get(t) || null;
  }
  const DIAL = [NG, ...COUNTRIES].sort((a, b) => b.dial.length - a.dial.length);
  function fromNumber(wa) {
    if (isTg(wa)) return null;
    const digits = String(wa).replace(/\D/g, '');
    if (digits.length < 8) return null;
    try { const l = d.lpnCountry && d.lpnCountry('+' + digits); if (l && l.cc) return { country: byCc(l.cc), confidence: 'high' }; } catch (e) { /* fall through */ }
    const c = DIAL.find((x) => digits.startsWith(x.dial));
    return c ? { country: c, confidence: c.dial === '1' ? 'low' : 'high' } : null;
  }

  // The country a customer told us they are in is remembered (small JSON file, same folder as the language store).
  const STORE = d.storeDir && d.storeDir !== 'memory' ? nodePath.join(d.storeDir, 'ask-country.json') : null;
  const chosen = new Map();
  try { if (STORE && fs.existsSync(STORE)) for (const [k, v] of Object.entries(JSON.parse(fs.readFileSync(STORE, 'utf8')))) chosen.set(k, v); } catch (e) { /* start empty */ }
  function saveChosen() {
    if (!STORE) return;
    try { fs.mkdirSync(nodePath.dirname(STORE), { recursive: true }); fs.writeFileSync(STORE, JSON.stringify(Object.fromEntries(chosen))); } catch (e) { /* not fatal */ }
  }
  const geoCache = new Map();
  async function geoCountry(wa) {
    const hit = geoCache.get(wa);
    if (hit && Date.now() - hit.t < 10 * 60 * 1000) return hit.cc;
    let cc = null;
    try {
      const p = await bot('/api/whatsapp/geo/profile', { wa });
      if (p.status === 200 && p.data && p.data.enabled !== false && p.data.consent === 'granted' && p.data.country) cc = nameToCc(p.data.country);
    } catch (e) { /* no geo */ }
    geoCache.set(wa, { t: Date.now(), cc });
    return cc;
  }
  /** { country, source: 'chosen' | 'location' | 'number' | 'unknown', confidence } */
  async function where(wa) {
    const c = chosen.get(String(wa));
    if (c) return { country: byCc(c), source: 'chosen', confidence: 'high' };
    const g = await geoCountry(wa);
    if (g) return { country: byCc(g), source: 'location', confidence: 'high' };
    const n = fromNumber(wa);
    if (n) return { country: n.country, source: 'number', confidence: n.confidence };
    return { country: null, source: 'unknown', confidence: 'none' };
  }
  const via = (w) => (w.source === 'location' ? 'the location you shared' : w.source === 'chosen' ? 'the country you told me' : 'your phone number');

  // ------------------------------------------------------------------ what exists where
  /** Services that only work for Nigerian accounts, meters, smartcards and exam bodies. */
  const NG_ONLY = new Set(['BILLS', 'UTILITY_ELECTRICITY', 'UTILITY_CABLE', 'EDU', 'INSURANCE', 'DATA']);
  const NG_WORDS = [
    ['UTILITY_ELECTRICITY', /\b(aba ?power|electric\w*|light bill|power bill|nepa|prepaid meter|postpaid meter|meter (number|no)|disco|ikeja|ikedc|ekedc|eko (electric|disco|edc)|ibedc|ibadan electric|aedc|abuja electric|phed|kedco|kaduna electric|enugu electric|eedc|jos electric|yola electric|benin electric)\b/i],
    ['UTILITY_CABLE', /\b(dstv|gotv|startimes|showmax|cable tv|decoder|tv subscription|smartcard)\b/i],
    ['EDU', /\b(waec|neco|nabteb|jamb|utme|exam pins?|result checker|school fees)\b/i],
    ['INSURANCE', /\b(motor insurance|car insurance|third[- ]party insurance)\b/i],
  ];
  const NG_LABEL = { UTILITY_ELECTRICITY: 'electricity', UTILITY_CABLE: 'cable TV', EDU: 'exam pins', INSURANCE: 'insurance', BILLS: 'bills', DATA: 'data bundles' };

  /** Things people ask for that Net365 cannot do yet. cat decides which alternatives we offer. */
  const UNSUPPORTED = [
    { key: 'starlink', name: 'Starlink', cat: 'internet', rx: /\bstar ?link\b|\bspacex\b/i, why: 'Starlink bills through its own account, so I cannot pay it for you yet.' },
    { key: 'satellite', name: 'Satellite internet', cat: 'internet', rx: /\b(hughes ?net|viasat|satellite (internet|wifi|wi-fi|broadband|dish))\b/i, why: 'Satellite internet providers are not connected to Net365 yet.' },
    { key: 'homeinternet', name: 'Home internet', cat: 'internet', rx: /\b(spectranet|swift ?networks?|ipnx|fibre ?one|tizeti|ntel|broadband|fib(re|er)( optic)?|home (wi-?fi|internet)|router (plan|subscription|data)|wifi (plan|subscription|bill))\b/i, why: 'Home and office internet providers are not connected to Net365 yet.' },
    { key: 'betting', name: 'Betting wallets', cat: 'other', rx: /\b(bet9ja|sportybet|1xbet|betking|nairabet|betting|bet wallet)\b/i, why: 'Betting wallets are not something Net365 supports.' },
    { key: 'flights', name: 'Flights and hotels', cat: 'other', rx: /\b(flights?|airline tickets?|book (a )?(flight|hotel)|hotel booking)\b/i, why: 'Travel bookings are not on Net365 yet.' },
    { key: 'rides', name: 'Ride-hailing', cat: 'other', rx: /\b(uber|bolt|lyft|indriver|ride credit)\b/i, why: 'Ride-hailing credit is not on Net365 yet.' },
    { key: 'transfers', name: 'Money transfers', cat: 'other', rx: /\b(western union|moneygram|remittance|send money abroad)\b/i, why: 'Cash transfers are not on Net365 yet.' },
  ];

  // Live operator list for any country. Net365 asks its own API, which asks the airtime and data network provider.
  const opCache = new Map();
  async function operatorsFor(cc) {
    const hit = opCache.get(cc);
    if (hit && Date.now() - hit.t < 10 * 60 * 1000) return hit.v;
    let v = { all: [], data: [] };
    try {
      const r = await net365Get(`/api/operators/country/${cc}`);
      const arr = Array.isArray(r.data) ? r.data : (Array.isArray(r.data && r.data.operators) ? r.data.operators : []);
      if (r.status === 200 && arr.length) {
        const live = arr.filter((o) => (o.operatorId || o.id) && o.name && (!o.status || /active/i.test(o.status)));
        const base = (n) => String(n).replace(/\s*\b(data|bundles?|internet|airtime|pin|voucher|topup|top-up)\b\s*/gi, ' ').replace(/\s{2,}/g, ' ').replace(/\s*\(.*?\)\s*/g, ' ').trim();
        const uniq = (list) => [...new Set(list.map((o) => base(o && o.name !== undefined ? o.name : o)).filter(Boolean))];
        v = { all: uniq(live.filter((o) => o.pin !== true)), data: uniq(live.filter((o) => o.data === true || /\b(data|bundle|internet|broadband)\b/i.test(o.name))) };
        opCache.set(cc, { t: Date.now(), v });
      } else if (hit) return hit.v;
    } catch (e) { log('ask: operator list failed', cc, e.message); }
    return v;
  }
  const list = (names, max = 6) => names.slice(0, max).join(', ') + (names.length > max ? ` and ${names.length - max} more` : '');

  async function interest(wa, service, cc, query) {
    try {
      const r = await bot('/api/whatsapp/interest', { wa, service, country: cc || '', query: String(query || '').slice(0, 160) });
      return r.status === 200 && r.data && r.data.success;
    } catch (e) { return false; }
  }

  // ------------------------------------------------------------------ replies
  const COUNTRY_BTNS = [{ id: 'ASK_C_NG', title: '🇳🇬 Nigeria' }, { id: 'ASK_C_CA', title: '🇨🇦 Canada' }, { id: 'ASK_C_GB', title: '🇬🇧 United Kingdom' }];
  const pending = new Map(); // wa -> { kind, intent|query, at }
  const fresh = (p) => p && Date.now() - p.at < 15 * 60 * 1000;
  const ngOk = new Map();    // wa -> time the customer said "yes, a Nigerian meter"; we do not ask again for 24 hours
  const ngOkNow = (wa) => { const t = ngOk.get(wa); return !!t && Date.now() - t < 24 * 3600 * 1000; };

  async function askCountry(wa, then) {
    pending.set(wa, { kind: 'country', then, at: Date.now() });
    const s = getSession(wa); s.state = 'ASK_COUNTRY';
    return sendButtons(wa, '*Which country are you in?*\n\nI will only suggest what actually works where you are. Tap one, or type the country name.\n\n_I only keep this to tailor suggestions. Reply *cancel* to skip._', COUNTRY_BTNS);
  }
  async function countryStep(wa, raw) {
    if (/^(cancel|skip|menu|stop)$/i.test(raw)) { reset(wa); pending.delete(wa); return d.sendMenu(wa, 'No problem. What would you like to do?'); }
    const cc = nameToCc(raw);
    if (!cc) return sendText(wa, 'I did not recognise that country. Type it like *Canada* or *Ghana*, or reply *cancel*.');
    return setCountry(wa, cc);
  }
  async function setCountry(wa, cc) {
    chosen.set(String(wa), cc); saveChosen();
    const p = pending.get(wa); pending.delete(wa); reset(wa);
    const c = byCc(cc);
    await sendText(wa, `${c.flag} *${c.name}*. Got it.`);
    if (p && fresh(p) && p.then && p.then.type === 'query') return handle(wa, p.then.text, p.then.text.toLowerCase(), { force: true });
    if (p && fresh(p) && p.then && p.then.type === 'intent') return d.startIntent(wa, p.then.intent);
    return capabilities(wa);
  }

  /** "Are you paying for something in Nigeria?" Returns true when it asked (the caller must stop). */
  async function gate(wa, intent) {
    try {
      if (!NG_ONLY.has(intent) || ngOkNow(wa)) return false;
      const w = await where(wa);
      if (!w.country || w.country.cc === 'NG') return false;
      pending.set(wa, { kind: 'ng', intent, at: Date.now() });
      const lab = NG_LABEL[intent] || 'bills';
      const lowConf = w.confidence === 'low' ? ' (that number starts with +1, so I cannot tell if it is Canada or the US)' : '';
      await sendButtons(wa,
        `*${w.country.flag} You seem to be in ${w.country.name}*\n\nBased on ${via(w)}${lowConf}. Nigerian ${lab} only work for meters, accounts and numbers in Nigeria, so I will not offer them blindly.\n\nAre you paying for someone in Nigeria?`,
        [{ id: 'ASK_NG_YES', title: 'Yes, in Nigeria' }, { id: 'ASK_NG_NO', title: 'No, show my options' }, { id: 'ASK_NG_WRONG', title: "I'm in Nigeria" }]);
      return true;
    } catch (e) { log('ask gate failed (continuing normally):', e.message); return false; }
  }

  async function capabilities(wa, forCc) {
    const w = await where(wa);
    const c = forCc ? byCc(forCc) : w.country;
    if (!c) return askCountry(wa, { type: 'query', text: 'what can i do' });
    const lines = [];
    if (c.cc === 'NG') {
      lines.push('• Airtime and data on MTN, Airtel, Glo and 9mobile', '• Electricity, cable TV and exam pins', '• Gift cards, scheduled payments and spending insights');
    } else {
      const ops = await operatorsFor(c.cc);
      lines.push(ops.all.length ? `• Mobile top-ups in ${c.name}: ${list(ops.all)}` : `• Mobile top-ups in ${c.name} (ask me to check the live list)`);
      if (ops.data.length) lines.push(`• Mobile data: ${list(ops.data)}`);
      lines.push('• Gift cards', '• Pay electricity, TV or exam pins for family in Nigeria 🇳🇬');
    }
    reset(wa);
    return sendButtons(wa, `*${c.flag} What Net365 can do for you${forCc ? ' in ' + c.name : ''}*\n\n${lines.join('\n')}\n\n_Not on the list? Just tell me what you need and I will find the closest option._`,
      c.cc === 'NG' ? [{ id: 'AIRTIME', title: 'Buy airtime' }, { id: 'BILLS', title: 'Pay a bill' }, { id: 'MENU', title: 'Menu' }]
        : [{ id: 'ASK_TOPUP', title: 'Top up a phone' }, { id: 'GIFTCARD', title: 'Gift cards' }, { id: 'MENU', title: 'Menu' }]);
  }

  async function unsupported(wa, u, text) {
    let w = await where(wa);
    if (!w.country) return askCountry(wa, { type: 'query', text });
    const c = w.country;
    const ok = await interest(wa, u.key, c.cc, text);
    let alt = '';
    let buttons;
    if (u.cat === 'internet') {
      if (c.cc === 'NG') {
        const ops = (await d.ngOperators().catch(() => [])).map((o) => o.short);
        const names = ops.length ? list(ops) : 'MTN, Airtel, Glo and 9mobile';
        alt = `*What you can do in ${c.flag} ${c.name} today*\n• Mobile data bundles on ${names}. Good as a backup when your main line is down, and a hotspot works anywhere there is signal.\n• Pay your mobile data from your Net365 wallet in a few taps.`;
        buttons = [{ id: d.svcState('DATA') === 'live' ? 'DATA' : 'AIRTIME', title: d.svcState('DATA') === 'live' ? 'Buy data' : 'Buy airtime' }];
      } else {
        const ops = await operatorsFor(c.cc);
        const names = ops.data.length ? ops.data : ops.all;
        alt = names.length
          ? `*What you can do in ${c.flag} ${c.name} today*\n• Top up mobile ${ops.data.length ? 'data' : 'airtime'} on ${list(names)}. These are the live options Net365 can reach in ${c.name}, and a mobile hotspot is a solid backup when home or satellite internet is not an option.`
          : `*What you can do in ${c.flag} ${c.name} today*\nI could not load the live list of mobile networks for ${c.name} just now. Tap *Top up a phone* and I will check again.`;
        buttons = [{ id: 'ASK_TOPUP', title: 'Top up a phone' }];
      }
    } else {
      alt = `*Closest things I can do in ${c.flag} ${c.name} today*\n• ${c.cc === 'NG' ? 'Airtime, data, electricity, cable TV and gift cards' : 'Mobile top-ups and gift cards'}\n• Tell me what you are trying to achieve and I will suggest the nearest option.`;
      buttons = [{ id: c.cc === 'NG' ? 'AIRTIME' : 'ASK_TOPUP', title: c.cc === 'NG' ? 'Buy airtime' : 'Top up a phone' }];
    }
    reset(wa);
    await sendText(wa, `*${u.name} is not on Net365 yet.*\n\n${u.why}${ok ? ' I have noted that you asked, which helps the team decide what to add next.' : ''}\n\n${alt}`);
    return sendButtons(wa, 'What would you like to do?', [...buttons, { id: 'GIFTCARD', title: 'Gift cards' }, { id: 'MENU', title: 'Menu' }].slice(0, 3));
  }

  /**
   * Natural-language entry. Returns true when it answered.
   * Strict by default: only NG-only words from outside Nigeria, things Net365 does not have, and "what can I do here?" questions.
   * opts.force (the customer tapped "Ask Net365") makes it always answer.
   */
  async function handle(wa, raw, lower, opts = {}) {
    try {
      const t = String(raw || '').trim();
      if (!t) return false;
      // 1. something Net365 does not have yet
      const u = UNSUPPORTED.find((x) => x.rx.test(t));
      if (u) { await unsupported(wa, u, t); return true; }
      // 2. a Nigerian service while the customer is somewhere else
      for (const [intent, rx] of NG_WORDS) {
        if (rx.test(t)) { if (await gate(wa, intent)) return true; break; }
      }
      // 3. "what can I do / buy / pay (in X)?"
      const q = /^(what|which)\b.*\b(can|could|do)\b.*\b(buy|pay|do|get|recharge|use|offer)\b|^(what|which) (services|things|bills|options)\b|^(services|options)( available)?( in .+)?$/i.exec(t);
      if (q) {
        const inM = /\bin\s+([a-z .'-]{3,30})$/i.exec(t.replace(/[?.!]+$/, ''));
        const cc = inM ? nameToCc(inM[1]) : null;
        await capabilities(wa, cc || undefined); return true;
      }
      // 4. the customer tapped Ask Net365 and said something we could not place: say so honestly and log it
      if (opts.force) {
        const w = await where(wa);
        const c = w.country || NG;
        await interest(wa, 'other', c.cc, t);
        reset(wa);
        await sendText(wa, `I could not match *"${t.slice(0, 80)}"* to something Net365 does today, so I have noted it for the team.\n\nHere is what I can do in ${c.flag} ${c.name}:`);
        return capabilities(wa);
      }
      return false;
    } catch (e) { log('ask handle failed (continuing normally):', e.message); return false; }
  }

  const owns = (id) => /^ASK_/.test(String(id || ''));
  async function onReply(wa, id) {
    const p = pending.get(wa);
    if (id === 'ASK_PROMPT') {
      const s = getSession(wa); s.state = 'ASK_NET365'; s.data = {};
      const w = await where(wa);
      const here = w.country ? `${w.country.flag} ${w.country.name}` : 'your location';
      return sendText(wa, `*Ask Net365*\n\nTell me what you need in your own words, for ${here}. For example:\n• pay my light bill\n• I want Starlink\n• data for my brother in Ghana\n• what can I do here?\n\n_Reply *cancel* to go back._`);
    }
    const cm = /^ASK_C_([A-Z]{2})$/.exec(id);
    if (cm) return setCountry(wa, cm[1]);
    if (id === 'ASK_NG_YES') {
      ngOk.set(wa, Date.now()); pending.delete(wa); reset(wa);
      return d.startIntent(wa, (p && fresh(p) && p.intent) || 'BILLS');
    }
    if (id === 'ASK_NG_WRONG') {
      chosen.set(String(wa), 'NG'); saveChosen(); ngOk.set(wa, Date.now()); pending.delete(wa); reset(wa);
      await sendText(wa, '🇳🇬 *Nigeria*. Noted, I will remember that.');
      return d.startIntent(wa, (p && fresh(p) && p.intent) || 'BILLS');
    }
    if (id === 'ASK_NG_NO') { pending.delete(wa); return capabilities(wa); }
    if (id === 'ASK_TOPUP') {
      const w = await where(wa);
      if (!w.country || w.country.cc === 'NG') return d.startIntent(wa, w.country ? 'AIRTIME' : 'INTL');
      if (!(await d.requireLinked(wa))) return;
      reset(wa);
      return d.intlSetCountry(wa, byCc(w.country.cc));
    }
    const nm = /^ASK_NOTIFY_([a-z0-9]+)$/.exec(id);
    if (nm) {
      const w = await where(wa); const ok = await interest(wa, nm[1], w.country && w.country.cc, 'notify');
      return sendText(wa, ok ? '✅ Noted. I have logged your request for the team.' : '⚠️ I could not log that right now. Please try again in a moment.');
    }
    return false;
  }

  // ------------------------------------------------------------------ transactions analytics (text version of the web analytics page)
  const SYM = { NGN: '₦', USD: '$', GBP: '£', EUR: '€', CAD: 'C$', AUD: 'A$' };
  const kind = (s) => {
    s = String(s || 'pending').toLowerCase();
    if (['fulfilled', 'completed', 'success', 'successful'].includes(s)) return 'ok';
    if (s === 'refunded') return 'ref';
    if (['failed', 'fulfillment_failed', 'cancelled', 'canceled', 'rejected', 'expired'].includes(s)) return 'bad';
    return 'wait';
  };
  const TYPE_NAME = { topup: 'Airtime', data: 'Data', electricity: 'Electricity', tv: 'Cable TV', education: 'Exams', insurance: 'Insurance', utility: 'Bills', giftcard: 'Gift cards', transfer: 'Transfers', wallet_funding: 'Wallet top-up' };
  const NOT_SPEND = new Set(['wallet_funding', 'reward', 'referral']);
  const dateOf = (v) => { let s = String(v || ''); if (!s) return new Date(NaN); if (!/Z|[+-]\d\d:?\d\d$/.test(s)) s = s.replace(' ', 'T') + 'Z'; return new Date(s); };
  const bar = (pct, n = 8) => { const f = Math.max(0, Math.min(n, Math.round((Number(pct) || 0) / 100 * n))); return '▰'.repeat(f) + '▱'.repeat(n - f); };
  const SPARK = '▁▂▃▄▅▆▇█';
  const spark = (vals) => { const m = Math.max(...vals, 0); return vals.map((v) => (m === 0 ? '▁' : SPARK[Math.min(7, Math.floor(v / m * 7.999))])).join(''); };

  /** Returns { text, hasData }. list = transactions as returned by /api/user/transactions. */
  function historyCard(list) {
    const all = Array.isArray(list) ? list : [];
    if (!all.length) return { text: '*Your transactions*\n\nNothing yet. Reply *airtime* to make your first recharge.', hasData: false };
    const cc = {}; all.forEach((t) => { const c = t.currency || 'NGN'; cc[c] = (cc[c] || 0) + 1; });
    const cur = Object.keys(cc).sort((a, b) => cc[b] - cc[a])[0];
    const sym = SYM[cur] || cur + ' ';
    const money = (n) => `${sym}${Math.round(Number(n) || 0).toLocaleString('en-NG')}`;
    const tx = all.filter((t) => (t.currency || 'NGN') === cur);
    const amt = (t) => parseFloat(t.amount || 0) || 0;
    const key = (t) => String(t.tx_type || t.type || '').toLowerCase();
    const paid = tx.filter((t) => kind(t.status) === 'ok');
    const spend = paid.filter((t) => !NOT_SPEND.has(key(t)));
    const now = new Date(), m = now.getMonth(), y = now.getFullYear(), lm = m === 0 ? 11 : m - 1, ly = m === 0 ? y - 1 : y;
    const inM = (t, mm, yy) => { const x = dateOf(t.created_at); return x.getMonth() === mm && x.getFullYear() === yy; };
    const sum = (l) => l.reduce((a, t) => a + amt(t), 0);
    const thisM = sum(spend.filter((t) => inM(t, m, y))), lastM = sum(spend.filter((t) => inM(t, lm, ly)));
    const delta = lastM > 0 ? `${thisM >= lastM ? '▲' : '▼'} ${Math.abs(Math.round((thisM - lastM) / lastM * 100))}% vs last month` : 'first month tracked';
    const rate = tx.length ? Math.round(paid.length / tx.length * 100) : 0;
    const cnt = { ok: 0, wait: 0, bad: 0, ref: 0 }; tx.forEach((t) => { cnt[kind(t.status)]++; });

    // 14-day trend
    const days = []; const base = new Date(); base.setHours(0, 0, 0, 0);
    for (let i = 13; i >= 0; i--) { const x = new Date(base); x.setDate(x.getDate() - i); days.push({ t: x.getTime(), v: 0 }); }
    spend.forEach((t) => { const x = dateOf(t.created_at); if (isNaN(x)) return; x.setHours(0, 0, 0, 0); const s = days.find((dd) => dd.t === x.getTime()); if (s) s.v += amt(t); });

    // where the money goes
    const by = {}; spend.forEach((t) => { const k = TYPE_NAME[key(t)] || (key(t) || 'Other').replace(/_/g, ' '); by[k] = (by[k] || 0) + amt(t); });
    const top = Object.entries(by).sort((a, b) => b[1] - a[1]).slice(0, 4);
    const tot = top.reduce((a, r) => a + r[1], 0) || 1;
    const w = Math.max(...top.map((r) => r[0].length), 6) + 2;

    const lines = [];
    lines.push('*Your money at a glance*');
    lines.push('');
    lines.push('```');
    lines.push('◆ NET365 · THIS MONTH');
    lines.push('────────────────────────');
    lines.push(`Spent   ${money(thisM)}`);
    lines.push(`        ${delta}`);
    lines.push(`Trend   ${spark(days.map((x) => x.v))}  14d`);
    lines.push(`Success ${bar(rate, 8)} ${rate}%`);
    lines.push(`        ● ${cnt.ok}  ◐ ${cnt.wait}  ○ ${cnt.bad}${cnt.ref ? `  ↺ ${cnt.ref}` : ''}`);
    if (top.length) {
      lines.push('────────────────────────');
      top.forEach(([k, v]) => lines.push(`${k.padEnd(w)}${bar(v / tot * 100, 6)} ${Math.round(v / tot * 100)}%`));
    }
    lines.push('```');

    // insights, computed from the data and nothing else
    const ins = [];
    const names = ['Sundays', 'Mondays', 'Tuesdays', 'Wednesdays', 'Thursdays', 'Fridays', 'Saturdays'];
    const dow = [0, 0, 0, 0, 0, 0, 0]; spend.forEach((t) => { const x = dateOf(t.created_at); if (!isNaN(x)) dow[x.getDay()]++; });
    if (Math.max(...dow) > 1) ins.push(`You pay most often on ${names[dow.indexOf(Math.max(...dow))]}.`);
    const big = spend.slice().sort((a, b) => amt(b) - amt(a))[0];
    if (big) ins.push(`Biggest payment: ${money(amt(big))} on ${TYPE_NAME[key(big)] || 'a bill'}.`);
    if (cnt.bad) ins.push(`${cnt.bad} payment${cnt.bad > 1 ? 's' : ''} did not go through. If you were charged, the money returns to your wallet. Send *status REFERENCE* to check one.`);
    else if (cnt.wait) ins.push(`${cnt.wait} payment${cnt.wait > 1 ? 's are' : ' is'} still pending. Please do not pay again.`);
    if (ins.length) lines.push('', ...ins.slice(0, 3).map((x) => `› ${x}`));

    // latest five
    lines.push('', '*Latest*');
    tx.slice().sort((a, b) => dateOf(b.created_at) - dateOf(a.created_at)).slice(0, 5).forEach((t) => {
      const k = kind(t.status); const g = k === 'ok' ? '●' : k === 'wait' ? '◐' : k === 'ref' ? '↺' : '○';
      const x = dateOf(t.created_at);
      lines.push(`${g} ${String(t.description || TYPE_NAME[key(t)] || 'Transaction').slice(0, 30)}  ${sym}${Math.round(amt(t)).toLocaleString('en-NG')}${isNaN(x) ? '' : ' · ' + x.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })}`);
    });
    if (all.length > tx.length) lines.push('', `_${all.length - tx.length} payment(s) in other currencies are not counted above._`);
    return { text: lines.join('\n'), hasData: true };
  }

  return { NG_ONLY, where, gate, handle, owns, onReply, countryStep, historyCard, askCountry };
};
