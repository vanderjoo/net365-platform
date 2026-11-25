'use strict';
// OpenRouter fallback for Ask Net365. Fails closed: returns null on any problem so the caller uses its normal reply.
const axios = require('axios');
const KEY = process.env.OPENROUTER_API_KEY;
const MODEL = process.env.OPENROUTER_MODEL || 'openai/gpt-4o-mini';
const DAILY_CAP = Number(process.env.LLM_DAILY_CAP || 500);
const PER_USER_PER_HOUR = Number(process.env.LLM_USER_HOURLY || 10);
const FACTS = process.env.LLM_FACTS || `Net365 sells Nigerian airtime and data (MTN, Airtel, Glo, 9mobile), electricity tokens, cable TV, exam pins and gift cards.
It also tops up mobile phones in other countries. Customers can pay bills in Nigeria for family while abroad.
Every payment needs the customer to confirm with Pay now. Never share your PIN or codes with anyone.
Not supported yet: Starlink, home broadband, betting wallets, flights, ride credit, money transfers.
Support: support@net365co.com`;

let day = '', used = 0;
const perUser = new Map();
const mask = (t) => String(t).replace(/[\w.+-]+@[\w-]+\.[\w.]+/g, '[email]').replace(/\+?\d[\d\s-]{6,}\d/g, '[number]').slice(0, 400);

async function askLLM(question, lang = 'en', who = '') {
  if (!KEY) return null;
  const today = new Date().toISOString().slice(0, 10);
  if (day !== today) { day = today; used = 0; }
  if (used >= DAILY_CAP) return null;
  const now = Date.now();
  const hits = (perUser.get(who) || []).filter((t) => now - t < 3600e3);
  if (hits.length >= PER_USER_PER_HOUR) return null;
  hits.push(now); perUser.set(who, hits); used++;
  if (perUser.size > 20000) perUser.clear();
  try {
    const r = await axios.post('https://openrouter.ai/api/v1/chat/completions', {
      model: MODEL, max_tokens: 250, temperature: 0.2,
      messages: [
        { role: 'system', content: `You are Ask Net365, a short friendly helper. Answer ONLY from the facts below. If the answer is not there, say you are not sure and the team will follow up. Never ask for or repeat PINs, codes or card numbers. Never quote prices, fees or refund promises. Reply in language code "${lang}", at most 4 sentences, plain text.\n\nFACTS:\n${FACTS}` },
        { role: 'user', content: mask(question) },
      ],
    }, {
      timeout: 12000,
      headers: { Authorization: `Bearer ${KEY}`, 'HTTP-Referer': process.env.NET365_PUBLIC_URL || 'https://net365co.com', 'X-Title': 'Net365 Ask' },
    });
    const out = String(r.data && r.data.choices && r.data.choices[0] && r.data.choices[0].message && r.data.choices[0].message.content || '').trim();
    return out ? out.slice(0, 900) : null;
  } catch (e) { console.warn('LLM fallback failed:', (e.response && e.response.status) || e.code || e.message); return null; }
}
module.exports = { askLLM };
