// ─── rateLimiter.js ───────────────────────────────────────────────────────
// In-memory rate limiter — tidak butuh Redis/dependency tambahan.
// Cocok untuk single-instance deployment (Railway, Render, dsb).
//
// Cara pakai:
//   const { httpLimiter, checkBotLimit, formatTimeLeft } = require('./rateLimiter');
//
//   // Express middleware (pasang sebelum route handler)
//   app.post('/claim',   httpLimiter('claim',   5, 60),  handler);
//   app.post('/session', httpLimiter('session', 10, 60), handler);
//
//   // Di dalam bot handler
//   const limit = checkBotLimit('upload', userId, 20, 60);
//   if (!limit.ok) return bot.sendMessage(chatId, `⏳ Terlalu cepat. Coba lagi dalam ${formatTimeLeft(limit.retryAfter)}.`);

"use strict";

// ─── Store ─────────────────────────────────────────────────────────────────
// Map<bucketKey, { count: number, resetAt: number }>
const store = new Map();

// Bersihkan entry yang sudah expired setiap 5 menit agar memory tidak bocor
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of store) {
    if (now > val.resetAt) store.delete(key);
  }
}, 5 * 60 * 1000);

// ─── Core check ────────────────────────────────────────────────────────────
/**
 * Cek & catat satu hit untuk key tertentu.
 *
 * @param {string} key        - Unik per kombinasi action+identifier
 * @param {number} maxHits    - Maksimal hit dalam satu window
 * @param {number} windowSecs - Durasi window dalam detik
 * @returns {{ ok: boolean, remaining: number, retryAfter: number }}
 *   - ok          : true jika masih dalam batas
 *   - remaining   : sisa hit yang diizinkan
 *   - retryAfter  : milidetik sampai window reset (0 jika ok)
 */
function hit(key, maxHits, windowSecs) {
  const now      = Date.now();
  const windowMs = windowSecs * 1000;

  let entry = store.get(key);

  // Window baru atau sudah expired → reset
  if (!entry || now > entry.resetAt) {
    entry = { count: 0, resetAt: now + windowMs };
    store.set(key, entry);
  }

  entry.count++;

  if (entry.count > maxHits) {
    return {
      ok:         false,
      remaining:  0,
      retryAfter: entry.resetAt - now,
    };
  }

  return {
    ok:         true,
    remaining:  maxHits - entry.count,
    retryAfter: 0,
  };
}

// ─── Format helper ─────────────────────────────────────────────────────────
/**
 * Format milidetik ke string yang mudah dibaca.
 * Contoh: 61500 → "1 menit 1 detik"
 *
 * @param {number} ms
 * @returns {string}
 */
function formatTimeLeft(ms) {
  const totalSecs = Math.ceil(ms / 1000);
  const mins      = Math.floor(totalSecs / 60);
  const secs      = totalSecs % 60;

  if (mins > 0 && secs > 0) return `${mins} menit ${secs} detik`;
  if (mins > 0)              return `${mins} menit`;
  return `${secs} detik`;
}

// ─── HTTP Middleware (Express) ──────────────────────────────────────────────
/**
 * Buat Express middleware rate limiter.
 * Identifier diambil dari body.user_id → IP sebagai fallback.
 *
 * @param {string} action     - Nama aksi (untuk namespace bucket)
 * @param {number} maxHits    - Maksimal request per window
 * @param {number} windowSecs - Durasi window dalam detik
 * @returns {Function} Express middleware
 *
 * @example
 *   app.post('/claim', httpLimiter('claim', 5, 60), claimHandler);
 */
function httpLimiter(action, maxHits, windowSecs) {
  return (req, res, next) => {
    // Ambil identifier: user_id dari body, fallback ke IP
    const userId = req.body?.user_id
      ? String(parseInt(req.body.user_id))
      : null;
    const ip     = req.headers['x-forwarded-for']?.split(',')[0]?.trim()
                || req.socket?.remoteAddress
                || 'unknown';

    const identifier = userId || ip;
    const key        = `http:${action}:${identifier}`;
    const result     = hit(key, maxHits, windowSecs);

    // Tambahkan header standar rate limit
    res.set('X-RateLimit-Limit',     maxHits);
    res.set('X-RateLimit-Remaining', result.remaining);

    if (!result.ok) {
      const retryAfterSecs = Math.ceil(result.retryAfter / 1000);
      res.set('Retry-After', retryAfterSecs);

      console.warn(`[RATE LIMIT] HTTP ${action} — id: ${identifier}, retry: ${retryAfterSecs}s`);

      return res.status(429).json({
        ok:    false,
        error: `Terlalu banyak permintaan. Coba lagi dalam ${formatTimeLeft(result.retryAfter)}.`,
        retryAfter: retryAfterSecs,
      });
    }

    next();
  };
}

// ─── Bot Handler Check ──────────────────────────────────────────────────────
/**
 * Cek rate limit untuk Telegram bot handler (bukan middleware).
 * Panggil di awal handler, cek hasilnya, lalu lanjut atau tolak.
 *
 * @param {string} action     - Nama aksi, misal 'upload', 'multi', 'delete'
 * @param {number} userId     - Telegram user ID
 * @param {number} maxHits    - Maksimal aksi per window
 * @param {number} windowSecs - Durasi window dalam detik
 * @returns {{ ok: boolean, remaining: number, retryAfter: number }}
 *
 * @example
 *   const limit = checkBotLimit('upload', userId, 20, 3600);
 *   if (!limit.ok) {
 *     return bot.sendMessage(chatId, `⏳ Terlalu cepat. Coba lagi dalam ${formatTimeLeft(limit.retryAfter)}.`);
 *   }
 */
function checkBotLimit(action, userId, maxHits, windowSecs) {
  const key    = `bot:${action}:${userId}`;
  const result = hit(key, maxHits, windowSecs);

  if (!result.ok) {
    console.warn(`[RATE LIMIT] Bot ${action} — user: ${userId}, retry: ${Math.ceil(result.retryAfter / 1000)}s`);
  }

  return result;
}

// ─── Export ────────────────────────────────────────────────────────────────
module.exports = { httpLimiter, checkBotLimit, formatTimeLeft };
