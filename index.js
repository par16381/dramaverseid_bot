require("dotenv").config();
const TelegramBot = require("node-telegram-bot-api");
const { Pool } = require("pg");
const express = require("express");
const cors = require("cors");
const { httpLimiter, checkBotLimit, formatTimeLeft } = require("./rateLimiter");
const crypto = require("crypto");

// ─── EXPRESS ───────────────────────────────────────────────────────────────
const app = express();
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type']
}));
app.options('*', cors());
app.use(express.json());

// ─── DATABASE ──────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS links (
      code          TEXT PRIMARY KEY,
      type          TEXT NOT NULL,
      data          JSONB NOT NULL,
      owner_id      BIGINT,
      download_count INT DEFAULT 0,
      created_at    TIMESTAMP DEFAULT NOW(),
      expires_at    TIMESTAMP DEFAULT NULL
    )
  `);

  await pool.query(`ALTER TABLE links ADD COLUMN IF NOT EXISTS owner_id BIGINT`).catch(() => {});
  await pool.query(`ALTER TABLE links ADD COLUMN IF NOT EXISTS download_count INT DEFAULT 0`).catch(() => {});
  await pool.query(`ALTER TABLE links ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP DEFAULT NULL`).catch(() => {});
  await pool.query(`ALTER TABLE links ADD COLUMN IF NOT EXISTS title TEXT DEFAULT NULL`).catch(() => {});

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ad_sessions (
      id         SERIAL PRIMARY KEY,
      code       TEXT NOT NULL,
      user_id    BIGINT NOT NULL,
      verified   BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT NOW(),
      expires_at TIMESTAMP DEFAULT NOW() + INTERVAL '30 minutes'
    )
  `);

  // Index agar query session lebih cepat
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_ad_sessions_code_user
    ON ad_sessions (code, user_id)
  `).catch(() => {});

  // Tabel blacklist user
  await pool.query(`
    CREATE TABLE IF NOT EXISTS blocked_users (
      user_id    BIGINT PRIMARY KEY,
      reason     TEXT DEFAULT 'Tidak ada alasan',
      banned_by  BIGINT NOT NULL,
      banned_at  TIMESTAMP DEFAULT NOW()
    )
  `);

  console.log("✅ Database siap.");
}

// ─── BLACKLIST HELPERS ─────────────────────────────────────────────────────

async function isBlacklisted(userId) {
  const result = await pool.query(
    "SELECT user_id FROM blocked_users WHERE user_id = $1",
    [userId]
  );
  return result.rows.length > 0;
}

async function banUser(targetId, adminId, reason) {
  // Admin tidak bisa di-ban
  if (ADMIN_IDS.includes(targetId)) return "is_admin";

  await pool.query(
    `INSERT INTO blocked_users (user_id, reason, banned_by)
     VALUES ($1, $2, $3)
     ON CONFLICT (user_id) DO UPDATE
       SET reason    = EXCLUDED.reason,
           banned_by = EXCLUDED.banned_by,
           banned_at = NOW()`,
    [targetId, reason || "Tidak ada alasan", adminId]
  );
  return "banned";
}

async function unbanUser(targetId) {
  const result = await pool.query(
    "DELETE FROM blocked_users WHERE user_id = $1 RETURNING user_id",
    [targetId]
  );
  return result.rows.length > 0 ? "unbanned" : "not_found";
}

async function getBanInfo(targetId) {
  const result = await pool.query(
    "SELECT reason, banned_by, banned_at FROM blocked_users WHERE user_id = $1",
    [targetId]
  );
  return result.rows[0] || null;
}

async function getBanList() {
  const result = await pool.query(
    "SELECT user_id, reason, banned_at FROM blocked_users ORDER BY banned_at DESC LIMIT 20"
  );
  return result.rows;
}

// ─── TITLE HELPERS ─────────────────────────────────────────────────────────

async function setLinkTitle(code, title) {
  const result = await pool.query(
    "UPDATE links SET title = $1 WHERE code = $2 RETURNING code",
    [title.trim(), code]
  );
  return result.rows.length > 0 ? "ok" : "not_found";
}

async function getLinkTitle(code) {
  const result = await pool.query(
    "SELECT title FROM links WHERE code = $1",
    [code]
  );
  return result.rows[0]?.title || null;
}

// ─── EDIT LINK HELPERS ─────────────────────────────────────────────────────

// Cek apakah user boleh mengedit link (owner atau admin)
async function canEditLink(code, userId) {
  const result = await pool.query(
    "SELECT owner_id FROM links WHERE code = $1",
    [code]
  );
  if (result.rows.length === 0) return "not_found";
  const isAdmin = ADMIN_IDS.includes(userId);
  const isOwner = result.rows[0].owner_id === userId;
  if (!isAdmin && !isOwner) return "forbidden";
  return "ok";
}

// Ambil data link mentah (tanpa cek expiry) untuk keperluan edit
async function getRawLink(code) {
  const result = await pool.query(
    "SELECT data, type, owner_id, expires_at FROM links WHERE code = $1",
    [code]
  );
  if (result.rows.length === 0) return null;
  return result.rows[0];
}

// Tambah file ke link — jika single jadi multi, jika multi append
async function addFileToLink(code, newStoredId) {
  const raw = await getRawLink(code);
  if (!raw) return "not_found";

  let ids = [];
  if (raw.type === "single") {
    ids = [raw.data.id, newStoredId];
  } else {
    ids = [...raw.data.ids, newStoredId];
  }

  const newData = { type: "multi", ids };
  await pool.query(
    "UPDATE links SET type = $1, data = $2 WHERE code = $3",
    ["multi", JSON.stringify(newData), code]
  );
  return ids.length;
}

// Hapus beberapa file sekaligus dari link berdasarkan nomor urut (1-based)
// indexes = array of number, misal [1, 3]
async function removeFileFromLink(code, indexes) {
  const raw = await getRawLink(code);
  if (!raw) return { status: "not_found" };

  let ids = raw.type === "single" ? [raw.data.id] : [...raw.data.ids];

  // Validasi semua index
  const invalid = indexes.filter(i => i < 1 || i > ids.length);
  if (invalid.length > 0) {
    return { status: "out_of_range", total: ids.length, invalid };
  }

  // Cek apakah akan jadi kosong
  if (indexes.length >= ids.length) {
    return { status: "empty" };
  }

  // Hapus dari belakang agar index tidak bergeser
  const sortedDesc = [...new Set(indexes)].sort((a, b) => b - a);
  sortedDesc.forEach(i => ids.splice(i - 1, 1));

  let newType, newData;
  if (ids.length === 1) {
    newType = "single";
    newData = { type: "single", id: ids[0] };
  } else {
    newType = "multi";
    newData = { type: "multi", ids };
  }

  await pool.query(
    "UPDATE links SET type = $1, data = $2 WHERE code = $3",
    [newType, JSON.stringify(newData), code]
  );

  return { status: "ok", remaining: ids.length, removed: indexes.length };
}

async function saveLink(data, ownerId, title = null) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
  let code;
  let exists = true;

  while (exists) {
    const length = Math.floor(Math.random() * 3) + 6;
    code = Array.from({ length }, () =>
      chars[Math.floor(Math.random() * chars.length)]
    ).join("");
    const result = await pool.query("SELECT code FROM links WHERE code = $1", [code]);
    exists = result.rows.length > 0;
  }

  const expireDays = parseInt(process.env.LINK_EXPIRE_DAYS) || 0;
  const expiresAt = expireDays > 0
    ? new Date(Date.now() + expireDays * 24 * 60 * 60 * 1000)
    : null;

  await pool.query(
    "INSERT INTO links (code, type, data, owner_id, expires_at, title) VALUES ($1, $2, $3, $4, $5, $6)",
    [code, data.type, JSON.stringify(data), ownerId || null, expiresAt, title || null]
  );

  return code;
}

async function getLink(code) {
  const result = await pool.query(
    "SELECT data, expires_at, download_count FROM links WHERE code = $1",
    [code]
  );
  if (result.rows.length === 0) return null;

  const row = result.rows[0];

  if (row.expires_at && new Date() > new Date(row.expires_at)) {
    return { expired: true };
  }

  return { ...row.data, download_count: row.download_count };
}

async function incrementDownload(code) {
  await pool.query(
    "UPDATE links SET download_count = download_count + 1 WHERE code = $1",
    [code]
  );
}

async function deleteLink(code, ownerId) {
  const result = await pool.query(
    "SELECT owner_id FROM links WHERE code = $1",
    [code]
  );
  if (result.rows.length === 0) return "not_found";

  const isAdmin = ADMIN_IDS.includes(ownerId);
  if (result.rows[0].owner_id !== ownerId && !isAdmin) return "forbidden";

  await pool.query("DELETE FROM links WHERE code = $1", [code]);
  return "deleted";
}

async function getStats(userId) {
  const isAdmin = ADMIN_IDS.includes(userId);

  if (isAdmin) {
    const total   = await pool.query("SELECT COUNT(*) FROM links");
    const totalDl = await pool.query("SELECT COALESCE(SUM(download_count), 0) as total FROM links");
    const today   = await pool.query(
      "SELECT COUNT(*) FROM links WHERE created_at >= NOW() - INTERVAL '1 day'"
    );
    return {
      type:           "admin",
      totalLinks:     parseInt(total.rows[0].count),
      totalDownloads: parseInt(totalDl.rows[0].total),
      todayLinks:     parseInt(today.rows[0].count),
    };
  } else {
    const result  = await pool.query(
      "SELECT code, type, title, download_count, created_at, expires_at FROM links WHERE owner_id = $1 ORDER BY created_at DESC LIMIT 10",
      [userId]
    );
    const totalDl = await pool.query(
      "SELECT COALESCE(SUM(download_count), 0) as total FROM links WHERE owner_id = $1",
      [userId]
    );
    return {
      type:           "user",
      links:          result.rows,
      totalDownloads: parseInt(totalDl.rows[0].total),
    };
  }
}

// ─── CONFIG ────────────────────────────────────────────────────────────────
const BOT_TOKEN          = process.env.BOT_TOKEN;
const STORAGE_CHANNEL_ID = process.env.STORAGE_CHANNEL_ID;
const BOT_USERNAME       = process.env.BOT_USERNAME;
const AD_URL             = process.env.AD_URL || "https://your-ad-link.com";
const WEBAPP_URL         = process.env.WEBAPP_URL || "";
const LANDING_URL        = process.env.LANDING_URL || "";
const WEBAPP_BACKEND_URL = process.env.WEBAPP_BACKEND_URL || "";
const WHITELIST_USERS    = process.env.WHITELIST_USERS
  ? process.env.WHITELIST_USERS.split(",").map((id) => parseInt(id.trim()))
  : [];
const ADMIN_IDS          = process.env.ADMIN_IDS
  ? process.env.ADMIN_IDS.split(",").map((id) => parseInt(id.trim()))
  : [];

const AD_WAIT_SECONDS = parseInt(process.env.AD_WAIT_SECONDS) || 20;
const PORT            = parseInt(process.env.PORT) || 3000;

if (!BOT_TOKEN || !STORAGE_CHANNEL_ID || !BOT_USERNAME) {
  console.error("❌ ERROR: BOT_TOKEN, STORAGE_CHANNEL_ID, dan BOT_USERNAME wajib diisi di .env");
  process.exit(1);
}

if (!WEBAPP_URL || !WEBAPP_BACKEND_URL) {
  console.warn("⚠️  PERINGATAN: WEBAPP_URL atau WEBAPP_BACKEND_URL belum diisi — fitur WebApp tidak akan berfungsi!");
}

// ─── VALIDASI initData TELEGRAM WEBAPP ────────────────────────────────────
// Dipindah ke sini agar BOT_TOKEN sudah terdefinisi saat fungsi dieksekusi.
// Dokumen resmi: https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app

function verifyTelegramInitData(initData) {
  try {
    if (!initData || typeof initData !== "string") return null;

    const params   = new URLSearchParams(initData);
    const hash     = params.get("hash");
    const authDate = parseInt(params.get("auth_date") || "0");

    if (!hash || !authDate) return null;

    // Tolak initData yang sudah lebih dari 1 jam (3600 detik)
    const MAX_AGE_SECONDS = 3600;
    const ageSecs         = Math.floor(Date.now() / 1000) - authDate;
    if (ageSecs > MAX_AGE_SECONDS) {
      console.warn(`[INITDATA] Kedaluarsa — usia: ${ageSecs}s`);
      return null;
    }

    // Susun data-check-string: semua field kecuali hash, urut alfabet, pisah \n
    params.delete("hash");
    const dataCheckString = Array.from(params.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}=${v}`)
      .join("\n");

    // Secret key = HMAC-SHA256("WebAppData", BOT_TOKEN)
    const secretKey = crypto
      .createHmac("sha256", "WebAppData")
      .update(BOT_TOKEN)
      .digest();

    const expectedHash = crypto
      .createHmac("sha256", secretKey)
      .update(dataCheckString)
      .digest("hex");

    if (expectedHash !== hash) {
      console.warn("[INITDATA] Hash tidak cocok — kemungkinan data dipalsukan");
      return null;
    }

    const userRaw = params.get("user");
    if (!userRaw) return null;

    return JSON.parse(userRaw); // { id, first_name, username, ... }

  } catch (err) {
    console.error("[INITDATA] Error validasi:", err.message);
    return null;
  }
}

function requireValidInitData(req, res, next) {
  const initData = req.body?.init_data || req.body?.initData || "";

  if (!initData) {
    console.warn(`[INITDATA] Tidak ada initData dari IP: ${
      req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket?.remoteAddress
    } — fallback ke user_id body`);
    return next();
  }

  const user = verifyTelegramInitData(initData);
  if (!user) {
    return res.status(403).json({
      ok:    false,
      error: "Data autentikasi Telegram tidak valid atau kedaluarsa. Buka ulang WebApp dari bot.",
    });
  }

  req.telegramUser   = user;
  req.verifiedUserId = user.id;
  console.log(`[INITDATA] Valid — user: ${user.id} (@${user.username || "-"})`);
  next();
}

// ─── BOT INIT dengan auto-retry saat 409 Conflict ─────────────────────────
// Railway rolling deploy menyebabkan 2 container jalan bersamaan sementara.
// Solusi: mulai polling: false dulu, lalu panggil startPolling() di initDB.
const bot = new TelegramBot(BOT_TOKEN, { polling: false });

let isPolling = false;

async function startPolling() {
  if (isPolling) return;
  try {
    // Bersihkan pending updates sebelum mulai
    await bot.getUpdates({ offset: -1, limit: 1, timeout: 0 });
    await bot.startPolling({ restart: false });
    isPolling = true;
    console.log("✅ Bot polling aktif.");
  } catch (err) {
    console.error("⚠️  Polling gagal, retry 5 detik lagi:", err.message);
    isPolling = false;
    setTimeout(startPolling, 5000);
  }
}

// ─── IN-MEMORY STORE ───────────────────────────────────────────────────────
const multiMode = new Map();
// editMode menyimpan state sementara saat user sedang dalam sesi edit
// Map<userId, { action: "replace"|"add", code: string }>
const editMode = new Map();

// ─── TIMEOUT HELPER untuk multiMode & editMode ────────────────────────────
// Sesi yang tidak selesai dalam 30 menit otomatis dibatalkan
// agar Map tidak menumpuk di memory selamanya
const SESSION_TIMEOUT_MS = 30 * 60 * 1000; // 30 menit

function setMultiModeWithTimeout(userId, chatId, data) {
  // Hapus timeout lama jika ada
  if (multiMode.has(userId) && multiMode.get(userId)._timeout) {
    clearTimeout(multiMode.get(userId)._timeout);
  }
  const timeout = setTimeout(async () => {
    if (multiMode.has(userId)) {
      multiMode.delete(userId);
      try {
        await bot.sendMessage(
          chatId,
          "⏰ Sesi multi file otomatis dibatalkan karena tidak ada aktivitas selama 30 menit."
        );
      } catch (_) {}
    }
  }, SESSION_TIMEOUT_MS);
  multiMode.set(userId, { ...data, _timeout: timeout });
}

function setEditModeWithTimeout(userId, chatId, data) {
  if (editMode.has(userId) && editMode.get(userId)._timeout) {
    clearTimeout(editMode.get(userId)._timeout);
  }
  const timeout = setTimeout(async () => {
    if (editMode.has(userId)) {
      editMode.delete(userId);
      try {
        await bot.sendMessage(
          chatId,
          "⏰ Sesi edit otomatis dibatalkan karena tidak ada aktivitas selama 30 menit."
        );
      } catch (_) {}
    }
  }, SESSION_TIMEOUT_MS);
  editMode.set(userId, { ...data, _timeout: timeout });
}

function deleteMultiMode(userId) {
  if (multiMode.has(userId)) {
    const s = multiMode.get(userId);
    if (s._timeout) clearTimeout(s._timeout);
    multiMode.delete(userId);
  }
}

function deleteEditMode(userId) {
  if (editMode.has(userId)) {
    const s = editMode.get(userId);
    if (s._timeout) clearTimeout(s._timeout);
    editMode.delete(userId);
  }
}

// ─── HELPER ────────────────────────────────────────────────────────────────
function isAllowed(userId) {
  if (WHITELIST_USERS.length === 0) return true;
  return WHITELIST_USERS.includes(userId) || ADMIN_IDS.includes(userId);
}

function makeShareLink(code) {
  if (LANDING_URL) {
    return `${LANDING_URL.replace(/\/+$/, '')}/${code}`;
  }
  return `https://t.me/${BOT_USERNAME}?start=${code}`;
}

function getMediaType(msg) {
  if (msg.photo)      return "photo";
  if (msg.video)      return "video";
  if (msg.document)   return "document";
  if (msg.audio)      return "audio";
  if (msg.voice)      return "voice";
  if (msg.video_note) return "video_note";
  if (msg.animation)  return "animation";
  return null;
}

async function forwardToStorage(fromChatId, messageId) {
  const forwarded = await bot.forwardMessage(STORAGE_CHANNEL_ID, fromChatId, messageId);
  return forwarded.message_id;
}

async function sendFromStorage(chatId, storedMessageId) {
  await bot.copyMessage(chatId, STORAGE_CHANNEL_ID, storedMessageId, {
    protect_content: true,
  });
}

function formatExpiry(expiresAt) {
  if (!expiresAt) return "♾️ Tidak ada";
  const diff = new Date(expiresAt) - new Date();
  if (diff <= 0) return "⛔ Sudah expired";
  const days  = Math.floor(diff / (1000 * 60 * 60 * 24));
  const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
  if (days > 0) return `⏳ ${days} hari ${hours} jam lagi`;
  return `⏳ ${hours} jam lagi`;
}

// ─── FIX: Helper buat session baru ─────────────────────────────────────────
// Dipanggil setiap kali user buka /start dengan code
// Selalu insert baru — tidak pakai ON CONFLICT agar tidak miss
async function createSession(code, userId) {
  try {
    await pool.query(
      `INSERT INTO ad_sessions (code, user_id, verified, expires_at)
       VALUES ($1, $2, FALSE, NOW() + INTERVAL '30 minutes')`,
      [code, userId]
    );
    console.log(`[SESSION] Dibuat — user: ${userId}, code: ${code}`);
    return true;
  } catch (err) {
    console.error(`[SESSION] Gagal buat session: ${err.message}`);
    return false;
  }
}

// ─── HTTP: /botinfo ────────────────────────────────────────────────────────
app.get("/botinfo", (req, res) => {
  res.json({
    username:    BOT_USERNAME,
    wait:        AD_WAIT_SECONDS,
    ad_url:      AD_URL,
    webapp_url:  WEBAPP_URL,
    backend_url: WEBAPP_BACKEND_URL,
  });
});

// ─── HTTP: /claim ──────────────────────────────────────────────────────────
// [TITIK 1] Rate limit: max 5 request per menit per user
// [VALIDASI] initData Telegram diverifikasi HMAC-SHA256 sebelum masuk handler
app.post("/claim", httpLimiter("claim", 5, 60), requireValidInitData, async (req, res) => {
  const { code, user_id } = req.body;

  if (!code || !user_id) {
    return res.json({ ok: false, error: "Parameter tidak lengkap." });
  }

  // Jika initData valid → pakai userId terverifikasi dari Telegram
  // Jika tidak ada initData (fallback) → pakai user_id dari body
  const userId = req.verifiedUserId || parseInt(user_id);

  // Cek blacklist sebelum proses apapun
  if (await isBlacklisted(userId)) {
    console.warn(`[CLAIM] Ditolak — user ${userId} ada di blacklist`);
    return res.json({ ok: false, error: "Akun kamu telah diblokir dari bot ini." });
  }

  try {
    // Ambil session terbaru yang belum verified dan belum expired
    const sessionResult = await pool.query(
      `SELECT id FROM ad_sessions
       WHERE code = $1
         AND user_id = $2
         AND verified = FALSE
         AND expires_at > NOW()
       ORDER BY created_at DESC
       LIMIT 1`,
      [code, userId]
    );

    if (sessionResult.rows.length === 0) {
      // Cek apakah sudah pernah verified (sudah diambil)
      const verifiedCheck = await pool.query(
        `SELECT id FROM ad_sessions
         WHERE code = $1 AND user_id = $2 AND verified = TRUE
         LIMIT 1`,
        [code, userId]
      );

      if (verifiedCheck.rows.length > 0) {
        return res.json({ ok: false, error: "File sudah pernah diambil. Gunakan link baru jika perlu." });
      }

      return res.json({ ok: false, error: "Session tidak ditemukan atau kadaluarsa. Silakan buka ulang link dari awal." });
    }

    // Tandai session verified
    await pool.query(
      `UPDATE ad_sessions SET verified = TRUE WHERE id = $1`,
      [sessionResult.rows[0].id]
    );

    // Ambil data link
    const linkData = await getLink(code);
    if (!linkData) {
      return res.json({ ok: false, error: "Link tidak ditemukan." });
    }
    if (linkData.expired) {
      return res.json({ ok: false, error: "Link sudah kadaluarsa." });
    }

    // Kirim file ke user
    if (linkData.type === "multi") {
      for (const id of linkData.ids) {
        await sendFromStorage(userId, id);
      }
    } else {
      await sendFromStorage(userId, linkData.id);
    }

    await incrementDownload(code);
    console.log(`[CLAIM] Berhasil — user: ${userId}, code: ${code}`);

    return res.json({ ok: true });
  } catch (err) {
    console.error("[CLAIM] Error:", err.message);
    return res.json({ ok: false, error: "Terjadi kesalahan server. Coba lagi." });
  }
});

// ─── HTTP: /session ────────────────────────────────────────────────────────
// Dipanggil oleh landing page sebelum redirect ke bot
// [TITIK 2] Rate limit: max 10 request per menit per user
app.post("/session", httpLimiter("session", 10, 60), async (req, res) => {
  const { code, user_id } = req.body;

  if (!code || !user_id) {
    return res.json({ ok: false, error: "Parameter tidak lengkap." });
  }

  const userId = parseInt(user_id);

  try {
    const linkData = await getLink(code);

    if (!linkData) {
      return res.json({ ok: false, error: "Link tidak ditemukan." });
    }

    if (linkData.expired) {
      return res.json({ ok: false, error: "Link sudah kadaluarsa." });
    }

    const ok = await createSession(code, userId);
    return res.json({ ok });
  } catch (err) {
    console.error("[SESSION] Error:", err.message);
    return res.json({ ok: false, error: "Terjadi kesalahan server." });
  }
});

// ─── HTTP: /linkinfo ───────────────────────────────────────────────────────
app.get("/linkinfo", async (req, res) => {
  const { code } = req.query;

  if (!code) {
    return res.json({ ok: false, error: "Parameter tidak lengkap." });
  }

  try {
    const linkData = await getLink(code);

    if (!linkData) {
      return res.json({ ok: false, error: "Link tidak ditemukan." });
    }

    if (linkData.expired) {
      return res.json({ ok: false, expired: true, error: "Link sudah kadaluarsa." });
    }

    const fileCount = linkData.type === "multi" ? linkData.ids.length : 1;
    const title     = await getLinkTitle(code);

    return res.json({ ok: true, fileCount, type: linkData.type, title: title || "", views: linkData.download_count || 0 });
  } catch (err) {
    console.error("[LINKINFO] Error:", err.message);
    return res.json({ ok: false, error: "Terjadi kesalahan server." });
  }
});

// Health check
app.get("/", (req, res) => res.json({ status: "ok", bot: BOT_USERNAME }));

// ─── HTTP: /dashboard/summary ──────────────────────────────────────────────
// Ringkasan global (admin) atau milik sendiri (whitelist user)
// Query param: user_id (wajib), init_data (opsional untuk verifikasi)
app.get("/dashboard/summary", async (req, res) => {
  const userId = parseInt(req.query.user_id);
  if (!userId) return res.json({ ok: false, error: "Parameter user_id tidak lengkap." });

  const isAdmin    = ADMIN_IDS.includes(userId);
  const isWhitelist = WHITELIST_USERS.includes(userId);
  if (!isAdmin && !isWhitelist) {
    return res.status(403).json({ ok: false, error: "Akses ditolak." });
  }

  try {
    if (isAdmin) {
      const totalLinks = await pool.query("SELECT COUNT(*) FROM links");
      const totalViews = await pool.query("SELECT COALESCE(SUM(download_count),0) as total FROM links");
      const totalBanned = await pool.query("SELECT COUNT(*) FROM blocked_users");
      return res.json({
        ok: true,
        role: "admin",
        totalLinks:  parseInt(totalLinks.rows[0].count),
        totalViews:  parseInt(totalViews.rows[0].total),
        totalBanned: parseInt(totalBanned.rows[0].count),
      });
    } else {
      const totalLinks = await pool.query(
        "SELECT COUNT(*) FROM links WHERE owner_id = $1", [userId]
      );
      const totalViews = await pool.query(
        "SELECT COALESCE(SUM(download_count),0) as total FROM links WHERE owner_id = $1", [userId]
      );
      return res.json({
        ok: true,
        role: "user",
        totalLinks: parseInt(totalLinks.rows[0].count),
        totalViews: parseInt(totalViews.rows[0].total),
      });
    }
  } catch (err) {
    console.error("[DASHBOARD/SUMMARY] Error:", err.message);
    return res.json({ ok: false, error: "Terjadi kesalahan server." });
  }
});

// ─── HTTP: /dashboard/chart ────────────────────────────────────────────────
// Statistik views per hari dalam rentang tanggal
// Query param: user_id, date_from (YYYY-MM-DD), date_to (YYYY-MM-DD)
// Cara kerja: hitung dari ad_sessions yang verified=TRUE dalam rentang
app.get("/dashboard/chart", async (req, res) => {
  const userId   = parseInt(req.query.user_id);
  const dateFrom = req.query.date_from;
  const dateTo   = req.query.date_to;

  if (!userId || !dateFrom || !dateTo) {
    return res.json({ ok: false, error: "Parameter tidak lengkap." });
  }

  const isAdmin     = ADMIN_IDS.includes(userId);
  const isWhitelist = WHITELIST_USERS.includes(userId);
  if (!isAdmin && !isWhitelist) {
    return res.status(403).json({ ok: false, error: "Akses ditolak." });
  }

  try {
    let rows;
    if (isAdmin) {
      // Admin: semua claim dalam rentang
      const result = await pool.query(
        `SELECT DATE(created_at) as date, COUNT(*) as views
         FROM ad_sessions
         WHERE verified = TRUE
           AND DATE(created_at) >= $1
           AND DATE(created_at) <= $2
         GROUP BY DATE(created_at)
         ORDER BY date ASC`,
        [dateFrom, dateTo]
      );
      rows = result.rows;
    } else {
      // Whitelist: hanya claim pada link milik user ini
      const result = await pool.query(
        `SELECT DATE(s.created_at) as date, COUNT(*) as views
         FROM ad_sessions s
         JOIN links l ON l.code = s.code
         WHERE s.verified = TRUE
           AND l.owner_id = $1
           AND DATE(s.created_at) >= $2
           AND DATE(s.created_at) <= $3
         GROUP BY DATE(s.created_at)
         ORDER BY date ASC`,
        [userId, dateFrom, dateTo]
      );
      rows = result.rows;
    }

    return res.json({
      ok: true,
      data: rows.map(r => ({ date: r.date, views: parseInt(r.views) })),
    });
  } catch (err) {
    console.error("[DASHBOARD/CHART] Error:", err.message);
    return res.json({ ok: false, error: "Terjadi kesalahan server." });
  }
});

// ─── HTTP: /dashboard/links ────────────────────────────────────────────────
// Daftar link dengan performa — admin lihat semua, whitelist lihat milik sendiri
// Query param: user_id, page (default 1), limit (default 10), search (opsional)
app.get("/dashboard/links", async (req, res) => {
  const userId = parseInt(req.query.user_id);
  const page   = Math.max(1, parseInt(req.query.page)  || 1);
  const limit  = Math.min(50, parseInt(req.query.limit) || 10);
  const offset = (page - 1) * limit;
  const search = req.query.search?.trim() || "";
  const sort   = req.query.sort === "newest" ? "newest" : "popular";

  if (!userId) return res.json({ ok: false, error: "Parameter user_id tidak lengkap." });

  const isAdmin     = ADMIN_IDS.includes(userId);
  const isWhitelist = WHITELIST_USERS.includes(userId);
  if (!isAdmin && !isWhitelist) {
    return res.status(403).json({ ok: false, error: "Akses ditolak." });
  }

  try {
    const conditions = [];
    const values     = [];

    if (!isAdmin) {
      values.push(userId);
      conditions.push(`owner_id = $${values.length}`);
    }

    if (search) {
      values.push(`%${search}%`);
      const idx = values.length;
      conditions.push(`(title ILIKE $${idx} OR code ILIKE $${idx})`);
    }

    const whereClause = conditions.length > 0
      ? `WHERE ${conditions.join(" AND ")}`
      : "";

    // Order berdasarkan sort mode
    const orderClause = sort === "newest"
      ? "ORDER BY created_at DESC"
      : "ORDER BY download_count DESC, created_at DESC";

    const dataValues = [...values, limit, offset];
    const result = await pool.query(
      `SELECT code, type, title, download_count, created_at, expires_at, owner_id
       FROM links
       ${whereClause}
       ${orderClause}
       LIMIT $${dataValues.length - 1} OFFSET $${dataValues.length}`,
      dataValues
    );

    const countResult = await pool.query(
      `SELECT COUNT(*) FROM links ${whereClause}`,
      values
    );

    return res.json({
      ok:    true,
      total: parseInt(countResult.rows[0].count),
      page,
      limit,
      sort,
      search,
      links: result.rows.map(r => ({
        code:           r.code,
        type:           r.type,
        title:          r.title || "",
        download_count: r.download_count,
        created_at:     r.created_at,
        expires_at:     r.expires_at,
        owner_id:       r.owner_id,
      })),
    });
  } catch (err) {
    console.error("[DASHBOARD/LINKS] Error:", err.message);
    return res.json({ ok: false, error: "Terjadi kesalahan server." });
  }
});

// ─── HTTP: /dashboard/link-chart ──────────────────────────────────────────
// Statistik views per hari untuk satu link spesifik
// Query param: user_id, code, date_from, date_to
app.get("/dashboard/link-chart", async (req, res) => {
  const userId   = parseInt(req.query.user_id);
  const code     = req.query.code;
  const dateFrom = req.query.date_from;
  const dateTo   = req.query.date_to;

  if (!userId || !code || !dateFrom || !dateTo) {
    return res.json({ ok: false, error: "Parameter tidak lengkap." });
  }

  const isAdmin     = ADMIN_IDS.includes(userId);
  const isWhitelist = WHITELIST_USERS.includes(userId);
  if (!isAdmin && !isWhitelist) {
    return res.status(403).json({ ok: false, error: "Akses ditolak." });
  }

  try {
    // Verifikasi kepemilikan jika bukan admin
    if (!isAdmin) {
      const ownerCheck = await pool.query(
        "SELECT owner_id FROM links WHERE code = $1", [code]
      );
      if (ownerCheck.rows.length === 0) {
        return res.json({ ok: false, error: "Link tidak ditemukan." });
      }
      if (Number(ownerCheck.rows[0].owner_id) !== Number(userId)) {
        return res.status(403).json({ ok: false, error: "Akses ditolak." });
      }
    }

    const result = await pool.query(
      `SELECT DATE(created_at) as date, COUNT(*) as views
       FROM ad_sessions
       WHERE code = $1
         AND verified = TRUE
         AND DATE(created_at) >= $2
         AND DATE(created_at) <= $3
       GROUP BY DATE(created_at)
       ORDER BY date ASC`,
      [code, dateFrom, dateTo]
    );

    // Ambil info link
    const linkInfo = await pool.query(
      "SELECT title, download_count, type FROM links WHERE code = $1", [code]
    );

    return res.json({
      ok:    true,
      code,
      title: linkInfo.rows[0]?.title || "",
      totalViews: linkInfo.rows[0]?.download_count || 0,
      type:  linkInfo.rows[0]?.type || "single",
      data:  result.rows.map(r => ({ date: r.date, views: parseInt(r.views) })),
    });
  } catch (err) {
    console.error("[DASHBOARD/LINK-CHART] Error:", err.message);
    return res.json({ ok: false, error: "Terjadi kesalahan server." });
  }
});

// ─── /start ────────────────────────────────────────────────────────────────
bot.onText(/\/start(?:\s+(\S+))?/, async (msg, match) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;
  const param  = match[1];

  // Cek blacklist — admin tidak pernah diblokir
  if (!ADMIN_IDS.includes(userId) && await isBlacklisted(userId)) {
    return bot.sendMessage(chatId, "⛔ Akun kamu telah diblokir dari bot ini.");
  }

  if (param) {
    const linkData = await getLink(param);

    if (!linkData) {
      return bot.sendMessage(chatId, "❌ Link tidak valid atau tidak ditemukan.");
    }

    if (linkData.expired) {
      return bot.sendMessage(
        chatId,
        "⛔ *Link sudah kadaluarsa!*\n\nMinta link baru kepada pengirim.",
        { parse_mode: "Markdown" }
      );
    }

    const fileCount = linkData.type === "multi" ? linkData.ids.length : 1;
    const fileLabel = fileCount > 1 ? `${fileCount} file` : "1 file";

    // Ambil judul link
    const linkTitle = await getLinkTitle(param);

    // FIX: Selalu buat session baru setiap /start dengan code
    await createSession(param, userId);

    // Pastikan semua env var lengkap sebelum buat WebApp URL
    if (!WEBAPP_URL || !WEBAPP_BACKEND_URL) {
      return bot.sendMessage(
        chatId,
        "❌ Konfigurasi bot belum lengkap. Hubungi admin.",
        { parse_mode: "Markdown" }
      );
    }

    const titleLine = linkTitle ? `🏷️ *${linkTitle}*\n\n` : "";
    const webAppUrl = `${WEBAPP_URL}?code=${encodeURIComponent(param)}&uid=${userId}&wait=${AD_WAIT_SECONDS}&ad=${encodeURIComponent(AD_URL)}&backend=${encodeURIComponent(WEBAPP_BACKEND_URL)}&bot=${BOT_USERNAME}`;

    console.log(`[START] User ${userId} → code: ${param}`);
    console.log(`[START] WebApp URL: ${webAppUrl}`);

    return bot.sendMessage(
      chatId,
      `📦 *${fileLabel} siap diakses!*\n\n` +
      titleLine +
      `Klik tombol di bawah, iklan akan terbuka otomatis.\n` +
      `Tunggu timer selesai lalu klik *Ambil File*.\n\n` +
      `⚠️ _Proses ini tidak bisa dilewati._`,
      {
        parse_mode: "Markdown",
        reply_markup: {
          inline_keyboard: [[
            {
              text: "🎁 Buka & Ambil File",
              web_app: { url: webAppUrl }
            }
          ]]
        }
      }
    );
  }

  await bot.sendMessage(
    chatId,
    `👋 *Selamat datang di File Share Bot!*\n\n` +
    `📌 *Cara upload:*\n` +
    `• *1 file:* Kirim langsung ke bot\n` +
    `• *Multi file:* Ketik /multi → kirim file → /done\n\n` +
    `📌 *Media didukung:*\n` +
    `🖼 Foto · 🎬 Video · 📄 Dokumen · 🎵 Audio · 🎤 Voice · 🎞 GIF\n\n` +
    `📋 *Perintah lengkap:* /help`,
    { parse_mode: "Markdown" }
  );
});

// ─── /dashboard ────────────────────────────────────────────────────────────
bot.onText(/\/dashboard/, async (msg) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;

  const isAdmin     = ADMIN_IDS.includes(userId);
  const isWhitelist = WHITELIST_USERS.includes(userId);

  if (!isAdmin && !isWhitelist) {
    return bot.sendMessage(chatId, "⛔ Kamu tidak memiliki akses ke dashboard.");
  }

  if (!WEBAPP_URL || !WEBAPP_BACKEND_URL) {
    return bot.sendMessage(chatId, "❌ Konfigurasi bot belum lengkap. Hubungi admin.");
  }

  const dashboardUrl = `${WEBAPP_URL.replace("webappbot.html", "dashboard.html")}?uid=${userId}&backend=${encodeURIComponent(WEBAPP_BACKEND_URL)}`;

  await bot.sendMessage(
    chatId,
    `📊 *Dashboard Analytics*\n\nKlik tombol di bawah untuk membuka dashboard.`,
    {
      parse_mode: "Markdown",
      reply_markup: {
        inline_keyboard: [[{
          text: "📊 Buka Dashboard",
          web_app: { url: dashboardUrl }
        }]]
      }
    }
  );
});

// ─── /help ─────────────────────────────────────────────────────────────────
bot.onText(/\/help/, async (msg) => {
  const isAdmin = ADMIN_IDS.includes(msg.from.id);
  const canEdit = isAllowedToEdit(msg.from.id);

  const editSection = canEdit
    ? `\n*Perintah Edit Link:*\n` +
      `• /replace \\[code\\] — Ganti semua file dalam link\n` +
      `• /addfile \\[code\\] — Tambah file ke link\n` +
      `• /removefile \\[code\\] \\[no\\] — Hapus file ke\\-N dari link\n` +
      `• /linkdetail \\[code\\] — Detail isi link\n` +
      `• /canceledit — Batalkan sesi edit\n`
    : "";

  const adminSection = isAdmin
    ? `\n*Perintah Admin:*\n` +
      `• /ban \\[id\\] \\[alasan\\] — Blokir user\n` +
      `• /unban \\[id\\] — Buka blokir user\n` +
      `• /banlist — Daftar user diblokir\n` +
      `• /checkban \\[id\\] — Cek status ban user\n`
    : "";

  try {
    await bot.sendMessage(
      msg.chat.id,
      `📖 *Bantuan \\- File Share Bot*\n\n` +
      `*Perintah Upload:*\n` +
      `• /multi — Mulai mode multi file\n` +
      `• /done — Selesai & buat link\n` +
      `• /cancel — Batalkan mode multi\n\n` +
      `*Perintah Info:*\n` +
      `• /stats — Statistik link kamu\n` +
      `• /myid — Lihat User ID kamu\n` +
      `• /help — Bantuan ini\n` +
      `• /dashboard — Buka dashboard analytics\n\n` +
      `*Perintah Kelola Link:*\n` +
      `• /delete \\[code\\] — Hapus link\n` +
      `  _Contoh: /delete AbCd1234_\n` +
      `• /settitle \\[code\\] \\[judul\\] — Ubah judul link\n` +
      `  _Contoh: /settitle AbCd1234 Judul Baru_` +
      editSection +
      adminSection + `\n\n` +
      `*Cara buat link:*\n` +
      `1\\. Kirim file langsung → link otomatis\n` +
      `2\\. /multi → kirim beberapa file → /done`,
      { parse_mode: "MarkdownV2" }
    );
  } catch (err) {
    console.error("[HELP] Error:", err.message);
    // Fallback: kirim tanpa markdown jika ada karakter yang bermasalah
    await bot.sendMessage(
      msg.chat.id,
      `📖 Bantuan - File Share Bot\n\n` +
      `Upload: /multi /done /cancel\n` +
      `Info: /stats /myid /dashboard\n` +
      `Kelola: /delete /settitle /linkdetail\n` +
      `Edit: /replace /addfile /removefile /canceledit\n\n` +
      `Kirim file langsung untuk upload single file.`
    );
  }
});

// ─── /myid ─────────────────────────────────────────────────────────────────
bot.onText(/\/myid/, async (msg) => {
  const username = msg.from.username ? `@${msg.from.username}` : "tidak ada";
  await bot.sendMessage(
    msg.chat.id,
    `🪪 *Info Akun Kamu*\n\n` +
    `👤 Nama: ${msg.from.first_name}\n` +
    `🔖 Username: ${username}\n` +
    `🆔 User ID: \`${msg.from.id}\``,
    { parse_mode: "Markdown" }
  );
});

// ─── /stats ────────────────────────────────────────────────────────────────
bot.onText(/\/stats/, async (msg) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;

  try {
    const stats = await getStats(userId);

    if (stats.type === "admin") {
      await bot.sendMessage(
        chatId,
        `📊 *Statistik Global (Admin)*\n\n` +
        `🔗 Total link aktif: *${stats.totalLinks}*\n` +
        `⬇️ Total download: *${stats.totalDownloads}*\n` +
        `📅 Link dibuat hari ini: *${stats.todayLinks}*`,
        { parse_mode: "Markdown" }
      );
    } else {
      if (stats.links.length === 0) {
        return bot.sendMessage(chatId, "📂 Kamu belum membuat link apapun.");
      }

      let text = `📊 *Statistik Link Kamu*\n`;
      text += `⬇️ Total download: *${stats.totalDownloads}*\n\n`;
      text += `*10 link terbaru:*\n`;
      text += `━━━━━━━━━━━━━━━━\n`;

      stats.links.forEach((row, i) => {
        const shareLink = makeShareLink(row.code);
        const typeLabel = row.type === "multi" ? "📦 Multi" : "📄 Single";
        const titleLine = row.title ? `   🏷️ ${row.title}\n` : "";
        text += `*${i + 1}.* \`${row.code}\` ${typeLabel}\n`;
        text += titleLine;
        text += `   ⬇️ ${row.download_count}x · ${formatExpiry(row.expires_at)}\n`;
        text += `   🔗 ${shareLink}\n`;
        if (i < stats.links.length - 1) text += `\n`;
      });

      await bot.sendMessage(chatId, text, {
        parse_mode: "Markdown",
        disable_web_page_preview: true,
      });
    }
  } catch (err) {
    console.error("Stats error:", err.message);
    bot.sendMessage(chatId, "❌ Gagal mengambil statistik.");
  }
});

// ─── /delete ───────────────────────────────────────────────────────────────
bot.onText(/\/delete(?:\s+(\S+))?/, async (msg, match) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;
  const code   = match[1];

  // [TITIK 3] Rate limit: max 10 delete per menit per user
  const deleteLimit = checkBotLimit("delete", userId, 10, 60);
  if (!deleteLimit.ok) {
    return bot.sendMessage(
      chatId,
      `⏳ Terlalu banyak permintaan delete. Coba lagi dalam *${formatTimeLeft(deleteLimit.retryAfter)}*`,
      { parse_mode: "Markdown" }
    );
  }

  if (!code) {
    return bot.sendMessage(
      chatId,
      "⚠️ Sertakan kode link yang ingin dihapus.\n\n_Contoh:_ /delete AbCd1234",
      { parse_mode: "Markdown" }
    );
  }

  const result = await deleteLink(code, userId);

  const messages = {
    deleted:   `✅ Link \`${code}\` berhasil dihapus.`,
    not_found: `❌ Link \`${code}\` tidak ditemukan.`,
    forbidden: `⛔ Kamu tidak memiliki izin untuk menghapus link ini.`,
  };

  await bot.sendMessage(chatId, messages[result] || "❌ Terjadi kesalahan.", {
    parse_mode: "Markdown",
  });
});

// ─── HELPER: cek akses edit (admin atau whitelist) ─────────────────────────
function isAllowedToEdit(userId) {
  return ADMIN_IDS.includes(userId) || WHITELIST_USERS.includes(userId);
}

// ─── /replace [code] ───────────────────────────────────────────────────────
// Ganti semua file dalam link. Setelah command, user kirim file baru.
bot.onText(/\/replace(?:\s+(\S+))?/, async (msg, match) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;
  const code   = match[1];

  if (!isAllowedToEdit(userId)) {
    return bot.sendMessage(chatId, "⛔ Kamu tidak memiliki izin untuk fitur ini.");
  }

  if (!code) {
    return bot.sendMessage(
      chatId,
      "⚠️ Sertakan kode link.\n\n_Contoh:_ /replace AbCd1234",
      { parse_mode: "Markdown" }
    );
  }

  const access = await canEditLink(code, userId);
  if (access === "not_found") return bot.sendMessage(chatId, `❌ Link \`${code}\` tidak ditemukan.`, { parse_mode: "Markdown" });
  if (access === "forbidden")  return bot.sendMessage(chatId, "⛔ Kamu tidak memiliki izin untuk mengedit link ini.");

  // Simpan state edit
  setEditModeWithTimeout(userId, chatId, { action: "replace", code, storedIds: [], mediaGroups: new Map() });

  await bot.sendMessage(
    chatId,
    `🔄 *Mode Ganti File*\n\n` +
    `Link: \`${code}\`\n\n` +
    `Kirimkan file pengganti \\(boleh lebih dari 1 atau album\\)\\.\n` +
    `Ketik /done jika selesai\\.\n` +
    `Ketik /canceledit untuk membatalkan\\.`,
    { parse_mode: "MarkdownV2" }
  );
});

// ─── /addfile [code] ───────────────────────────────────────────────────────
// Tambah file ke link yang sudah ada.
bot.onText(/\/addfile(?:\s+(\S+))?/, async (msg, match) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;
  const code   = match[1];

  if (!isAllowedToEdit(userId)) {
    return bot.sendMessage(chatId, "⛔ Kamu tidak memiliki izin untuk fitur ini.");
  }

  if (!code) {
    return bot.sendMessage(
      chatId,
      "⚠️ Sertakan kode link.\n\n_Contoh:_ /addfile AbCd1234",
      { parse_mode: "Markdown" }
    );
  }

  const access = await canEditLink(code, userId);
  if (access === "not_found") return bot.sendMessage(chatId, `❌ Link \`${code}\` tidak ditemukan.`, { parse_mode: "Markdown" });
  if (access === "forbidden")  return bot.sendMessage(chatId, "⛔ Kamu tidak memiliki izin untuk mengedit link ini.");

  // Tampilkan isi link saat ini
  const raw = await getRawLink(code);
  const currentCount = raw.type === "single" ? 1 : raw.data.ids.length;

  setEditModeWithTimeout(userId, chatId, { action: "add", code, mediaGroups: new Map() });

  await bot.sendMessage(
    chatId,
    `➕ *Mode Tambah File*\n\n` +
    `Link: \`${code}\`\n` +
    `File saat ini: *${currentCount} file*\n\n` +
    `Kirimkan file yang ingin ditambahkan \\(boleh album\\)\\.\n` +
    `Ketik /done jika selesai\\.\n` +
    `Ketik /canceledit untuk membatalkan\\.`,
    { parse_mode: "MarkdownV2" }
  );
});

// ─── /removefile [code] [nomor...] ────────────────────────────────────────
// Hapus satu atau beberapa file dari link.
// Format: /removefile AbCd1234 2
//         /removefile AbCd1234 1 3
//         /removefile AbCd1234 1,3,5
bot.onText(/\/removefile(?:\s+(\S+))?(?:\s+(.+))?/, async (msg, match) => {
  const chatId    = msg.chat.id;
  const userId    = msg.from.id;
  const code      = match[1];
  const rawNomor  = match[2] || "";

  if (!isAllowedToEdit(userId)) {
    return bot.sendMessage(chatId, "⛔ Kamu tidak memiliki izin untuk fitur ini.");
  }

  if (!code) {
    return bot.sendMessage(
      chatId,
      "⚠️ Sertakan kode link dan nomor file.\n\n" +
      "_Contoh hapus 1 file:_ /removefile AbCd1234 2\n" +
      "_Contoh hapus beberapa:_ /removefile AbCd1234 1 3 5\n" +
      "_Atau dengan koma:_ /removefile AbCd1234 1,3,5",
      { parse_mode: "Markdown" }
    );
  }

  const access = await canEditLink(code, userId);
  if (access === "not_found") return bot.sendMessage(chatId, `❌ Link \`${code}\` tidak ditemukan.`, { parse_mode: "Markdown" });
  if (access === "forbidden")  return bot.sendMessage(chatId, "⛔ Kamu tidak memiliki izin untuk mengedit link ini.");

  const raw = await getRawLink(code);
  const ids  = raw.type === "single" ? [raw.data.id] : raw.data.ids;

  // Jika nomor tidak disertakan → tampilkan daftar file
  if (!rawNomor.trim()) {
    let text = `📋 *Daftar File di Link* \`${code}\`\n`;
    text += `━━━━━━━━━━━━━━━━\n`;
    ids.forEach((id, i) => {
      text += `*${i + 1}.* Message ID: \`${id}\`\n`;
    });
    text += `\nGunakan: /removefile ${code} [nomor]\n`;
    text += `_Bisa lebih dari satu, pisah spasi atau koma_\n`;
    text += `_Contoh: /removefile ${code} 1 3_`;
    return bot.sendMessage(chatId, text, { parse_mode: "Markdown" });
  }

  // Parse nomor: support spasi dan koma sebagai pemisah
  const indexes = rawNomor
    .split(/[\s,]+/)
    .map(s => parseInt(s.trim()))
    .filter(n => !isNaN(n));

  if (indexes.length === 0) {
    return bot.sendMessage(
      chatId,
      "⚠️ Nomor file tidak valid.\n\n_Contoh: /removefile AbCd1234 1 3_",
      { parse_mode: "Markdown" }
    );
  }

  // Duplikat tidak diproses dua kali
  const uniqueIndexes = [...new Set(indexes)];

  const result = await removeFileFromLink(code, uniqueIndexes);

  if (result.status === "not_found") {
    return bot.sendMessage(chatId, `❌ Link \`${code}\` tidak ditemukan.`, { parse_mode: "Markdown" });
  }

  if (result.status === "out_of_range") {
    return bot.sendMessage(
      chatId,
      `⚠️ Nomor tidak valid: *${result.invalid.join(", ")}*\n` +
      `Link ini hanya punya *${result.total} file* (nomor 1–${result.total}).\n\n` +
      `Gunakan /removefile ${code} untuk lihat daftar file.`,
      { parse_mode: "Markdown" }
    );
  }

  if (result.status === "empty") {
    return bot.sendMessage(
      chatId,
      `⚠️ Tidak bisa menghapus semua file — link akan jadi kosong.\n` +
      `Gunakan /delete \`${code}\` jika ingin menghapus link sepenuhnya.`,
      { parse_mode: "Markdown" }
    );
  }

  const nomorLabel = uniqueIndexes.length === 1
    ? `ke-${uniqueIndexes[0]}`
    : `ke-${uniqueIndexes.join(", ")}`;

  console.log(`[REMOVEFILE] File ${nomorLabel} dari link ${code} dihapus oleh user ${userId}`);

  await bot.sendMessage(
    chatId,
    `✅ *File ${nomorLabel} berhasil dihapus!*\n\n` +
    `Link: \`${code}\`\n` +
    `Dihapus: *${result.removed} file*\n` +
    `File tersisa: *${result.remaining} file*`,
    { parse_mode: "Markdown" }
  );
});

// ─── /canceledit ───────────────────────────────────────────────────────────
bot.onText(/\/canceledit/, async (msg) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;

  if (!editMode.has(userId)) {
    return bot.sendMessage(chatId, "⚠️ Tidak ada sesi edit yang aktif.");
  }

  deleteEditMode(userId);
  await bot.sendMessage(chatId, "❌ Sesi edit dibatalkan.");
});

// ─── /linkinfo [code] (bot command) ────────────────────────────────────────
// Tampilkan detail isi link: jumlah file, tipe, expiry, download count.
bot.onText(/\/linkdetail(?:\s+(\S+))?/, async (msg, match) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;
  const code   = match[1];

  if (!isAllowedToEdit(userId)) {
    return bot.sendMessage(chatId, "⛔ Kamu tidak memiliki izin untuk fitur ini.");
  }

  if (!code) {
    return bot.sendMessage(
      chatId,
      "⚠️ Sertakan kode link.\n\n_Contoh:_ /linkdetail AbCd1234",
      { parse_mode: "Markdown" }
    );
  }

  const raw = await getRawLink(code);
  if (!raw) return bot.sendMessage(chatId, `❌ Link \`${code}\` tidak ditemukan.`, { parse_mode: "Markdown" });

  const linkData = await getLink(code);
  const ids      = raw.type === "single" ? [raw.data.id] : raw.data.ids;
  const expired  = linkData?.expired ? "⛔ Sudah expired" : "✅ Aktif";
  const title    = await getLinkTitle(code);

  let text = `🔍 *Detail Link* \`${code}\`\n`;
  text += `━━━━━━━━━━━━━━━━\n`;
  if (title) text += `🏷️ Judul: *${title}*\n`;
  text += `📦 Tipe: ${raw.type === "single" ? "Single" : "Multi"}\n`;
  text += `📄 Jumlah file: *${ids.length}*\n`;
  text += `⬇️ Download: *${linkData?.download_count ?? 0}x*\n`;
  text += `🔴 Status: ${expired}\n`;
  text += `⏳ Expired: ${formatExpiry(linkData?.expires_at ?? null)}\n\n`;
  text += `*Daftar File:*\n`;
  ids.forEach((id, i) => {
    text += `  *${i + 1}.* Message ID \`${id}\`\n`;
  });
  text += `\n_Edit: /replace, /addfile, /removefile_`;
  if (title) text += `\n_Ubah judul: /settitle ${code} Judul Baru_`;

  await bot.sendMessage(chatId, text, { parse_mode: "Markdown" });
});

// ─── /settitle ─────────────────────────────────────────────────────────────
// Set/ubah judul link. Format: /settitle [code] [judul]
// Siapa saja pemilik link bisa pakai (bukan hanya admin).
bot.onText(/\/settitle(?:\s+(\S+))?(?:\s+(.+))?/, async (msg, match) => {
  const chatId  = msg.chat.id;
  const userId  = msg.from.id;
  const code    = match[1];
  const title   = match[2]?.trim();

  if (!code || !title) {
    return bot.sendMessage(
      chatId,
      `⚠️ Format: /settitle \\[code\\] \\[judul\\]\n\n` +
      `_Contoh:_ /settitle AbCd1234 Materi Belajar Python`,
      { parse_mode: "Markdown" }
    );
  }

  // Cek link ada & milik user (atau admin)
  const raw = await getRawLink(code);
  if (!raw) {
    return bot.sendMessage(chatId, `❌ Link \`${code}\` tidak ditemukan.`, { parse_mode: "Markdown" });
  }

  const isAdmin     = ADMIN_IDS.includes(userId);
  const isWhitelist = WHITELIST_USERS.includes(userId);
  if (raw.owner_id !== userId && !isAdmin && !isWhitelist) {
    return bot.sendMessage(chatId, "⛔ Kamu tidak memiliki izin untuk mengubah judul link ini.");
  }

  // Batasi panjang judul
  if (title.length > 100) {
    return bot.sendMessage(chatId, "⚠️ Judul terlalu panjang. Maksimal 100 karakter.");
  }

  const result = await setLinkTitle(code, title);
  if (result === "not_found") {
    return bot.sendMessage(chatId, `❌ Link \`${code}\` tidak ditemukan.`, { parse_mode: "Markdown" });
  }

  console.log(`[SETTITLE] Link ${code} → judul: "${title}" oleh user ${userId}`);

  await bot.sendMessage(
    chatId,
    `✅ *Judul berhasil diubah!*\n\n` +
    `🔑 Link: \`${code}\`\n` +
    `🏷️ Judul baru: *${title}*`,
    { parse_mode: "Markdown" }
  );
});

// ─── /ban ──────────────────────────────────────────────────────────────────
// Hanya admin. Format: /ban [user_id] [alasan opsional]
bot.onText(/\/ban(?:\s+(\d+))?(?:\s+(.+))?/, async (msg, match) => {
  const chatId   = msg.chat.id;
  const adminId  = msg.from.id;
  const targetId = match[1] ? parseInt(match[1]) : null;
  const reason   = match[2] || "Tidak ada alasan";

  if (!ADMIN_IDS.includes(adminId)) {
    return bot.sendMessage(chatId, "⛔ Perintah ini hanya untuk admin.");
  }

  if (!targetId) {
    return bot.sendMessage(
      chatId,
      "⚠️ Sertakan User ID yang ingin diblokir.\n\n_Contoh:_ /ban 123456789 spam",
      { parse_mode: "Markdown" }
    );
  }

  if (targetId === adminId) {
    return bot.sendMessage(chatId, "⚠️ Kamu tidak bisa memblokir diri sendiri.");
  }

  const result = await banUser(targetId, adminId, reason);

  if (result === "is_admin") {
    return bot.sendMessage(chatId, "⛔ Admin tidak bisa diblokir.");
  }

  console.log(`[BAN] User ${targetId} diblokir oleh admin ${adminId} — alasan: ${reason}`);

  await bot.sendMessage(
    chatId,
    `🚫 *User Diblokir*\n\n` +
    `🆔 User ID: \`${targetId}\`\n` +
    `📝 Alasan: ${reason}\n` +
    `👮 Oleh: \`${adminId}\``,
    { parse_mode: "Markdown" }
  );
});

// ─── /unban ────────────────────────────────────────────────────────────────
// Hanya admin. Format: /unban [user_id]
bot.onText(/\/unban(?:\s+(\d+))?/, async (msg, match) => {
  const chatId   = msg.chat.id;
  const adminId  = msg.from.id;
  const targetId = match[1] ? parseInt(match[1]) : null;

  if (!ADMIN_IDS.includes(adminId)) {
    return bot.sendMessage(chatId, "⛔ Perintah ini hanya untuk admin.");
  }

  if (!targetId) {
    return bot.sendMessage(
      chatId,
      "⚠️ Sertakan User ID yang ingin dibuka blokirnya.\n\n_Contoh:_ /unban 123456789",
      { parse_mode: "Markdown" }
    );
  }

  const result = await unbanUser(targetId);

  if (result === "not_found") {
    return bot.sendMessage(
      chatId,
      `ℹ️ User \`${targetId}\` tidak ada di daftar blokir.`,
      { parse_mode: "Markdown" }
    );
  }

  console.log(`[UNBAN] User ${targetId} dibuka blokirnya oleh admin ${adminId}`);

  await bot.sendMessage(
    chatId,
    `✅ *User Dibuka Blokirnya*\n\n` +
    `🆔 User ID: \`${targetId}\`\n` +
    `👮 Oleh: \`${adminId}\``,
    { parse_mode: "Markdown" }
  );
});

// ─── /banlist ──────────────────────────────────────────────────────────────
// Hanya admin. Tampilkan 20 user yang diblokir terbaru.
bot.onText(/\/banlist/, async (msg) => {
  const chatId  = msg.chat.id;
  const adminId = msg.from.id;

  if (!ADMIN_IDS.includes(adminId)) {
    return bot.sendMessage(chatId, "⛔ Perintah ini hanya untuk admin.");
  }

  try {
    const list = await getBanList();

    if (list.length === 0) {
      return bot.sendMessage(chatId, "✅ Tidak ada user yang diblokir saat ini.");
    }

    let text = `🚫 *Daftar User Diblokir* (${list.length})\n`;
    text += `━━━━━━━━━━━━━━━━\n`;

    list.forEach((row, i) => {
      const tgl = new Date(row.banned_at).toLocaleDateString("id-ID", {
        day: "2-digit", month: "short", year: "numeric"
      });
      text += `*${i + 1}.* \`${row.user_id}\`\n`;
      text += `   📝 ${row.reason}\n`;
      text += `   📅 ${tgl}\n`;
      if (i < list.length - 1) text += `\n`;
    });

    await bot.sendMessage(chatId, text, { parse_mode: "Markdown" });

  } catch (err) {
    console.error("Banlist error:", err.message);
    bot.sendMessage(chatId, "❌ Gagal mengambil daftar blokir.");
  }
});

// ─── /checkban ─────────────────────────────────────────────────────────────
// Hanya admin. Cek status ban satu user. Format: /checkban [user_id]
bot.onText(/\/checkban(?:\s+(\d+))?/, async (msg, match) => {
  const chatId   = msg.chat.id;
  const adminId  = msg.from.id;
  const targetId = match[1] ? parseInt(match[1]) : null;

  if (!ADMIN_IDS.includes(adminId)) {
    return bot.sendMessage(chatId, "⛔ Perintah ini hanya untuk admin.");
  }

  if (!targetId) {
    return bot.sendMessage(
      chatId,
      "⚠️ Sertakan User ID yang ingin dicek.\n\n_Contoh:_ /checkban 123456789",
      { parse_mode: "Markdown" }
    );
  }

  const info = await getBanInfo(targetId);

  if (!info) {
    return bot.sendMessage(
      chatId,
      `✅ User \`${targetId}\` *tidak* ada di daftar blokir.`,
      { parse_mode: "Markdown" }
    );
  }

  const tgl = new Date(info.banned_at).toLocaleString("id-ID", {
    day: "2-digit", month: "short", year: "numeric",
    hour: "2-digit", minute: "2-digit"
  });

  await bot.sendMessage(
    chatId,
    `🚫 *User Diblokir*\n\n` +
    `🆔 User ID: \`${targetId}\`\n` +
    `📝 Alasan: ${info.reason}\n` +
    `👮 Diblokir oleh: \`${info.banned_by}\`\n` +
    `📅 Sejak: ${tgl}`,
    { parse_mode: "Markdown" }
  );
});

// ─── /multi ────────────────────────────────────────────────────────────────
bot.onText(/\/multi/, async (msg) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;

  if (!isAllowed(userId)) {
    return bot.sendMessage(chatId, "⛔ Kamu tidak memiliki izin untuk menggunakan bot ini.");
  }

  // [TITIK 4] Rate limit: max 5 sesi multi per jam per user
  const multiLimit = checkBotLimit("multi", userId, 5, 3600);
  if (!multiLimit.ok) {
    return bot.sendMessage(
      chatId,
      `⏳ *Terlalu banyak sesi multi file!*\n\nCoba lagi dalam *${formatTimeLeft(multiLimit.retryAfter)}*.\n\n_Maksimal 5 sesi per jam._`,
      { parse_mode: "Markdown" }
    );
  }

  setMultiModeWithTimeout(userId, chatId, { storedIds: [], mediaGroups: new Map() });

  await bot.sendMessage(
    chatId,
    `📦 *Mode Multi File Aktif!*\n\n` +
    `Kirimkan file satu-satu atau dalam bentuk album.\n` +
    `Setelah selesai, ketik /done untuk membuat link.\n` +
    `Ketik /cancel untuk membatalkan.`,
    { parse_mode: "Markdown" }
  );
});

// ─── /done ─────────────────────────────────────────────────────────────────
bot.onText(/\/done/, async (msg) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;

  // ── Selesaikan sesi editMode (replace / add) ────────────────────────────
  if (editMode.has(userId)) {
    const session = editMode.get(userId);
    deleteEditMode(userId);

    // REPLACE: simpan semua file yang sudah dikumpulkan
    if (session.action === "replace") {
      const ids = session.storedIds || [];
      if (ids.length === 0) {
        return bot.sendMessage(chatId, "⚠️ Belum ada file yang dikirim. Sesi dibatalkan.");
      }

      const loadingMsg = await bot.sendMessage(chatId, "⏳ Mengganti file...");
      try {
        let newType, newData;
        if (ids.length === 1) {
          newType = "single";
          newData = { type: "single", id: ids[0] };
        } else {
          newType = "multi";
          newData = { type: "multi", ids };
        }
        await pool.query(
          "UPDATE links SET type = $1, data = $2 WHERE code = $3",
          [newType, JSON.stringify(newData), session.code]
        );

        const shareLink = makeShareLink(session.code);
        await bot.deleteMessage(chatId, loadingMsg.message_id);
        await bot.sendMessage(
          chatId,
          `✅ *File berhasil diganti!*\n\n` +
          `🔑 Link: \`${session.code}\`\n` +
          `📦 Total file baru: *${ids.length}*\n` +
          `🔗 ${shareLink}\n\n` +
          `_Semua file lama telah diganti._`,
          {
            parse_mode: "Markdown",
            reply_markup: {
              inline_keyboard: [[{ text: "📤 Bagikan Link", url: shareLink }]],
            },
          }
        );
        console.log(`[REPLACE] Link ${session.code} diganti ${ids.length} file oleh user ${userId}`);
      } catch (err) {
        console.error("Error replace done:", err.message);
        await bot.editMessageText("❌ Gagal mengganti file.", {
          chat_id: chatId, message_id: loadingMsg.message_id,
        });
      }
      return;
    }

    // ADD: konfirmasi selesai tambah file
    if (session.action === "add") {
      const raw   = await getRawLink(session.code);
      const total = raw ? (raw.type === "single" ? 1 : raw.data.ids.length) : 0;
      const shareLink = makeShareLink(session.code);

      await bot.sendMessage(
        chatId,
        `✅ *Selesai menambah file!*\n\n` +
        `🔑 Link: \`${session.code}\`\n` +
        `📦 Total file sekarang: *${total}*\n` +
        `🔗 ${shareLink}`,
        {
          parse_mode: "Markdown",
          reply_markup: {
            inline_keyboard: [[{ text: "📤 Bagikan Link", url: shareLink }]],
          },
        }
      );
      console.log(`[ADDFILE] Sesi selesai — link ${session.code}, total: ${total} file, user: ${userId}`);
      return;
    }
  }

  // ── Selesaikan sesi multiMode (upload biasa) ────────────────────────────
  if (!multiMode.has(userId)) {
    return bot.sendMessage(chatId, "⚠️ Kamu tidak sedang dalam mode multi file.\nKetik /multi untuk memulai.");
  }

  const session = multiMode.get(userId);
  deleteMultiMode(userId);

  if (session.storedIds.length === 0) {
    return bot.sendMessage(chatId, "⚠️ Belum ada file yang dikirim. Sesi dibatalkan.");
  }

  const loadingMsg = await bot.sendMessage(chatId, "⏳ Membuat link...");

  try {
    const linkData = session.storedIds.length === 1
      ? { type: "single", id: session.storedIds[0] }
      : { type: "multi", ids: session.storedIds };

    const defaultTitle = `Paket ${session.storedIds.length} File`;
    const code         = await saveLink(linkData, userId, defaultTitle);
    const shareLink    = makeShareLink(code);
    const expireDays   = parseInt(process.env.LINK_EXPIRE_DAYS) || 0;

    await bot.deleteMessage(chatId, loadingMsg.message_id);
    await bot.sendMessage(
      chatId,
      `✅ *${session.storedIds.length} file berhasil diupload!*\n\n` +
      `🏷️ *Judul:* ${defaultTitle}\n` +
      `🔑 Kode: \`${code}\`\n` +
      `🔗 *Link Share:*\n\`${shareLink}\`\n\n` +
      `⏳ Expired: ${expireDays > 0 ? `${expireDays} hari` : "Tidak ada"}\n\n` +
      `_Ubah judul: /settitle ${code} Judul Baru_\n` +
      `_Penerima perlu membuka iklan sebelum mengakses file._`,
      {
        parse_mode: "Markdown",
        reply_markup: {
          inline_keyboard: [[{ text: "📤 Bagikan Link", url: shareLink }]],
        },
      }
    );

    console.log(`[UPLOAD] Multi ${session.storedIds.length} file oleh ${userId} → code: ${code}`);
  } catch (err) {
    console.error("Error membuat link:", err.message);
    await bot.editMessageText("❌ Gagal membuat link.", {
      chat_id: chatId, message_id: loadingMsg.message_id,
    });
  }
});

// ─── /cancel ───────────────────────────────────────────────────────────────
// Regex exact: /cancel$ agar tidak ikut menangkap /canceledit
bot.onText(/\/cancel$/, async (msg) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;

  if (!multiMode.has(userId)) {
    return bot.sendMessage(chatId, "⚠️ Tidak ada sesi aktif yang bisa dibatalkan.");
  }

  deleteMultiMode(userId);
  await bot.sendMessage(chatId, "❌ Sesi multi file dibatalkan.");
});

// ─── CALLBACK QUERY ────────────────────────────────────────────────────────
bot.on("callback_query", async (query) => {
  if (query.data === "noop") {
    await bot.answerCallbackQuery(query.id);
  }
});

// ─── HANDLER PESAN (upload file) ───────────────────────────────────────────
bot.on("message", async (msg) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;

  if (msg.web_app_data) return;
  if (msg.text && msg.text.startsWith("/")) return;

  if (!isAllowed(userId)) {
    return bot.sendMessage(chatId, "⛔ Kamu tidak memiliki izin untuk menggunakan bot ini.");
  }

  // Cek blacklist
  if (!ADMIN_IDS.includes(userId) && await isBlacklisted(userId)) {
    return bot.sendMessage(chatId, "⛔ Akun kamu telah diblokir dari bot ini.");
  }

  const mediaType = getMediaType(msg);
  if (!mediaType) {
    return bot.sendMessage(
      chatId,
      "ℹ️ Kirimkan *file, foto, video, audio, atau dokumen*.",
      { parse_mode: "Markdown" }
    );
  }

  // [TITIK 5] Rate limit: max 20 upload per jam per user
  const uploadLimit = checkBotLimit("upload", userId, 20, 3600);
  if (!uploadLimit.ok) {
    return bot.sendMessage(
      chatId,
      `⏳ *Batas upload tercapai!*\n\nKamu bisa upload lagi dalam *${formatTimeLeft(uploadLimit.retryAfter)}*.\n\n_Maksimal 20 file per jam._`,
      { parse_mode: "Markdown" }
    );
  }

  const mediaEmoji = {
    photo: "🖼", video: "🎬", document: "📄",
    audio: "🎵", voice: "🎤", video_note: "📹", animation: "🎞",
  };
  const emoji = mediaEmoji[mediaType] || "📁";

  // ── MODE EDIT LINK ───────────────────────────────────────────────────────
  if (editMode.has(userId)) {
    const session = editMode.get(userId);

    // ── REPLACE: support multi file via album, selesai dengan /done ──────────
    if (session.action === "replace") {

      // Tangani album (media_group)
      if (msg.media_group_id) {
        const groupId = msg.media_group_id;
        if (!session.mediaGroups) session.mediaGroups = new Map();
        if (!session.mediaGroups.has(groupId)) {
          session.mediaGroups.set(groupId, { msgs: [], timer: null });
        }
        const group = session.mediaGroups.get(groupId);
        group.msgs.push(msg);

        if (group.timer) clearTimeout(group.timer);
        group.timer = setTimeout(async () => {
          session.mediaGroups.delete(groupId);
          if (!session.storedIds) session.storedIds = [];
          const processingMsg = await bot.sendMessage(chatId, `⏳ Memproses ${group.msgs.length} file dari album...`);
          try {
            for (const m of group.msgs) {
              const storedId = await forwardToStorage(chatId, m.message_id);
              session.storedIds.push(storedId);
            }
            await bot.editMessageText(
              `✅ *${group.msgs.length} file* dari album ditambahkan!\n` +
              `📦 Total: *${session.storedIds.length} file*\n\n` +
              `_Kirim file lagi atau ketik /done jika selesai._`,
              { chat_id: chatId, message_id: processingMsg.message_id, parse_mode: "Markdown" }
            );
          } catch (err) {
            console.error("Error forward album replace:", err.message);
            await bot.editMessageText("❌ Gagal memproses album.", {
              chat_id: chatId, message_id: processingMsg.message_id,
            });
          }
        }, 1500);
        return;
      }

      // File tunggal
      if (!session.storedIds) session.storedIds = [];
      const processingMsg = await bot.sendMessage(chatId, "⏳ Memproses file...");
      try {
        const storedId = await forwardToStorage(chatId, msg.message_id);
        session.storedIds.push(storedId);
        await bot.editMessageText(
          `${emoji} *File ke-${session.storedIds.length} diterima!*\n\n` +
          `🔑 Link: \`${session.code}\`\n\n` +
          `_Kirim file lagi atau ketik /done jika selesai._`,
          { chat_id: chatId, message_id: processingMsg.message_id, parse_mode: "Markdown" }
        );
      } catch (err) {
        console.error("Error forward file replace:", err.message);
        await bot.editMessageText("❌ Gagal memproses file.", {
          chat_id: chatId, message_id: processingMsg.message_id,
        });
      }
      return;
    }

    // ── ADD: tambah file, mode tetap aktif sampai /done ─────────────────────
    if (session.action === "add") {

      // Tangani album (media_group)
      if (msg.media_group_id) {
        const groupId = msg.media_group_id;
        if (!session.mediaGroups) session.mediaGroups = new Map();
        if (!session.mediaGroups.has(groupId)) {
          session.mediaGroups.set(groupId, { msgs: [], timer: null });
        }
        const group = session.mediaGroups.get(groupId);
        group.msgs.push(msg);

        if (group.timer) clearTimeout(group.timer);
        group.timer = setTimeout(async () => {
          session.mediaGroups.delete(groupId);
          const processingMsg = await bot.sendMessage(chatId, `⏳ Memproses ${group.msgs.length} file dari album...`);
          try {
            let totalFiles = 0;
            for (const m of group.msgs) {
              const storedId = await forwardToStorage(chatId, m.message_id);
              totalFiles = await addFileToLink(session.code, storedId);
            }
            await bot.editMessageText(
              `✅ *${group.msgs.length} file* dari album ditambahkan!\n` +
              `📦 Total file sekarang: *${totalFiles}*\n\n` +
              `_Kirim file lagi atau ketik /done jika selesai._`,
              { chat_id: chatId, message_id: processingMsg.message_id, parse_mode: "Markdown" }
            );
            console.log(`[ADDFILE] Album ${group.msgs.length} file ke link ${session.code} oleh user ${userId}, total: ${totalFiles}`);
          } catch (err) {
            console.error("Error forward album addfile:", err.message);
            await bot.editMessageText("❌ Gagal memproses album.", {
              chat_id: chatId, message_id: processingMsg.message_id,
            });
          }
        }, 1500);
        return;
      }

      // File tunggal
      const processingMsg = await bot.sendMessage(chatId, "⏳ Menambahkan file...");
      try {
        const storedId   = await forwardToStorage(chatId, msg.message_id);
        const totalFiles = await addFileToLink(session.code, storedId);
        await bot.editMessageText(
          `${emoji} *File ditambahkan!*\n\n` +
          `🔑 Link: \`${session.code}\`\n` +
          `📦 Total file sekarang: *${totalFiles}*\n\n` +
          `_Kirim file lagi atau ketik /done jika selesai._`,
          { chat_id: chatId, message_id: processingMsg.message_id, parse_mode: "Markdown" }
        );
        console.log(`[ADDFILE] File ditambahkan ke link ${session.code} oleh user ${userId}, total: ${totalFiles}`);
      } catch (err) {
        console.error("Error add file:", err.message);
        await bot.editMessageText("❌ Gagal menambahkan file.", {
          chat_id: chatId, message_id: processingMsg.message_id,
        });
      }
      return;
    }
  }

  // ── MODE MULTI FILE ──────────────────────────────────────────────────────
  if (multiMode.has(userId)) {
    const session = multiMode.get(userId);

    if (msg.media_group_id) {
      const groupId = msg.media_group_id;
      if (!session.mediaGroups.has(groupId)) {
        session.mediaGroups.set(groupId, { msgs: [], timer: null });
      }
      const group = session.mediaGroups.get(groupId);
      group.msgs.push(msg);

      if (group.timer) clearTimeout(group.timer);
      group.timer = setTimeout(async () => {
        session.mediaGroups.delete(groupId);
        const processingMsg = await bot.sendMessage(chatId, `⏳ Memproses ${group.msgs.length} file dari album...`);
        try {
          for (const m of group.msgs) {
            const storedId = await forwardToStorage(chatId, m.message_id);
            session.storedIds.push(storedId);
          }
          await bot.editMessageText(
            `✅ *${group.msgs.length} file* dari album ditambahkan!\n` +
            `📦 Total: *${session.storedIds.length} file* — Ketik /done jika selesai.`,
            { chat_id: chatId, message_id: processingMsg.message_id, parse_mode: "Markdown" }
          );
        } catch (err) {
          console.error("Error forward album:", err.message);
          await bot.editMessageText("❌ Gagal memproses album.", {
            chat_id: chatId, message_id: processingMsg.message_id,
          });
        }
      }, 1500);
      return;
    }

    try {
      const storedId = await forwardToStorage(chatId, msg.message_id);
      session.storedIds.push(storedId);
      await bot.sendMessage(
        chatId,
        `${emoji} File ke-*${session.storedIds.length}* ditambahkan!\n_Kirim lagi atau ketik /done untuk selesai._`,
        { parse_mode: "Markdown" }
      );
    } catch (err) {
      console.error("Error forward file:", err.message);
      await bot.sendMessage(chatId, "❌ Gagal memproses file.");
    }
    return;
  }

  // ── SINGLE FILE ──────────────────────────────────────────────────────────
  const loadingMsg = await bot.sendMessage(chatId, "⏳ Sedang memproses file...");

  try {
    const storedMessageId = await forwardToStorage(chatId, msg.message_id);

    const fileName =
      msg.document?.file_name ||
      msg.audio?.title ||
      msg.audio?.file_name ||
      (mediaType.charAt(0).toUpperCase() + mediaType.slice(1));

    // Simpan title default dari nama file
    const code      = await saveLink({ type: "single", id: storedMessageId }, userId, fileName);
    const shareLink = makeShareLink(code);
    const expireDays = parseInt(process.env.LINK_EXPIRE_DAYS) || 0;

    await bot.deleteMessage(chatId, loadingMsg.message_id);
    await bot.sendMessage(
      chatId,
      `✅ *File berhasil diupload!*\n\n` +
      `${emoji} *Nama:* ${fileName}\n` +
      `🏷️ *Judul:* ${fileName}\n` +
      `🔑 *Kode:* \`${code}\`\n` +
      `⏳ *Expired:* ${expireDays > 0 ? `${expireDays} hari` : "Tidak ada"}\n\n` +
      `🔗 *Link Share:*\n\`${shareLink}\`\n\n` +
      `_Ubah judul: /settitle ${code} Judul Baru_\n` +
      `_Penerima perlu membuka iklan sebelum mengakses file._`,
      {
        parse_mode: "Markdown",
        reply_markup: {
          inline_keyboard: [[{ text: "📤 Bagikan Link", url: shareLink }]],
        },
      }
    );

    console.log(`[UPLOAD] Single file oleh ${userId} → code: ${code}`);
  } catch (err) {
    console.error("Error memproses file:", err.message);
    await bot.editMessageText(
      "❌ Gagal memproses file. Pastikan bot sudah menjadi admin di channel penyimpanan.",
      { chat_id: chatId, message_id: loadingMsg.message_id }
    );
  }
});

bot.on("polling_error", (err) => {
  // 409 = instance lain masih jalan (Railway rolling deploy)
  // Stop polling dan retry setelah 5 detik
  if (err.message.includes("409")) {
    console.warn("⚠️  409 Conflict — instance lain masih aktif, retry 5 detik lagi...");
    isPolling = false;
    bot.stopPolling().then(() => {
      setTimeout(startPolling, 5000);
    }).catch(() => {
      setTimeout(startPolling, 5000);
    });
  } else {
    console.error("Polling error:", err.message);
  }
});

// ─── INIT ──────────────────────────────────────────────────────────────────
initDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`🌐 HTTP server berjalan di port ${PORT}`);
      console.log(`🤖 Bot aktif: @${BOT_USERNAME}`);
      console.log(`🔗 Backend URL: ${WEBAPP_BACKEND_URL}`);
      console.log(`📱 WebApp URL: ${WEBAPP_URL}`);
    });
    // Mulai polling setelah DB siap
    startPolling();

    // ── Cleanup job: hapus session & link expired setiap 1 jam ──────────────
    setInterval(async () => {
      try {
        const r1 = await pool.query("DELETE FROM ad_sessions WHERE expires_at < NOW()");
        const r2 = await pool.query(
          "DELETE FROM links WHERE expires_at IS NOT NULL AND expires_at < NOW()"
        );
        const n1 = r1.rowCount, n2 = r2.rowCount;
        if (n1 > 0 || n2 > 0) {
          console.log(`[CLEANUP] Hapus ${n1} session & ${n2} link expired`);
        }
      } catch (err) {
        console.error("[CLEANUP] Error:", err.message);
      }
    }, 60 * 60 * 1000); // setiap 1 jam
  })
  .catch((err) => {
    console.error("❌ Gagal koneksi database:", err.message);
    process.exit(1);
  });
