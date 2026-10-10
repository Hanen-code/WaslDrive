/* WaslDrive | وصل درايف — Personal cloud file vault.
 * Stack: Cloudflare Workers + D1 + TypeScript.
 * Workflow: Register → Login → Upload file → Open file.
 * Intentional vuln: IDOR on file read/download (missing ownership check).
 * Flag lives ONLY in live D1 content of file id=1, generated at runtime.
 */

export interface Env {
  DB: D1Database;
  COMPANY_NAME?: string;
  APP_NAME?: string;
}

const COMPANY = "Wasl Cloud Solutions | شركة وصل السحابية";
const PBKDF2_ITER = 100000;
const SESSION_TTL_MS = 7 * 24 * 3600 * 1000;
const MAX_FILE_BYTES = 200_000;

// ---------- helpers ----------
function esc(s: string): string {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function hex(bytes: ArrayBuffer | Uint8Array): string {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}
function unhex(s: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(s.length / 2));
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function randHex(nBytes: number): string {
  return hex(crypto.getRandomValues(new Uint8Array(nBytes)));
}

async function hashPassword(password: string, saltHex: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: unhex(saltHex), iterations: PBKDF2_ITER },
    key,
    256
  );
  return hex(bits);
}

function getCookie(req: Request, name: string): string | null {
  const h = req.headers.get("Cookie");
  if (!h) return null;
  for (const part of h.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return decodeURIComponent(rest.join("="));
  }
  return null;
}

interface SessionUser {
  id: number;
  name: string;
  email: string;
}

async function currentUser(req: Request, env: Env): Promise<SessionUser | null> {
  const sid = getCookie(req, "sid");
  if (!sid) return null;
  const row = await env.DB.prepare(
    "SELECT s.expires_at AS exp, u.id AS id, u.name AS name, u.email AS email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?"
  )
    .bind(sid)
    .first<{ exp: number; id: number; name: string; email: string }>();
  if (!row) return null;
  if (row.exp < Date.now()) {
    await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(sid).run();
    return null;
  }
  return { id: row.id, name: row.name, email: row.email };
}

function sessionCookie(sid: string, maxAgeSec: number): string {
  return `sid=${encodeURIComponent(sid)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSec}; Secure`;
}
function clearCookie(): string {
  return `sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
}

// Runtime seed: ensures victim (id=1) + target file (id=1) exist,
// and generates the confidential content + random recovery-code flag ONCE,
// directly in live D1. Nothing flag-like is committed to the repo.
async function ensureRuntimeSeed(env: Env): Promise<void> {
  const f = await env.DB.prepare("SELECT id, content FROM files WHERE id = 1").first<{ id: number; content: string }>();
  if (f && f.content.includes("SDC" + "{")) return; // already provisioned
  const flag = "SDC" + "{" + randHex(8) + "_wasl_" + randHex(4) + "}";
  const report =
    `WaslDrive — Confidential Q4 Financial Report | التقرير المالي السري\n` +
    `Company: Wasl Cloud Solutions | Owner: a.alharbi@waslcloud.sa\n` +
    `------------------------------------------------------------\n` +
    `Revenue Q4: 1,284,500 SAR | Net: 312,900 SAR\n` +
    `Auditor note: private — do not share outside finance.\n` +
    `ملاحظة: هذا الملف خاص بصاحبه فقط ومشاركته ممنوعة.\n` +
    `------------------------------------------------------------\n` +
    `Vault recovery code: ${flag}\n` +
    `Use this code to verify Q4 archive integrity.\n`;
  if (f) {
    await env.DB.prepare("UPDATE files SET content = ?, size = ?, mime = 'text/plain' WHERE id = 1")
      .bind(report, report.length)
      .run();
  } else {
    await env.DB.prepare(
      "INSERT INTO files (id, owner_id, filename, mime, size, content, is_private) VALUES (1, 1, 'تقرير_مالي_سري_Q4.txt', 'text/plain', ?, ?, 1)"
    )
      .bind(report.length, report)
      .run();
  }
}

// ---------- UI ----------
const CSS = `
*{box-sizing:border-box}body{font-family:'Segoe UI',Tahoma,Arial,sans-serif;background:#f1f5f9;color:#0f172a;margin:0}
.wrap{max-width:880px;margin:0 auto;padding:24px}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:14px;padding:24px;box-shadow:0 2px 10px rgba(0,0,0,.04)}
header.top{background:#0f2743;color:#fff;padding:14px 0}header.top .wrap{display:flex;justify-content:space-between;align-items:center}
a{color:#1d4ed8}.btn{background:#1d4ed8;color:#fff;border:0;border-radius:10px;padding:10px 18px;cursor:pointer;font-size:15px}
.btn.ghost{background:#e2e8f0;color:#0f172a}input,textarea{width:100%;padding:10px;border:1px solid #cbd5e1;border-radius:10px;margin:6px 0 12px}
table{width:100%;border-collapse:collapse}td,th{border-bottom:1px solid #e2e8f0;padding:10px;text-align:right}
.rtl{direction:rtl;text-align:right}.muted{color:#64748b;font-size:13px}
.nav a{color:#fff;margin-inline-start:14px;text-decoration:none}
.alert{background:#fef2f2;border:1px solid #fecaca;color:#991b1b;padding:10px;border-radius:10px;margin-bottom:12px}
pre{background:#0f172a;color:#e2e8f0;padding:16px;border-radius:12px;white-space:pre-wrap;word-break:break-word}
`;

function layout(title: string, user: SessionUser | null, body: string): string {
  return `<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${esc(title)} — WaslDrive</title><link rel="stylesheet" href="/styles.css"/></head>
<body><header class="top"><div class="wrap">
<div><b>WaslDrive | وصل درايف</b><div class="muted" style="color:#cbd5e1">${esc(COMPANY)}</div></div>
<nav class="nav">${user
    ? `<span>${esc(user.name)}</span><a href="/dashboard">لوحتي / Dashboard</a><a href="/logout">خروج / Logout</a>`
    : `<a href="/login">دخول / Login</a><a href="/register">حساب جديد / Register</a>`}</nav>
</div></header><div class="wrap"><div class="card">${body}</div>
<p class="muted">WaslDrive — خزنة ملفاتك الخاصة للعقود والفواتير والمستندات | Your private vault for contracts &amp; invoices.</p>
</div></body></html>`;
}

function homePage(user: SessionUser | null): Response {
  const body = `<div class="rtl">
<h1>خزنتك السحابية الخاصة 🔒</h1>
<p>ارفع عقودك وفواتيرك وملفاتك الخاصة، وافتحها أو حمّلها في أي وقت برابط مباشر.</p>
<p class="muted">Your private cloud vault — upload contracts &amp; invoices, open or download them anytime via a direct link.</p>
${user ? `<p><a class="btn" href="/dashboard">الذهاب إلى لوحتي</a></p>` : `<p><a class="btn" href="/register">أنشئ حسابك مجاناً</a> <a class="btn ghost" href="/login">تسجيل الدخول</a></p>`}
<h3>كيف تستخدم الخدمة؟ | How it works</h3>
<ol><li>سجّل حساباً جديداً (Register)</li><li>سجّل الدخول (Login)</li><li>ارفع ملفاً نصياً من لوحتك (Upload)</li><li>افتح ملفك من جدول ملفاتك (Open / Download)</li></ol>
</div>`;
  return html(layout("الرئيسية | Home", user, body));
}
function html(s: string, status = 200): Response {
  return new Response(s, { status, headers: { "content-type": "text/html; charset=utf-8" } });
}

// ---------- router ----------
export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;
    const method = req.method.toUpperCase();

    if (path === "/styles.css")
      return new Response(CSS, { headers: { "content-type": "text/css; charset=utf-8" } });
    if (path === "/health") return Response.json({ ok: true, app: "wasldrive" });

    await ensureRuntimeSeed(env);

    if (path === "/" && method === "GET") return homePage(await currentUser(req, env));

    if (path === "/register" && method === "GET") {
      const body = `<div class="rtl"><h2>حساب جديد | Register</h2>
<form method="post" action="/register">
<label>الاسم | Name</label><input name="name" required maxlength="80"/>
<label>البريد | Email</label><input name="email" type="email" required maxlength="120"/>
<label>كلمة المرور | Password</label><input name="password" type="password" required minlength="8"/>
<button class="btn">إنشاء الحساب</button></form>
<p class="muted">لديك حساب؟ <a href="/login">سجّل الدخول</a></p></div>`;
      return html(layout("Register", await currentUser(req, env), body));
    }

    if (path === "/register" && method === "POST") {
      const form = await req.formData();
      const name = String(form.get("name") || "").trim().slice(0, 80);
      const email = String(form.get("email") || "").trim().toLowerCase().slice(0, 120);
      const password = String(form.get("password") || "");
      const me = await currentUser(req, env);
      if (!name || !email.includes("@") || password.length < 8) {
        return html(layout("Register", me, `<div class="rtl"><div class="alert">بيانات غير صالحة. تحقق من الاسم والبريد (وكلمة ≥ 8 أحرف).</div><a href="/register">رجوع</a></div>`), 400);
      }
      const exists = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
      if (exists) {
        return html(layout("Register", me, `<div class="rtl"><div class="alert">هذا البريد مسجل مسبقاً. <a href="/login">سجّل الدخول</a></div></div>`), 409);
      }
      const salt = randHex(16);
      const pwHash = await hashPassword(password, salt);
      const res = await env.DB.prepare("INSERT INTO users (name, email, password_hash, salt) VALUES (?, ?, ?, ?)")
        .bind(name, email, pwHash, salt)
        .run();
      const userId = Number(res.meta.last_row_id);
      const sid = randHex(32);
      await env.DB.prepare("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)")
        .bind(sid, userId, Date.now() + SESSION_TTL_MS)
        .run();
      return new Response(null, {
        status: 302,
        headers: { Location: "/dashboard", "Set-Cookie": sessionCookie(sid, 604800) },
      });
    }

    if (path === "/login" && method === "GET") {
      const body = `<div class="rtl"><h2>تسجيل الدخول | Login</h2>
<form method="post" action="/login">
<label>البريد | Email</label><input name="email" type="email" required/>
<label>كلمة المرور | Password</label><input name="password" type="password" required/>
<button class="btn">دخول</button></form>
<p class="muted">حساب جديد؟ <a href="/register">سجّل هنا</a></p></div>`;
      return html(layout("Login", await currentUser(req, env), body));
    }

    if (path === "/login" && method === "POST") {
      const form = await req.formData();
      const email = String(form.get("email") || "").trim().toLowerCase();
      const password = String(form.get("password") || "");
      const row = await env.DB.prepare("SELECT id, name, email, password_hash, salt FROM users WHERE email = ?")
        .bind(email)
        .first<{ id: number; name: string; email: string; password_hash: string; salt: string }>();
      const fail = async () =>
        html(layout("Login", null, `<div class="rtl"><div class="alert">بريد أو كلمة مرور غير صحيحة.</div><a href="/login">حاول مجدداً</a></div>`), 401);
      if (!row) return fail();
      const calc = await hashPassword(password, row.salt);
      if (calc !== row.password_hash) return fail();
      const sid = randHex(32);
      await env.DB.prepare("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)")
        .bind(sid, row.id, Date.now() + SESSION_TTL_MS)
        .run();
      return new Response(null, {
        status: 302,
        headers: { Location: "/dashboard", "Set-Cookie": sessionCookie(sid, 604800) },
      });
    }

    if ((path === "/logout" && method === "GET") || (path === "/logout" && method === "POST")) {
      const sid = getCookie(req, "sid");
      if (sid) await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(sid).run();
      return new Response(null, { status: 302, headers: { Location: "/", "Set-Cookie": clearCookie() } });
    }

    // ----- authenticated area -----
    if (path === "/dashboard" && method === "GET") {
      const user = await currentUser(req, env);
      if (!user) return new Response(null, { status: 302, headers: { Location: "/login" } });
      const mine = await env.DB.prepare(
        "SELECT id, filename, size, created_at FROM files WHERE owner_id = ? ORDER BY id DESC LIMIT 50"
      )
        .bind(user.id)
        .all<{ id: number; filename: string; size: number; created_at: string }>();
      const rows = (mine.results || [])
        .map(
          (r) =>
            `<tr><td>${r.id}</td><td>${esc(r.filename)}</td><td>${r.size}</td><td>${esc(r.created_at)}</td>` +
            `<td><a href="/files/${r.id}">فتح / Open</a> · <a href="/files/${r.id}/download">تحميل / Download</a></td></tr>`
        )
        .join("");
      const body = `<div class="rtl"><h2>لوحتي | My vault</h2>
<p class="muted">مرحباً ${esc(user.name)} (${esc(user.email)}) — هذه ملفاتك الخاصة فقط.</p>
<h3>رفع ملف نصي جديد | Upload a text file</h3>
<form method="post" action="/upload" enctype="multipart/form-data">
<label>اختر ملفاً (.txt حتى 200KB)</label><input type="file" name="doc" accept=".txt,text/plain" required/>
<label>أو الصق نصاً مباشرة | Or paste text</label><textarea name="pasted" rows="4" placeholder="الصق محتوى الملف هنا..."></textarea>
<label>اسم الملف | Filename</label><input name="filename" maxlength="120" placeholder="مثال: عقد_عميل.txt"/>
<button class="btn">رفع | Upload</button></form>
<h3>ملفاتي | My files</h3>
<table><tr><th>ID</th><th>الاسم</th><th>الحجم</th><th>التاريخ</th><th>إجراءات</th></tr>${rows || '<tr><td colspan="5" class="muted">لا ملفات بعد — ارفع أول ملف لك.</td></tr>'}</table>
<p class="muted">Tip: each file has a direct link like <code>/files/2</code>. | لكل ملف رابط مباشر.</p>
</div>`;
      return html(layout("Dashboard", user, body));
    }

    if (path === "/upload" && method === "POST") {
      const user = await currentUser(req, env);
      if (!user) return new Response(null, { status: 302, headers: { Location: "/login" } });
      const form = await req.formData();
      const up = form.get("doc");
      const pasted = String(form.get("pasted") || "");
      let custom = String(form.get("filename") || "").trim().slice(0, 120);
      let content = "";
      let filename = custom || "ملف_جديد.txt";
      if (up instanceof File && up.size > 0) {
        if (up.size > MAX_FILE_BYTES) {
          return html(layout("Dashboard", user, `<div class="rtl"><div class="alert">الملف أكبر من 200KB.</div><a href="/dashboard">رجوع</a></div>`), 413);
        }
        content = (await up.text()).slice(0, MAX_FILE_BYTES);
        if (!custom) filename = (up.name || "upload.txt").slice(0, 120);
      } else if (pasted.trim()) {
        content = pasted.slice(0, MAX_FILE_BYTES);
      } else {
        return html(layout("Dashboard", user, `<div class="rtl"><div class="alert">اختر ملفاً أو الصق نصاً.</div><a href="/dashboard">رجوع</a></div>`), 400);
      }
      const res = await env.DB.prepare(
        "INSERT INTO files (owner_id, filename, mime, size, content, is_private) VALUES (?, ?, 'text/plain', ?, ?, 1)"
      )
        .bind(user.id, filename, content.length, content)
        .run();
      const newId = Number(res.meta.last_row_id);
      return new Response(null, { status: 302, headers: { Location: `/files/${newId}` } });
    }

    // VULNERABLE: view any file by id when logged in — no ownership check (IDOR).
    const viewM = path.match(/^\/files\/(\d+)$/);
    if (viewM && method === "GET") {
      const user = await currentUser(req, env);
      if (!user) return new Response(null, { status: 302, headers: { Location: "/login" } });
      const id = Number(viewM[1]);
      const row = await env.DB.prepare(
        "SELECT f.id, f.filename, f.size, f.content, f.created_at, u.name AS owner_name FROM files f JOIN users u ON u.id = f.owner_id WHERE f.id = ?"
      )
        .bind(id)
        .first<{ id: number; filename: string; size: number; content: string; created_at: string; owner_name: string }>();
      if (!row)
        return html(layout("File", user, `<div class="rtl"><div class="alert">الملف غير موجود (404).</div><a href="/dashboard">رجوع للوحة</a></div>`), 404);
      const body = `<div class="rtl"><h2>📄 ${esc(row.filename)}</h2>
<p class="muted">File #${row.id} · الحجم ${row.size} · بتاريخ ${esc(row.created_at)} · <a href="/files/${row.id}/download">تحميل / Download</a></p>
<pre>${esc(row.content)}</pre>
<p><a href="/dashboard">← رجوع للوحة</a></p></div>`;
      return html(layout(`File #${row.id}`, user, body));
    }

    // VULNERABLE: download any file by id when logged in — no ownership check (IDOR).
    const dlM = path.match(/^\/files\/(\d+)\/download$/);
    if (dlM && method === "GET") {
      const user = await currentUser(req, env);
      if (!user) return new Response("Login required", { status: 401 });
      const id = Number(dlM[1]);
      const row = await env.DB.prepare("SELECT filename, content FROM files WHERE id = ?")
        .bind(id)
        .first<{ filename: string; content: string }>();
      if (!row) return new Response("Not found", { status: 404 });
      const safe = row.filename.replace(/["\r\n]/g, "_");
      return new Response(row.content, {
        headers: {
          "content-type": "text/plain; charset=utf-8",
          "content-disposition": `attachment; filename*=UTF-8''${encodeURIComponent(safe)}`,
        },
      });
    }

    // JSON API (own list is scoped; single-file read is intentionally unscoped — same IDOR).
    if (path === "/api/files" && method === "GET") {
      const user = await currentUser(req, env);
      if (!user) return Response.json({ error: "auth" }, { status: 401 });
      const mine = await env.DB.prepare("SELECT id, filename, size, created_at FROM files WHERE owner_id = ? ORDER BY id DESC")
        .bind(user.id)
        .all();
      return Response.json({ files: mine.results });
    }
    const apiM = path.match(/^\/api\/files\/(\d+)$/);
    if (apiM && method === "GET") {
      const user = await currentUser(req, env);
      if (!user) return Response.json({ error: "auth" }, { status: 401 });
      const id = Number(apiM[1]);
      const row = await env.DB.prepare("SELECT id, filename, size, created_at, content FROM files WHERE id = ?")
        .bind(id)
        .first();
      if (!row) return Response.json({ error: "not_found" }, { status: 404 });
      return Response.json({ file: row });
    }

    return new Response("Not found", { status: 404 });
  },
};
