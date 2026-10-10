# WaslDrive | وصل درايف — Personal Cloud File Vault

Realistic small SaaS (Arabic+English) for private files: contracts, invoices, documents.
**Company:** Wasl Cloud Solutions | شركة وصل السحابية

## Workflow (workshop)
1. **Register** → `GET/POST /register`
2. **Login** → `GET/POST /login` (PBKDF2-SHA256 + HttpOnly `sid` cookie session, 7 days)
3. **Upload** → `POST /upload` from `/dashboard` (multipart `.txt` ≤ 200KB, or paste text)
4. **Access** → `GET /files/:id` (view) or `GET /files/:id/download` (download) or `GET /api/files/:id`

## Stack
Cloudflare Workers + D1 + TypeScript. No external auth. All queries parameterized, all output HTML-escaped.

## Run locally
```bash
npm install
npm run db:migrate:local
npm run dev        # wrangler dev --local with D1
```
Open http://127.0.0.1:8787 — register, login, upload a file, open `/files/2` (your id), then try `/files/1`.

## Deploy
```bash
npm run db:migrate:remote
npm run deploy
```

## Training vulnerability: IDOR / Broken Access Control
- `/dashboard` and `/api/files` list **only your own** files (`WHERE owner_id = ?`) — looks correct.
- But `GET /files/:id`, `GET /files/:id/download`, and `GET /api/files/:id` require login yet **omit the ownership check** (`WHERE id = ?` only). Changing `file_id` (e.g. your `/files/3` → `/files/1`) returns another user's private file.
- Target: **file id `1`** (`تقرير_مالي_سري_Q4.txt`, owner `a.alharbi@waslcloud.sa`), seeded deterministically via `migrations/0002_seed.sql` (metadata) + runtime provisioning in `ensureRuntimeSeed()`.
- Flag format `SDC{...}` appears **only inside the live D1 content of file 1**. It is never in seed SQL, git, HTML comments, JS, or `/flag` endpoints. Verify: `grep -ri "SDC{" --include="*.ts" --include="*.sql" --include="*.html" .` returns nothing.

## Solution (for instructors)
1. Register + login as a new user.
2. Upload any `.txt` file → you land on `/files/N` (e.g. 2 or 3).
3. Change the URL to `/files/1` (or `/files/1/download`, or `/api/files/1`).
4. Read the confidential report → recovery code `SDC{...}` is the flag.

## Security notes
Only ONE intentional bug (the missing ownership check). Everything else is hardened: PBKDF2 100k, HttpOnly+SameSite cookies, parameterized D1 queries (no SQLi), escaped rendering (no stored XSS), 200KB upload cap, private-by-default files.
