-- Deterministic seed: victim user (id=1) + private target file (id=1).
-- IMPORTANT: file content here is a BENIGN placeholder. The real confidential
-- content + flag is generated at runtime by the Worker (see ensureRuntimeSeed
-- in src/index.ts) so that no flag ever appears in seed files, git, or HTML.

INSERT OR IGNORE INTO users (id, name, email, password_hash, salt)
VALUES (
  1,
  'م. عبدالله الحربي',
  'a.alharbi@waslcloud.sa',
  '1b89d229736b608ccc269b893acc46d14b9385781612bd4b043abb43473a8d46',
  '73650c45f33b679fd43bd6ad2b326908'
);

INSERT OR IGNORE INTO files (id, owner_id, filename, mime, size, content, is_private)
VALUES (
  1,
  1,
  'تقرير_مالي_سري_Q4.txt',
  'text/plain',
  128,
  'PLACEHOLDER — will be replaced at runtime with the confidential report. / سيتم استبداله عند التشغيل.',
  1
);
