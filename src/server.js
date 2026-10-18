const http = require('http');
const fs = require('fs');
const path = require('path');
const {
  parseJsonBody,
  sendJson,
  hashPassword,
  verifyPassword,
  signToken,
  verifyToken,
  randomId,
  nowIso
} = require('./utils');
const { roles, computeAutoScore, examViewForAttempt, randomizeExam, parseCsvUsers } = require('./store');
const { initSchema, pool, withTransaction } = require('./db');
const { createCache } = require('./cache');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const runtimeState = {
  sseClients: []
};

let cache = null;

const infrastructureReady = (async () => {
  await initSchema();
  const c = await createCache();
  cache = c.cache;
})().catch((err) => {
  if (require.main === module) {
    // eslint-disable-next-line no-console
    console.error('Failed to initialize infrastructure:', err.message);
    process.exit(1);
  }
  throw err;
});

function canAccessRole(user, allowed) {
  return user && allowed.includes(user.role);
}

function getClientIp(req) {
  return (
    req.headers['cf-connecting-ip'] ||
    String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.socket.remoteAddress ||
    'unknown'
  );
}

async function enforceRateLimit(req, res) {
  const windowSeconds = Number(process.env.RATE_LIMIT_WINDOW_SECONDS || 60);
  const maxRequests = Number(process.env.RATE_LIMIT_MAX || 120);
  const key = `rate:${getClientIp(req)}:${Math.floor(Date.now() / (windowSeconds * 1000))}`;
  const count = await cache.incr(key, windowSeconds);
  if (count > maxRequests) {
    sendJson(res, 429, { error: 'Too many requests' });
    return false;
  }
  return true;
}

async function authenticate(req) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return null;

  const cached = await cache.get(`session:${token}`);
  if (cached) {
    try {
      return JSON.parse(cached);
    } catch {
      // ignore parse failures
    }
  }

  try {
    const decoded = verifyToken(token);
    await cache.set(`session:${token}`, JSON.stringify(decoded), Number(process.env.SESSION_TTL_SECONDS || 28_800));
    return decoded;
  } catch {
    return null;
  }
}

function routeKey(method, pathname) {
  return `${method} ${pathname}`;
}

function getPathParams(pathname, pattern) {
  const current = pathname.split('/').filter(Boolean);
  const pat = pattern.split('/').filter(Boolean);
  if (current.length !== pat.length) return null;
  const params = {};
  for (let i = 0; i < pat.length; i += 1) {
    if (pat[i].startsWith(':')) {
      params[pat[i].slice(1)] = decodeURIComponent(current[i]);
    } else if (pat[i] !== current[i]) {
      return null;
    }
  }
  return params;
}

function writeSse(client, type, data) {
  client.res.write(`event: ${type}\n`);
  client.res.write(`data: ${JSON.stringify(data)}\n\n`);
}

async function addAudit(actorId, tenantId, action, payload = {}) {
  await pool.query(
    `INSERT INTO audit_logs (id, actor_id, tenant_id, action, payload_json, created_at)
     VALUES ($1, $2, $3, $4, $5::jsonb, $6::timestamptz)`,
    [randomId('audit'), actorId || null, tenantId || null, action, JSON.stringify(payload), nowIso()]
  );
}

function normalizeExamFromRow(row) {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    ownerId: row.owner_id,
    title: row.title,
    startAt: new Date(row.start_at).toISOString(),
    endAt: new Date(row.end_at).toISOString(),
    durationMinutes: Number(row.duration_minutes),
    negativeMarking: Number(row.negative_marking),
    sections: row.sections_json || []
  };
}

function normalizeAttemptFromRow(row) {
  return {
    id: row.id,
    examId: row.exam_id,
    tenantId: row.tenant_id,
    examineeId: row.examinee_id,
    startedAt: new Date(row.started_at).toISOString(),
    endsAt: new Date(row.ends_at).toISOString(),
    status: row.status,
    answers: row.answers_json || [],
    events: row.events_json || [],
    heartbeats: row.heartbeats_json || [],
    warnings: row.warnings_json || [],
    autoScore: row.auto_score_json,
    subjectiveScore: Number(row.subjective_score || 0),
    rubricScores: row.rubric_scores_json || [],
    examSnapshot: row.exam_snapshot_json
  };
}

function isExamOwner(user, exam) {
  return user.role === roles.SUPER_ADMIN || exam.ownerId === user.userId;
}

async function handleRequest(req, res) {
  await infrastructureReady;

  if (!(await enforceRateLimit(req, res))) return;

  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;
  const user = await authenticate(req);

  if (req.method === 'GET' && (pathname === '/' || pathname.startsWith('/public'))) {
    const relative = pathname === '/' ? '/index.html' : pathname.replace('/public', '');
    const filePath = path.join(PUBLIC_DIR, relative);
    if (!filePath.startsWith(PUBLIC_DIR) || !fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
      return sendJson(res, 404, { error: 'Not found' });
    }
    const ext = path.extname(filePath);
    const contentType = ext === '.js' ? 'application/javascript' : 'text/html';
    res.writeHead(200, {
      'Content-Type': `${contentType}; charset=utf-8`,
      'X-Forwarded-Proto': String(req.headers['x-forwarded-proto'] || 'http'),
      'X-Forwarded-Host': String(req.headers['x-forwarded-host'] || req.headers.host || ''),
      'X-Client-IP': getClientIp(req)
    });
    fs.createReadStream(filePath).pipe(res);
    return;
  }

  if (routeKey(req.method, pathname) === 'POST /api/auth/register') {
    const body = await parseJsonBody(req);
    const { tenantId, name, email, password, role } = body;
    if (!tenantId || !email || !password || !role) {
      return sendJson(res, 400, { error: 'tenantId, email, password, role are required' });
    }
    if (!Object.values(roles).includes(role)) return sendJson(res, 400, { error: 'Invalid role' });

    const safeEmail = String(email).toLowerCase();
    const existing = await pool.query('SELECT id FROM users WHERE tenant_id = $1 AND email = $2', [tenantId, safeEmail]);
    if (existing.rows.length) return sendJson(res, 409, { error: 'User already exists' });

    const created = {
      id: randomId('user'),
      tenantId,
      name: name || safeEmail.split('@')[0],
      email: safeEmail,
      role,
      passwordHash: hashPassword(password),
      accessCode: role === roles.EXAMINEE ? null : randomId('acc').slice(-8)
    };

    await pool.query(
      `INSERT INTO users (id, tenant_id, name, email, role, password_hash, access_code)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [created.id, created.tenantId, created.name, created.email, created.role, created.passwordHash, created.accessCode]
    );

    await addAudit(created.id, created.tenantId, 'auth.register', { role });
    return sendJson(res, 201, { id: created.id, email: created.email, role: created.role });
  }

  if (routeKey(req.method, pathname) === 'POST /api/auth/login') {
    const body = await parseJsonBody(req);
    const { tenantId, email, password } = body;
    const safeEmail = String(email || '').toLowerCase();
    const found = await pool.query(
      `SELECT id, tenant_id, role, email, password_hash
       FROM users WHERE tenant_id = $1 AND email = $2`,
      [tenantId, safeEmail]
    );

    const candidate = found.rows[0];
    if (!candidate || !verifyPassword(password, candidate.password_hash)) {
      return sendJson(res, 401, { error: 'Invalid credentials' });
    }

    const session = {
      userId: candidate.id,
      tenantId: candidate.tenant_id,
      role: candidate.role,
      email: candidate.email
    };
    const token = signToken(session);
    await cache.set(`session:${token}`, JSON.stringify(session), Number(process.env.SESSION_TTL_SECONDS || 28_800));
    await addAudit(candidate.id, candidate.tenant_id, 'auth.login', { ip: getClientIp(req) });

    return sendJson(res, 200, { token, role: candidate.role, userId: candidate.id });
  }

  if (routeKey(req.method, pathname) === 'POST /api/roster/import-csv') {
    if (!canAccessRole(user, [roles.SUPER_ADMIN, roles.EXAMINER])) return sendJson(res, 403, { error: 'Forbidden' });
    const body = await parseJsonBody(req);
    const { users: importedUsers, errors } = parseCsvUsers(body.csv, user.tenantId);

    const imported = [];
    await withTransaction(async (client) => {
      for (const candidate of importedUsers) {
        const result = await client.query(
          `INSERT INTO users (id, tenant_id, name, email, role, password_hash, access_code)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           ON CONFLICT (tenant_id, email) DO NOTHING
           RETURNING id, email, access_code`,
          [
            candidate.id,
            candidate.tenantId,
            candidate.name,
            candidate.email,
            candidate.role,
            candidate.passwordHash,
            candidate.accessCode
          ]
        );
        if (result.rows[0]) imported.push(result.rows[0]);
      }
    });

    await addAudit(user.userId, user.tenantId, 'roster.import', {
      imported: imported.length,
      rejected: errors.length
    });

    return sendJson(res, 200, {
      imported: imported.map((u) => ({ id: u.id, email: u.email, accessCode: u.access_code })),
      errors
    });
  }

  if (routeKey(req.method, pathname) === 'POST /api/exams') {
    if (!canAccessRole(user, [roles.SUPER_ADMIN, roles.EXAMINER])) return sendJson(res, 403, { error: 'Forbidden' });

    const body = await parseJsonBody(req);
    if (!body.title || !Array.isArray(body.sections) || !body.sections.length) {
      return sendJson(res, 400, { error: 'title and non-empty sections are required' });
    }

    const exam = {
      id: randomId('exam'),
      tenantId: user.tenantId,
      ownerId: user.userId,
      title: String(body.title),
      startAt: body.startAt || nowIso(),
      endAt: body.endAt || new Date(Date.now() + 3_600_000).toISOString(),
      durationMinutes: Number(body.durationMinutes || 60),
      negativeMarking: Number(body.negativeMarking || 0),
      sections: body.sections.map((section) => ({
        id: randomId('section'),
        title: section.title,
        timeLimitMinutes: Number(section.timeLimitMinutes || 0),
        randomCount: section.randomCount ? Number(section.randomCount) : null,
        shuffleQuestions: Boolean(section.shuffleQuestions),
        questions: (section.questions || []).map((q) => ({
          id: randomId('q'),
          type: q.type,
          prompt: q.prompt,
          latex: q.latex,
          options: q.options,
          leftItems: q.leftItems,
          rightItems: q.rightItems,
          shuffleOptions: Boolean(q.shuffleOptions),
          correct: q.correct,
          marks: Number(q.marks || 1),
          negativeMarks: q.negativeMarks,
          tolerance: q.tolerance
        }))
      }))
    };

    await pool.query(
      `INSERT INTO exams (id, tenant_id, owner_id, title, start_at, end_at, duration_minutes, negative_marking, sections_json)
       VALUES ($1, $2, $3, $4, $5::timestamptz, $6::timestamptz, $7, $8, $9::jsonb)`,
      [
        exam.id,
        exam.tenantId,
        exam.ownerId,
        exam.title,
        exam.startAt,
        exam.endAt,
        exam.durationMinutes,
        exam.negativeMarking,
        JSON.stringify(exam.sections)
      ]
    );

    await addAudit(user.userId, user.tenantId, 'exam.create', { examId: exam.id });
    return sendJson(res, 201, { examId: exam.id });
  }

  if (routeKey(req.method, pathname) === 'GET /api/exams') {
    if (!canAccessRole(user, [roles.SUPER_ADMIN, roles.EXAMINER])) return sendJson(res, 403, { error: 'Forbidden' });
    const rows = await pool.query(
      `SELECT id, title, start_at, end_at, duration_minutes
       FROM exams
       WHERE tenant_id = $1
       ORDER BY start_at DESC`,
      [user.tenantId]
    );
    return sendJson(res, 200, { exams: rows.rows });
  }

  const attemptStartParams = getPathParams(pathname, '/api/exams/:examId/attempts');
  if (attemptStartParams && req.method === 'POST') {
    if (!canAccessRole(user, [roles.EXAMINEE])) return sendJson(res, 403, { error: 'Forbidden' });

    const found = await pool.query(
      `SELECT * FROM exams WHERE id = $1 AND tenant_id = $2`,
      [attemptStartParams.examId, user.tenantId]
    );
    const row = found.rows[0];
    if (!row) return sendJson(res, 404, { error: 'Exam not found' });

    const exam = normalizeExamFromRow(row);
    const now = Date.now();
    if (now < new Date(exam.startAt).getTime() || now > new Date(exam.endAt).getTime()) {
      return sendJson(res, 400, { error: 'Exam outside schedule window' });
    }

    const body = await parseJsonBody(req);
    const candidateResult = await pool.query('SELECT access_code FROM users WHERE id = $1', [user.userId]);
    const candidate = candidateResult.rows[0];
    if (candidate?.access_code && body.accessCode !== candidate.access_code) {
      return sendJson(res, 403, { error: 'Valid access code is required' });
    }

    const attemptExam = randomizeExam(exam);
    const attempt = {
      id: randomId('attempt'),
      examId: exam.id,
      tenantId: user.tenantId,
      examineeId: user.userId,
      startedAt: nowIso(),
      endsAt: new Date(Date.now() + exam.durationMinutes * 60_000).toISOString(),
      answers: [],
      events: [],
      heartbeats: [],
      warnings: [],
      autoScore: null,
      subjectiveScore: 0,
      rubricScores: [],
      status: 'in_progress',
      examSnapshot: attemptExam
    };

    await pool.query(
      `INSERT INTO attempts
       (id, exam_id, tenant_id, examinee_id, started_at, ends_at, status, answers_json, events_json, heartbeats_json, warnings_json, auto_score_json, subjective_score, rubric_scores_json, exam_snapshot_json)
       VALUES
       ($1, $2, $3, $4, $5::timestamptz, $6::timestamptz, $7, $8::jsonb, $9::jsonb, $10::jsonb, $11::jsonb, $12::jsonb, $13, $14::jsonb, $15::jsonb)`,
      [
        attempt.id,
        attempt.examId,
        attempt.tenantId,
        attempt.examineeId,
        attempt.startedAt,
        attempt.endsAt,
        attempt.status,
        JSON.stringify(attempt.answers),
        JSON.stringify(attempt.events),
        JSON.stringify(attempt.heartbeats),
        JSON.stringify(attempt.warnings),
        null,
        attempt.subjectiveScore,
        JSON.stringify(attempt.rubricScores),
        JSON.stringify(attempt.examSnapshot)
      ]
    );

    await cache.set(`timer:${attempt.id}`, String(new Date(attempt.endsAt).getTime()), Math.ceil(exam.durationMinutes * 60));
    await addAudit(user.userId, user.tenantId, 'attempt.start', { attemptId: attempt.id, examId: exam.id });

    return sendJson(res, 201, { attemptId: attempt.id, exam: examViewForAttempt(attemptExam) });
  }

  const answerParams = getPathParams(pathname, '/api/attempts/:attemptId/answer');
  if (answerParams && req.method === 'POST') {
    if (!canAccessRole(user, [roles.EXAMINEE])) return sendJson(res, 403, { error: 'Forbidden' });
    const body = await parseJsonBody(req);
    if (!body.questionId) return sendJson(res, 400, { error: 'questionId is required' });

    const saved = await withTransaction(async (client) => {
      const current = await client.query(
        `SELECT answers_json, status, tenant_id FROM attempts WHERE id = $1 AND examinee_id = $2 FOR UPDATE`,
        [answerParams.attemptId, user.userId]
      );
      const attempt = current.rows[0];
      if (!attempt || attempt.status !== 'in_progress') return false;
      const answers = attempt.answers_json || [];
      const idx = answers.findIndex((a) => a.questionId === body.questionId);
      const entry = { questionId: body.questionId, value: body.value, answeredAt: nowIso() };
      if (idx >= 0) answers[idx] = entry;
      else answers.push(entry);
      await client.query(
        'UPDATE attempts SET answers_json = $2::jsonb, updated_at = now() WHERE id = $1',
        [answerParams.attemptId, JSON.stringify(answers)]
      );
      return { tenantId: attempt.tenant_id };
    });

    if (!saved) return sendJson(res, 404, { error: 'Attempt not active' });
    await addAudit(user.userId, saved.tenantId, 'attempt.answer', { attemptId: answerParams.attemptId, questionId: body.questionId });
    return sendJson(res, 200, { saved: true });
  }

  const heartbeatParams = getPathParams(pathname, '/api/attempts/:attemptId/heartbeat');
  if (heartbeatParams && req.method === 'POST') {
    if (!canAccessRole(user, [roles.EXAMINEE])) return sendJson(res, 403, { error: 'Forbidden' });
    const body = await parseJsonBody(req);

    const updated = await withTransaction(async (client) => {
      const current = await client.query(
        'SELECT heartbeats_json, tenant_id FROM attempts WHERE id = $1 AND examinee_id = $2 FOR UPDATE',
        [heartbeatParams.attemptId, user.userId]
      );
      const attempt = current.rows[0];
      if (!attempt) return null;
      const heartbeats = attempt.heartbeats_json || [];
      heartbeats.push({ at: nowIso(), online: body.online !== false });
      await client.query(
        'UPDATE attempts SET heartbeats_json = $2::jsonb, updated_at = now() WHERE id = $1',
        [heartbeatParams.attemptId, JSON.stringify(heartbeats)]
      );
      return attempt;
    });

    if (!updated) return sendJson(res, 404, { error: 'Attempt not found' });
    return sendJson(res, 200, { ok: true });
  }

  const snapshotParams = getPathParams(pathname, '/api/attempts/:attemptId/proctor-snapshot');
  if (snapshotParams && req.method === 'POST') {
    if (!canAccessRole(user, [roles.EXAMINEE])) return sendJson(res, 403, { error: 'Forbidden' });
    const body = await parseJsonBody(req);

    if (body.consent !== true) return sendJson(res, 400, { error: 'Webcam consent is required' });
    const dataUrl = String(body.imageData || '');
    const match = dataUrl.match(/^data:(image\/(jpeg|png));base64,([a-zA-Z0-9+/=]+)$/);
    if (!match) return sendJson(res, 400, { error: 'Invalid snapshot payload' });

    const base64 = match[3];
    if (base64.length > 450_000) return sendJson(res, 413, { error: 'Snapshot too large' });

    const attempt = await pool.query('SELECT id, tenant_id FROM attempts WHERE id = $1 AND examinee_id = $2', [
      snapshotParams.attemptId,
      user.userId
    ]);
    if (!attempt.rows[0]) return sendJson(res, 404, { error: 'Attempt not found' });

    await pool.query(
      `INSERT INTO proctor_snapshots (id, attempt_id, captured_at, mime_type, image_data_base64)
       VALUES ($1, $2, $3::timestamptz, $4, $5)`,
      [randomId('snap'), snapshotParams.attemptId, nowIso(), match[1], base64]
    );

    await addAudit(user.userId, attempt.rows[0].tenant_id, 'attempt.snapshot', { attemptId: snapshotParams.attemptId });
    return sendJson(res, 201, { stored: true });
  }

  const eventParams = getPathParams(pathname, '/api/attempts/:attemptId/events');
  if (eventParams && req.method === 'POST') {
    if (!canAccessRole(user, [roles.EXAMINEE])) return sendJson(res, 403, { error: 'Forbidden' });
    const body = await parseJsonBody(req);
    if (!body.type) return sendJson(res, 400, { error: 'type is required' });

    const eventId = randomId('evt');
    const updated = await withTransaction(async (client) => {
      const current = await client.query(
        'SELECT events_json, tenant_id FROM attempts WHERE id = $1 AND examinee_id = $2 FOR UPDATE',
        [eventParams.attemptId, user.userId]
      );
      const attempt = current.rows[0];
      if (!attempt) return null;
      const event = { id: eventId, at: nowIso(), type: body.type, details: body.details || {} };
      const events = attempt.events_json || [];
      events.push(event);
      await client.query('UPDATE attempts SET events_json = $2::jsonb, updated_at = now() WHERE id = $1', [
        eventParams.attemptId,
        JSON.stringify(events)
      ]);
      return { attempt, event };
    });

    if (!updated) return sendJson(res, 404, { error: 'Attempt not found' });
    await addAudit(user.userId, updated.attempt.tenant_id, 'attempt.event', {
      attemptId: eventParams.attemptId,
      type: updated.event.type
    });
    return sendJson(res, 201, { id: eventId });
  }

  const submitParams = getPathParams(pathname, '/api/attempts/:attemptId/submit');
  if (submitParams && req.method === 'POST') {
    if (!canAccessRole(user, [roles.EXAMINEE])) return sendJson(res, 403, { error: 'Forbidden' });

    const result = await withTransaction(async (client) => {
      const current = await client.query(
        'SELECT * FROM attempts WHERE id = $1 AND examinee_id = $2 FOR UPDATE',
        [submitParams.attemptId, user.userId]
      );
      const row = current.rows[0];
      if (!row) return null;
      const attempt = normalizeAttemptFromRow(row);
      const grade = computeAutoScore(attempt, attempt.examSnapshot);
      await client.query(
        `UPDATE attempts
         SET auto_score_json = $2::jsonb, status = 'submitted', updated_at = now()
         WHERE id = $1`,
        [submitParams.attemptId, JSON.stringify(grade)]
      );
      return { grade, tenantId: attempt.tenantId };
    });

    if (!result) return sendJson(res, 404, { error: 'Attempt not found' });
    await addAudit(user.userId, result.tenantId, 'attempt.submit', {
      attemptId: submitParams.attemptId,
      objectiveScore: result.grade.objectiveScore
    });

    return sendJson(res, 200, {
      objectiveScore: result.grade.objectiveScore,
      pendingManualGrading: result.grade.items.some((i) => !i.objective)
    });
  }

  const gradingParams = getPathParams(pathname, '/api/grading/attempts/:attemptId');
  if (gradingParams && req.method === 'POST') {
    if (!canAccessRole(user, [roles.SUPER_ADMIN, roles.EXAMINER])) return sendJson(res, 403, { error: 'Forbidden' });

    const body = await parseJsonBody(req);
    const rubricScores = Array.isArray(body.rubricScores) ? body.rubricScores : [];

    const graded = await withTransaction(async (client) => {
      const rowRes = await client.query(
        `SELECT a.*, e.owner_id
         FROM attempts a
         JOIN exams e ON e.id = a.exam_id
         WHERE a.id = $1 AND a.tenant_id = $2
         FOR UPDATE`,
        [gradingParams.attemptId, user.tenantId]
      );
      const row = rowRes.rows[0];
      if (!row) return null;

      const attempt = normalizeAttemptFromRow(row);
      const exam = { ownerId: row.owner_id };
      if (!isExamOwner(user, exam)) return { forbidden: true };

      const subjectiveScore = rubricScores.reduce((sum, item) => sum + Number(item.score || 0), 0);
      await client.query(
        `UPDATE attempts
         SET subjective_score = $2, rubric_scores_json = $3::jsonb, status = 'graded', updated_at = now()
         WHERE id = $1`,
        [gradingParams.attemptId, subjectiveScore, JSON.stringify(rubricScores)]
      );

      return {
        tenantId: attempt.tenantId,
        totalScore: Number(attempt.autoScore?.objectiveScore || 0) + subjectiveScore,
        subjectiveScore
      };
    });

    if (!graded) return sendJson(res, 404, { error: 'Attempt not found' });
    if (graded.forbidden) return sendJson(res, 403, { error: 'Forbidden by exam ownership' });

    await addAudit(user.userId, graded.tenantId, 'grading.manual', { attemptId: gradingParams.attemptId, rubricScores });
    return sendJson(res, 200, { totalScore: graded.totalScore, subjectiveScore: graded.subjectiveScore });
  }

  const stateParams = getPathParams(pathname, '/api/attempts/:attemptId/state');
  if (stateParams && req.method === 'GET') {
    const result = await pool.query(
      'SELECT tenant_id, ends_at, warnings_json FROM attempts WHERE id = $1',
      [stateParams.attemptId]
    );
    const attempt = result.rows[0];
    if (!attempt || attempt.tenant_id !== user?.tenantId) return sendJson(res, 404, { error: 'Attempt not found' });

    const cachedTimer = await cache.get(`timer:${stateParams.attemptId}`);
    const endsAtMs = cachedTimer ? Number(cachedTimer) : new Date(attempt.ends_at).getTime();
    if (!cachedTimer) {
      const ttl = Math.max(5, Math.ceil((endsAtMs - Date.now()) / 1000));
      await cache.set(`timer:${stateParams.attemptId}`, String(endsAtMs), ttl);
    }

    return sendJson(res, 200, {
      remainingSeconds: Math.max(0, Math.floor((endsAtMs - Date.now()) / 1000)),
      warnings: attempt.warnings_json || []
    });
  }

  if (routeKey(req.method, pathname) === 'GET /api/proctor/stream') {
    if (!canAccessRole(user, [roles.PROCTOR, roles.SUPER_ADMIN, roles.EXAMINEE])) return sendJson(res, 403, { error: 'Forbidden' });
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      Connection: 'keep-alive',
      'Cache-Control': 'no-cache'
    });

    const client = { id: randomId('sse'), tenantId: user.tenantId, res };
    runtimeState.sseClients.push(client);
    writeSse(client, 'connected', { ok: true });

    const heartbeat = setInterval(() => writeSse(client, 'ping', { at: nowIso() }), 20_000);

    req.on('close', () => {
      clearInterval(heartbeat);
      runtimeState.sseClients = runtimeState.sseClients.filter((c) => c.id !== client.id);
    });
    return;
  }

  const warningParams = getPathParams(pathname, '/api/proctor/warnings/:attemptId');
  if (warningParams && req.method === 'POST') {
    if (!canAccessRole(user, [roles.PROCTOR, roles.SUPER_ADMIN])) return sendJson(res, 403, { error: 'Forbidden' });

    const body = await parseJsonBody(req);
    const warning = { id: randomId('warn'), message: body.message || 'Policy warning', at: nowIso() };

    const updated = await withTransaction(async (client) => {
      const current = await client.query('SELECT warnings_json, tenant_id FROM attempts WHERE id = $1 FOR UPDATE', [
        warningParams.attemptId
      ]);
      const attempt = current.rows[0];
      if (!attempt || attempt.tenant_id !== user.tenantId) return null;
      const warnings = attempt.warnings_json || [];
      warnings.push(warning);
      await client.query('UPDATE attempts SET warnings_json = $2::jsonb, updated_at = now() WHERE id = $1', [
        warningParams.attemptId,
        JSON.stringify(warnings)
      ]);
      return attempt;
    });

    if (!updated) return sendJson(res, 404, { error: 'Attempt not found' });

    for (const client of runtimeState.sseClients.filter((c) => c.tenantId === user.tenantId)) {
      writeSse(client, 'proctor-warning', { attemptId: warningParams.attemptId, warning });
    }

    await addAudit(user.userId, user.tenantId, 'proctor.warning', {
      attemptId: warningParams.attemptId,
      warning: warning.message
    });
    return sendJson(res, 200, { sent: true });
  }

  const proctorAttemptParams = getPathParams(pathname, '/api/proctor/attempts/:attemptId');
  if (proctorAttemptParams && req.method === 'GET') {
    if (!canAccessRole(user, [roles.PROCTOR, roles.SUPER_ADMIN])) return sendJson(res, 403, { error: 'Forbidden' });
    const result = await pool.query('SELECT * FROM attempts WHERE id = $1 AND tenant_id = $2', [
      proctorAttemptParams.attemptId,
      user.tenantId
    ]);
    const row = result.rows[0];
    if (!row) return sendJson(res, 404, { error: 'Attempt not found' });

    const attempt = normalizeAttemptFromRow(row);
    return sendJson(res, 200, {
      attemptId: attempt.id,
      status: attempt.status,
      heartbeats: attempt.heartbeats,
      events: attempt.events,
      warnings: attempt.warnings
    });
  }

  const analyticsParams = getPathParams(pathname, '/api/analytics/exams/:examId/item-analysis');
  if (analyticsParams && req.method === 'GET') {
    if (!canAccessRole(user, [roles.SUPER_ADMIN, roles.EXAMINER])) return sendJson(res, 403, { error: 'Forbidden' });

    const examRes = await pool.query('SELECT owner_id FROM exams WHERE id = $1 AND tenant_id = $2', [
      analyticsParams.examId,
      user.tenantId
    ]);
    const exam = examRes.rows[0];
    if (!exam) return sendJson(res, 404, { error: 'Exam not found' });
    if (!isExamOwner(user, { ownerId: exam.owner_id })) return sendJson(res, 403, { error: 'Forbidden by exam ownership' });

    const attempts = await pool.query(
      `SELECT auto_score_json
       FROM attempts
       WHERE exam_id = $1 AND tenant_id = $2 AND status <> 'in_progress'`,
      [analyticsParams.examId, user.tenantId]
    );

    const rows = [];
    for (const attempt of attempts.rows) {
      for (const item of attempt.auto_score_json?.items || []) {
        rows.push({
          questionId: item.questionId,
          score: Number(item.score || 0),
          correct: item.correct === true ? 1 : 0
        });
      }
    }

    const grouped = {};
    for (const row of rows) {
      grouped[row.questionId] ||= { total: 0, attempts: 0, correct: 0 };
      grouped[row.questionId].total += row.score;
      grouped[row.questionId].attempts += 1;
      grouped[row.questionId].correct += row.correct;
    }

    const out = Object.entries(grouped).map(([questionId, agg]) => ({
      questionId,
      difficultyIndex: agg.attempts ? Number((agg.correct / agg.attempts).toFixed(3)) : 0,
      discriminationIndex: agg.attempts ? Number((agg.total / agg.attempts).toFixed(3)) : 0
    }));

    if (url.searchParams.get('format') === 'csv') {
      const csv = ['questionId,difficultyIndex,discriminationIndex']
        .concat(out.map((r) => `${r.questionId},${r.difficultyIndex},${r.discriminationIndex}`))
        .join('\n');
      res.writeHead(200, { 'Content-Type': 'text/csv; charset=utf-8' });
      return res.end(csv);
    }

    if (url.searchParams.get('format') === 'pdf') {
      const content = `Item Analysis Report\n\n${out
        .map((r) => `${r.questionId} | difficulty=${r.difficultyIndex} discrimination=${r.discriminationIndex}`)
        .join('\n')}`;
      res.writeHead(200, { 'Content-Type': 'application/pdf' });
      return res.end(Buffer.from(content));
    }

    return sendJson(res, 200, { items: out });
  }

  if (routeKey(req.method, pathname) === 'GET /api/audit-logs') {
    if (!canAccessRole(user, [roles.SUPER_ADMIN, roles.EXAMINER, roles.PROCTOR])) return sendJson(res, 403, { error: 'Forbidden' });
    const logs = await pool.query(
      `SELECT id, actor_id, action, payload_json, created_at
       FROM audit_logs
       WHERE tenant_id = $1
       ORDER BY created_at DESC`,
      [user.tenantId]
    );
    return sendJson(res, 200, { logs: logs.rows });
  }

  return sendJson(res, 404, { error: 'Route not found' });
}

function createServer() {
  return http.createServer((req, res) => {
    handleRequest(req, res).catch((err) => {
      sendJson(res, 500, { error: 'Internal server error', details: err.message });
    });
  });
}

if (require.main === module) {
  const port = Number(process.env.PORT || 3000);
  createServer().listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`Exam system running on http://localhost:${port}`);
  });
}

module.exports = {
  createServer,
  roles,
  state: runtimeState,
  infrastructureReady
};
