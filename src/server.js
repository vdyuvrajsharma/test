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
const {
  roles,
  state,
  addAudit,
  computeAutoScore,
  examViewForAttempt,
  randomizeExam,
  parseCsvUsers
} = require('./store');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');

function canAccessRole(user, allowed) {
  return user && allowed.includes(user.role);
}

function authenticate(req) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return null;
  try {
    return verifyToken(token);
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

async function handleRequest(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;
  const user = authenticate(req);

  if (req.method === 'GET' && (pathname === '/' || pathname.startsWith('/public'))) {
    const relative = pathname === '/' ? '/index.html' : pathname.replace('/public', '');
    const filePath = path.join(PUBLIC_DIR, relative);
    if (!filePath.startsWith(PUBLIC_DIR) || !fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
      return sendJson(res, 404, { error: 'Not found' });
    }
    const ext = path.extname(filePath);
    const contentType = ext === '.js' ? 'application/javascript' : 'text/html';
    res.writeHead(200, { 'Content-Type': `${contentType}; charset=utf-8` });
    fs.createReadStream(filePath).pipe(res);
    return;
  }

  if (routeKey(req.method, pathname) === 'POST /api/auth/register') {
    const body = await parseJsonBody(req);
    const { tenantId, name, email, password, role } = body;
    if (!tenantId || !email || !password || !role) {
      return sendJson(res, 400, { error: 'tenantId, email, password, role are required' });
    }
    if (!Object.values(roles).includes(role)) {
      return sendJson(res, 400, { error: 'Invalid role' });
    }

    const existing = state.users.find((u) => u.tenantId === tenantId && u.email === String(email).toLowerCase());
    if (existing) {
      return sendJson(res, 409, { error: 'User already exists' });
    }

    const created = {
      id: randomId('user'),
      tenantId,
      name: name || String(email).split('@')[0],
      email: String(email).toLowerCase(),
      role,
      passwordHash: hashPassword(password),
      accessCode: randomId('acc').slice(-8)
    };

    state.users.push(created);
    addAudit(created.id, 'auth.register', { tenantId, role });
    return sendJson(res, 201, { id: created.id, email: created.email, role: created.role });
  }

  if (routeKey(req.method, pathname) === 'POST /api/auth/login') {
    const body = await parseJsonBody(req);
    const { tenantId, email, password } = body;
    const candidate = state.users.find(
      (u) => u.tenantId === tenantId && u.email === String(email).toLowerCase()
    );
    if (!candidate || !verifyPassword(password, candidate.passwordHash)) {
      return sendJson(res, 401, { error: 'Invalid credentials' });
    }
    const token = signToken({
      userId: candidate.id,
      tenantId: candidate.tenantId,
      role: candidate.role,
      email: candidate.email
    });
    addAudit(candidate.id, 'auth.login', {});
    return sendJson(res, 200, { token, role: candidate.role, userId: candidate.id });
  }

  if (routeKey(req.method, pathname) === 'POST /api/roster/import-csv') {
    if (!canAccessRole(user, [roles.SUPER_ADMIN, roles.EXAMINER])) {
      return sendJson(res, 403, { error: 'Forbidden' });
    }
    const body = await parseJsonBody(req);
    const csvText = String(body.csv || '');
    const imported = parseCsvUsers(csvText, user.tenantId);

    for (const candidate of imported) {
      if (!state.users.find((u) => u.tenantId === candidate.tenantId && u.email === candidate.email)) {
        state.users.push(candidate);
      }
    }

    addAudit(user.userId, 'roster.import', { count: imported.length });
    return sendJson(res, 200, {
      imported: imported.map((u) => ({ id: u.id, email: u.email, accessCode: u.accessCode }))
    });
  }

  if (routeKey(req.method, pathname) === 'POST /api/exams') {
    if (!canAccessRole(user, [roles.SUPER_ADMIN, roles.EXAMINER])) {
      return sendJson(res, 403, { error: 'Forbidden' });
    }

    const body = await parseJsonBody(req);
    if (!body.title || !Array.isArray(body.sections)) {
      return sendJson(res, 400, { error: 'title and sections are required' });
    }

    const exam = {
      id: randomId('exam'),
      tenantId: user.tenantId,
      title: body.title,
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
          shuffleOptions: Boolean(q.shuffleOptions),
          correct: q.correct,
          marks: Number(q.marks || 1),
          negativeMarks: q.negativeMarks,
          tolerance: q.tolerance
        }))
      }))
    };

    state.exams.push(exam);
    addAudit(user.userId, 'exam.create', { examId: exam.id });
    return sendJson(res, 201, { examId: exam.id });
  }

  const attemptStartParams = getPathParams(pathname, '/api/exams/:examId/attempts');
  if (attemptStartParams && req.method === 'POST') {
    if (!canAccessRole(user, [roles.EXAMINEE])) {
      return sendJson(res, 403, { error: 'Forbidden' });
    }
    const exam = state.exams.find((e) => e.id === attemptStartParams.examId && e.tenantId === user.tenantId);
    if (!exam) return sendJson(res, 404, { error: 'Exam not found' });

    const now = Date.now();
    if (now < new Date(exam.startAt).getTime() || now > new Date(exam.endAt).getTime()) {
      return sendJson(res, 400, { error: 'Exam outside schedule window' });
    }

    const body = await parseJsonBody(req);
    const candidate = state.users.find((u) => u.id === user.userId);
    if (candidate.accessCode && body.accessCode !== candidate.accessCode) {
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
      status: 'in_progress',
      examSnapshot: attemptExam
    };

    state.attempts.push(attempt);
    addAudit(user.userId, 'attempt.start', { attemptId: attempt.id, examId: exam.id });
    return sendJson(res, 201, { attemptId: attempt.id, exam: examViewForAttempt(attemptExam) });
  }

  const answerParams = getPathParams(pathname, '/api/attempts/:attemptId/answer');
  if (answerParams && req.method === 'POST') {
    if (!canAccessRole(user, [roles.EXAMINEE])) return sendJson(res, 403, { error: 'Forbidden' });
    const body = await parseJsonBody(req);
    const attempt = state.attempts.find((a) => a.id === answerParams.attemptId && a.examineeId === user.userId);
    if (!attempt || attempt.status !== 'in_progress') return sendJson(res, 404, { error: 'Attempt not active' });
    const idx = attempt.answers.findIndex((a) => a.questionId === body.questionId);
    const entry = { questionId: body.questionId, value: body.value, answeredAt: nowIso() };
    if (idx >= 0) attempt.answers[idx] = entry;
    else attempt.answers.push(entry);
    addAudit(user.userId, 'attempt.answer', { attemptId: attempt.id, questionId: body.questionId });
    return sendJson(res, 200, { saved: true });
  }

  const heartbeatParams = getPathParams(pathname, '/api/attempts/:attemptId/heartbeat');
  if (heartbeatParams && req.method === 'POST') {
    if (!canAccessRole(user, [roles.EXAMINEE])) return sendJson(res, 403, { error: 'Forbidden' });
    const body = await parseJsonBody(req);
    const attempt = state.attempts.find((a) => a.id === heartbeatParams.attemptId && a.examineeId === user.userId);
    if (!attempt) return sendJson(res, 404, { error: 'Attempt not found' });
    attempt.heartbeats.push({ at: nowIso(), online: body.online !== false, webcamSnapshot: body.webcamSnapshot || null });
    return sendJson(res, 200, { ok: true });
  }

  const eventParams = getPathParams(pathname, '/api/attempts/:attemptId/events');
  if (eventParams && req.method === 'POST') {
    if (!canAccessRole(user, [roles.EXAMINEE])) return sendJson(res, 403, { error: 'Forbidden' });
    const body = await parseJsonBody(req);
    const attempt = state.attempts.find((a) => a.id === eventParams.attemptId && a.examineeId === user.userId);
    if (!attempt) return sendJson(res, 404, { error: 'Attempt not found' });
    const event = { id: randomId('evt'), at: nowIso(), type: body.type, details: body.details || {} };
    attempt.events.push(event);
    addAudit(user.userId, 'attempt.event', { attemptId: attempt.id, type: event.type });
    return sendJson(res, 201, { id: event.id });
  }

  const submitParams = getPathParams(pathname, '/api/attempts/:attemptId/submit');
  if (submitParams && req.method === 'POST') {
    if (!canAccessRole(user, [roles.EXAMINEE])) return sendJson(res, 403, { error: 'Forbidden' });
    const attempt = state.attempts.find((a) => a.id === submitParams.attemptId && a.examineeId === user.userId);
    if (!attempt) return sendJson(res, 404, { error: 'Attempt not found' });

    const exam = attempt.examSnapshot;
    const grade = computeAutoScore(attempt, exam);
    attempt.autoScore = grade;
    attempt.status = 'submitted';
    addAudit(user.userId, 'attempt.submit', { attemptId: attempt.id, objectiveScore: grade.objectiveScore });

    return sendJson(res, 200, {
      objectiveScore: grade.objectiveScore,
      pendingManualGrading: grade.items.some((i) => !i.objective)
    });
  }

  const gradingParams = getPathParams(pathname, '/api/grading/attempts/:attemptId');
  if (gradingParams && req.method === 'POST') {
    if (!canAccessRole(user, [roles.SUPER_ADMIN, roles.EXAMINER])) {
      return sendJson(res, 403, { error: 'Forbidden' });
    }
    const attempt = state.attempts.find((a) => a.id === gradingParams.attemptId && a.tenantId === user.tenantId);
    if (!attempt) return sendJson(res, 404, { error: 'Attempt not found' });
    const body = await parseJsonBody(req);
    const rubricScores = Array.isArray(body.rubricScores) ? body.rubricScores : [];
    attempt.subjectiveScore = rubricScores.reduce((sum, item) => sum + Number(item.score || 0), 0);
    attempt.status = 'graded';
    addAudit(user.userId, 'grading.manual', { attemptId: attempt.id, rubricScores });
    return sendJson(res, 200, {
      totalScore: (attempt.autoScore?.objectiveScore || 0) + attempt.subjectiveScore,
      subjectiveScore: attempt.subjectiveScore
    });
  }

  const stateParams = getPathParams(pathname, '/api/attempts/:attemptId/state');
  if (stateParams && req.method === 'GET') {
    const attempt = state.attempts.find((a) => a.id === stateParams.attemptId);
    if (!attempt || attempt.tenantId !== user?.tenantId) return sendJson(res, 404, { error: 'Attempt not found' });
    return sendJson(res, 200, {
      remainingSeconds: Math.max(0, Math.floor((new Date(attempt.endsAt).getTime() - Date.now()) / 1000)),
      warnings: attempt.warnings
    });
  }

  if (routeKey(req.method, pathname) === 'GET /api/proctor/stream') {
    if (!canAccessRole(user, [roles.PROCTOR, roles.SUPER_ADMIN, roles.EXAMINEE])) {
      return sendJson(res, 403, { error: 'Forbidden' });
    }
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      Connection: 'keep-alive',
      'Cache-Control': 'no-cache'
    });

    const client = { id: randomId('sse'), tenantId: user.tenantId, res };
    state.sseClients.push(client);
    writeSse(client, 'connected', { ok: true });

    req.on('close', () => {
      state.sseClients = state.sseClients.filter((c) => c.id !== client.id);
    });
    return;
  }

  const warningParams = getPathParams(pathname, '/api/proctor/warnings/:attemptId');
  if (warningParams && req.method === 'POST') {
    if (!canAccessRole(user, [roles.PROCTOR, roles.SUPER_ADMIN])) return sendJson(res, 403, { error: 'Forbidden' });
    const attempt = state.attempts.find((a) => a.id === warningParams.attemptId && a.tenantId === user.tenantId);
    if (!attempt) return sendJson(res, 404, { error: 'Attempt not found' });
    const body = await parseJsonBody(req);
    const warning = { id: randomId('warn'), message: body.message || 'Policy warning', at: nowIso() };
    attempt.warnings.push(warning);

    for (const client of state.sseClients.filter((c) => c.tenantId === user.tenantId)) {
      writeSse(client, 'proctor-warning', { attemptId: attempt.id, warning });
    }

    addAudit(user.userId, 'proctor.warning', { attemptId: attempt.id, warning: warning.message });
    return sendJson(res, 200, { sent: true });
  }

  const proctorAttemptParams = getPathParams(pathname, '/api/proctor/attempts/:attemptId');
  if (proctorAttemptParams && req.method === 'GET') {
    if (!canAccessRole(user, [roles.PROCTOR, roles.SUPER_ADMIN])) return sendJson(res, 403, { error: 'Forbidden' });
    const attempt = state.attempts.find((a) => a.id === proctorAttemptParams.attemptId && a.tenantId === user.tenantId);
    if (!attempt) return sendJson(res, 404, { error: 'Attempt not found' });
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
    const attempts = state.attempts.filter((a) => a.examId === analyticsParams.examId && a.status !== 'in_progress');
    const rows = [];

    for (const attempt of attempts) {
      for (const item of attempt.autoScore?.items || []) {
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
    if (!canAccessRole(user, [roles.SUPER_ADMIN, roles.EXAMINER, roles.PROCTOR])) {
      return sendJson(res, 403, { error: 'Forbidden' });
    }
    return sendJson(res, 200, {
      logs: state.auditLogs.filter((log) => {
        const actor = log.actorId ? state.users.find((u) => u.id === log.actorId) : null;
        return !actor || actor.tenantId === user.tenantId;
      })
    });
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

module.exports = { createServer, state, roles };
