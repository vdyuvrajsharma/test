const { nowIso, randomId, shuffle } = require('./utils');

const roles = {
  SUPER_ADMIN: 'super_admin',
  EXAMINER: 'examiner',
  PROCTOR: 'proctor',
  EXAMINEE: 'examinee'
};

function normalizeMatching(value = {}) {
  return Object.keys(value)
    .sort()
    .reduce((acc, key) => {
      acc[key] = value[key];
      return acc;
    }, {});
}

function computeAutoScore(attempt, exam) {
  const answerMap = new Map((attempt.answers || []).map((a) => [a.questionId, a.value]));
  let score = 0;
  const items = [];

  for (const section of exam.sections || []) {
    for (const q of section.questions || []) {
      const provided = answerMap.get(q.id);
      if (q.type === 'subjective') {
        items.push({ questionId: q.id, objective: false, score: null });
        continue;
      }

      const mark = Number(q.marks || 1);
      const negative = Number(q.negativeMarks ?? exam.negativeMarking ?? 0);
      let correct = false;

      if (q.type === 'mcq') {
        correct = provided === q.correct;
      } else if (q.type === 'multi') {
        const p = Array.isArray(provided) ? [...provided].sort() : [];
        const c = Array.isArray(q.correct) ? [...q.correct].sort() : [];
        correct = JSON.stringify(p) === JSON.stringify(c);
      } else if (q.type === 'numerical') {
        const tolerance = Number(q.tolerance || 0);
        const num = Number(provided);
        correct = Number.isFinite(num) && Math.abs(num - Number(q.correct)) <= tolerance;
      } else if (q.type === 'matching') {
        correct = JSON.stringify(normalizeMatching(provided || {})) === JSON.stringify(normalizeMatching(q.correct || {}));
      }

      const itemScore = correct ? mark : provided !== undefined && provided !== null && provided !== '' ? -Math.abs(negative) : 0;
      score += itemScore;
      items.push({ questionId: q.id, objective: true, score: itemScore, correct });
    }
  }

  return { objectiveScore: score, items };
}

function examViewForAttempt(exam) {
  return {
    id: exam.id,
    tenantId: exam.tenantId,
    title: exam.title,
    startAt: exam.startAt,
    endAt: exam.endAt,
    durationMinutes: exam.durationMinutes,
    sections: (exam.sections || []).map((section) => ({
      id: section.id,
      title: section.title,
      timeLimitMinutes: section.timeLimitMinutes,
      questions: (section.questions || []).map((q) => ({
        id: q.id,
        type: q.type,
        prompt: q.prompt,
        latex: q.latex || null,
        options: q.options || null,
        leftItems: q.leftItems || null,
        rightItems: q.rightItems || null,
        marks: q.marks || 1
      }))
    }))
  };
}

function randomizeExam(exam) {
  const cloned = JSON.parse(JSON.stringify(exam));
  cloned.sections = (cloned.sections || []).map((section) => {
    let questions = [...(section.questions || [])];
    if (section.randomCount && section.randomCount < questions.length) {
      questions = shuffle(questions).slice(0, section.randomCount);
    }
    if (section.shuffleQuestions) {
      questions = shuffle(questions);
    }
    questions = questions.map((q) => {
      if (Array.isArray(q.options) && q.shuffleOptions) {
        q.options = shuffle(q.options);
      }
      return q;
    });
    return { ...section, questions };
  });
  return cloned;
}

function parseCsvUsers(csvText, tenantId) {
  const lines = String(csvText || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  if (lines.length < 2) return { users: [], errors: [{ row: 0, error: 'CSV must include header and at least one record' }] };

  const headers = lines[0].split(',').map((h) => h.trim().toLowerCase());
  const nameIdx = headers.indexOf('name');
  const emailIdx = headers.indexOf('email');
  const users = [];
  const errors = [];
  const seen = new Set();

  if (emailIdx < 0) return { users: [], errors: [{ row: 0, error: 'Missing required email column' }] };

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  lines.slice(1).forEach((line, rowOffset) => {
    const row = rowOffset + 2;
    const cols = line.split(',').map((c) => c.trim());
    const email = (cols[emailIdx] || '').toLowerCase();
    if (!emailRegex.test(email)) {
      errors.push({ row, error: 'Invalid email format' });
      return;
    }
    const key = `${tenantId}:${email}`;
    if (seen.has(key)) {
      errors.push({ row, error: 'Duplicate email in upload' });
      return;
    }
    seen.add(key);
    users.push({
      id: randomId('user'),
      tenantId,
      name: cols[nameIdx] || 'Unnamed Candidate',
      email,
      role: roles.EXAMINEE,
      passwordHash: null,
      accessCode: randomId('acc').slice(-8),
      createdAt: nowIso()
    });
  });

  return { users, errors };
}

module.exports = {
  roles,
  computeAutoScore,
  examViewForAttempt,
  randomizeExam,
  parseCsvUsers
};
