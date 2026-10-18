const { nowIso, randomId, shuffle } = require('./utils');

const roles = {
  SUPER_ADMIN: 'super_admin',
  EXAMINER: 'examiner',
  PROCTOR: 'proctor',
  EXAMINEE: 'examinee'
};

const state = {
  users: [],
  exams: [],
  attempts: [],
  auditLogs: [],
  sseClients: []
};

function addAudit(actorId, action, payload = {}) {
  const entry = {
    id: randomId('audit'),
    actorId: actorId || null,
    action,
    payload,
    createdAt: nowIso()
  };
  state.auditLogs.push(entry);
  return entry;
}

function computeAutoScore(attempt, exam) {
  const answerMap = new Map(attempt.answers.map((a) => [a.questionId, a.value]));
  let score = 0;
  const items = [];

  for (const section of exam.sections) {
    for (const q of section.questions) {
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
        correct = Math.abs(Number(provided) - Number(q.correct)) <= tolerance;
      } else if (q.type === 'matching') {
        correct = JSON.stringify(provided || {}) === JSON.stringify(q.correct || {});
      }

      const itemScore = correct ? mark : provided !== undefined ? -Math.abs(negative) : 0;
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
    sections: exam.sections.map((section) => ({
      id: section.id,
      title: section.title,
      timeLimitMinutes: section.timeLimitMinutes,
      questions: section.questions.map((q) => ({
        id: q.id,
        type: q.type,
        prompt: q.prompt,
        latex: q.latex || null,
        options: q.options || null,
        marks: q.marks || 1
      }))
    }))
  };
}

function randomizeExam(exam) {
  const cloned = JSON.parse(JSON.stringify(exam));
  cloned.sections = cloned.sections.map((section) => {
    let questions = [...section.questions];
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
  const lines = csvText
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  if (lines.length < 2) return [];
  const headers = lines[0].split(',').map((h) => h.trim().toLowerCase());
  const nameIdx = headers.indexOf('name');
  const emailIdx = headers.indexOf('email');
  const users = [];

  for (const line of lines.slice(1)) {
    const cols = line.split(',').map((c) => c.trim());
    if (!cols[emailIdx]) continue;
    users.push({
      id: randomId('user'),
      tenantId,
      name: cols[nameIdx] || 'Unnamed Candidate',
      email: cols[emailIdx].toLowerCase(),
      role: roles.EXAMINEE,
      passwordHash: null,
      accessCode: randomId('acc').slice(-8)
    });
  }
  return users;
}

module.exports = {
  roles,
  state,
  addAudit,
  computeAutoScore,
  examViewForAttempt,
  randomizeExam,
  parseCsvUsers
};
