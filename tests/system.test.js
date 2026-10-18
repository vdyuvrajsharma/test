const test = require('node:test');
const assert = require('node:assert/strict');

const { createServer, state, roles } = require('../src/server');

async function request(baseUrl, path, method = 'GET', token = null, body = null) {
  const res = await fetch(`${baseUrl}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: 'Bearer ' + token } : {})
    },
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await res.json();
  return { status: res.status, data };
}

test('auth + exam + attempt + grading flow', async () => {
  state.users.length = 0;
  state.exams.length = 0;
  state.attempts.length = 0;
  state.auditLogs.length = 0;

  const server = createServer();
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;

  try {
    const adminReg = await request(base, '/api/auth/register', 'POST', null, {
      tenantId: 'demo',
      name: 'Admin',
      email: 'admin@demo.com',
      password: 'Pass@123',
      role: roles.EXAMINER
    });
    assert.equal(adminReg.status, 201);

    const studentReg = await request(base, '/api/auth/register', 'POST', null, {
      tenantId: 'demo',
      name: 'Student',
      email: 'student@demo.com',
      password: 'Pass@123',
      role: roles.EXAMINEE
    });
    assert.equal(studentReg.status, 201);

    const adminLogin = await request(base, '/api/auth/login', 'POST', null, {
      tenantId: 'demo',
      email: 'admin@demo.com',
      password: 'Pass@123'
    });
    assert.equal(adminLogin.status, 200);

    const createExam = await request(base, '/api/exams', 'POST', adminLogin.data.token, {
      title: 'Sample Test',
      durationMinutes: 30,
      negativeMarking: 0.25,
      sections: [
        {
          title: 'Math',
          shuffleQuestions: true,
          questions: [
            {
              type: 'mcq',
              prompt: '2 + 2 = ?',
              options: [
                { label: '3', value: '3' },
                { label: '4', value: '4' }
              ],
              correct: '4',
              marks: 1
            },
            {
              type: 'subjective',
              prompt: 'Explain Pythagoras theorem',
              marks: 5
            }
          ]
        }
      ]
    });
    assert.equal(createExam.status, 201);

    const studentLogin = await request(base, '/api/auth/login', 'POST', null, {
      tenantId: 'demo',
      email: 'student@demo.com',
      password: 'Pass@123'
    });
    assert.equal(studentLogin.status, 200);

    const startAttempt = await request(
      base,
      `/api/exams/${createExam.data.examId}/attempts`,
      'POST',
      studentLogin.data.token,
      { accessCode: state.users.find((u) => u.email === 'student@demo.com').accessCode }
    );
    assert.equal(startAttempt.status, 201);

    const objectiveQ = startAttempt.data.exam.sections[0].questions.find((q) => q.type === 'mcq');
    const saveAnswer = await request(
      base,
      `/api/attempts/${startAttempt.data.attemptId}/answer`,
      'POST',
      studentLogin.data.token,
      { questionId: objectiveQ.id, value: '4' }
    );
    assert.equal(saveAnswer.status, 200);

    const submit = await request(
      base,
      `/api/attempts/${startAttempt.data.attemptId}/submit`,
      'POST',
      studentLogin.data.token,
      {}
    );
    assert.equal(submit.status, 200);
    assert.equal(submit.data.objectiveScore, 1);
    assert.equal(submit.data.pendingManualGrading, true);

    const grade = await request(
      base,
      `/api/grading/attempts/${startAttempt.data.attemptId}`,
      'POST',
      adminLogin.data.token,
      { rubricScores: [{ questionId: 'subjective', score: 4 }] }
    );
    assert.equal(grade.status, 200);
    assert.equal(grade.data.totalScore, 5);

    const analytics = await request(
      base,
      `/api/analytics/exams/${createExam.data.examId}/item-analysis`,
      'GET',
      adminLogin.data.token
    );
    assert.equal(analytics.status, 200);
    assert.ok(Array.isArray(analytics.data.items));
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
