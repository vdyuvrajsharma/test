const authEl = document.getElementById('auth');
const examEl = document.getElementById('exam');
const authMsg = document.getElementById('authMsg');
const warningEl = document.getElementById('warning');
const clockEl = document.getElementById('clock');

let token = null;
let attemptId = null;
let exam = null;
let questionIndex = 0;

const storageKey = () => `attempt_cache_${attemptId || 'pending'}`;

function api(path, method = 'GET', body) {
  return fetch(path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: 'Bearer ' + token } : {})
    },
    body: body ? JSON.stringify(body) : undefined
  }).then(async (res) => {
    const contentType = res.headers.get('content-type') || '';
    const data = contentType.includes('application/json') ? await res.json() : await res.text();
    if (!res.ok) throw new Error(data.error || res.statusText);
    return data;
  });
}

function flattenQuestions() {
  return exam.sections.flatMap((s) => s.questions.map((q) => ({ ...q, sectionTitle: s.title })));
}

function render() {
  const questions = flattenQuestions();
  const q = questions[questionIndex];
  if (!q) return;

  document.getElementById('examTitle').textContent = exam.title;
  document.getElementById('sectionTitle').textContent = q.sectionTitle;
  document.getElementById('question').innerHTML = `<strong>Q${questionIndex + 1}.</strong> ${q.prompt}${
    q.latex ? `<div>\\(${q.latex}\\)</div>` : ''
  }`;

  const optionsEl = document.getElementById('options');
  optionsEl.innerHTML = '';

  if (Array.isArray(q.options)) {
    q.options.forEach((opt) => {
      const line = document.createElement('div');
      line.innerHTML = `<label><input type="radio" name="answer" value="${opt.value}" /> ${opt.label}</label>`;
      optionsEl.appendChild(line);
    });
  } else if (q.type === 'numerical') {
    optionsEl.innerHTML = '<input id="numericAns" placeholder="Enter numerical value" />';
  } else if (q.type === 'subjective') {
    optionsEl.innerHTML = '<textarea id="essayAns" rows="6" style="width:100%" placeholder="Type answer"></textarea>';
  }

  const palette = document.getElementById('palette');
  palette.innerHTML = '';
  questions.forEach((_, idx) => {
    const btn = document.createElement('button');
    btn.className = `question-btn ${idx === questionIndex ? 'active' : ''}`;
    btn.textContent = String(idx + 1);
    btn.onclick = () => {
      questionIndex = idx;
      render();
    };
    palette.appendChild(btn);
  });
}

function readCurrentAnswer() {
  const q = flattenQuestions()[questionIndex];
  if (Array.isArray(q.options)) {
    const selected = document.querySelector('input[name="answer"]:checked');
    return selected?.value;
  }
  if (q.type === 'numerical') return document.getElementById('numericAns')?.value;
  if (q.type === 'subjective') return document.getElementById('essayAns')?.value;
  return null;
}

async function sendEvent(type, details = {}) {
  if (!attemptId) return;
  try {
    await api(`/api/attempts/${attemptId}/events`, 'POST', { type, details });
  } catch (_) {}
}

async function sendHeartbeat() {
  if (!attemptId) return;
  let webcamSnapshot = null;
  if (navigator.mediaDevices?.getUserMedia) {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: false });
      const track = stream.getVideoTracks()[0];
      const imageCapture = new ImageCapture(track);
      const bitmap = await imageCapture.grabFrame();
      const canvas = document.createElement('canvas');
      canvas.width = 120;
      canvas.height = 90;
      canvas.getContext('2d').drawImage(bitmap, 0, 0, 120, 90);
      webcamSnapshot = canvas.toDataURL('image/jpeg', 0.5);
      track.stop();
    } catch (_) {}
  }
  try {
    await api(`/api/attempts/${attemptId}/heartbeat`, 'POST', { online: navigator.onLine, webcamSnapshot });
  } catch (_) {}
}

async function syncClock() {
  if (!attemptId) return;
  try {
    const state = await api(`/api/attempts/${attemptId}/state`);
    const mins = String(Math.floor(state.remainingSeconds / 60)).padStart(2, '0');
    const secs = String(state.remainingSeconds % 60).padStart(2, '0');
    clockEl.textContent = `${mins}:${secs}`;
    if (state.warnings?.length) {
      warningEl.textContent = state.warnings[state.warnings.length - 1].message;
    }
  } catch (_) {}
}

function persistOfflineCache() {
  localStorage.setItem(storageKey(), JSON.stringify({ exam, attemptId, questionIndex, savedAt: Date.now() }));
}

function blockExamShortcuts() {
  document.addEventListener('contextmenu', (e) => e.preventDefault());
  ['copy', 'cut', 'paste'].forEach((evt) => {
    document.addEventListener(evt, (e) => {
      e.preventDefault();
      sendEvent('clipboard_violation', { event: evt });
    });
  });

  window.addEventListener('blur', () => sendEvent('window_blur'));
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) sendEvent('tab_switch');
  });

  document.addEventListener('fullscreenchange', () => {
    if (!document.fullscreenElement) {
      sendEvent('fullscreen_exit');
      warningEl.textContent = 'Full-screen mode is required during exam.';
    }
  });
}

document.getElementById('loginBtn').onclick = async () => {
  try {
    authMsg.textContent = '';
    const tenantId = document.getElementById('tenant').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const examId = document.getElementById('examId').value;

    const login = await api('/api/auth/login', 'POST', { tenantId, email, password });
    token = login.token;

    const started = await api(`/api/exams/${examId}/attempts`, 'POST', {});
    attemptId = started.attemptId;
    exam = started.exam;

    await document.documentElement.requestFullscreen?.();
    authEl.classList.add('hidden');
    examEl.classList.remove('hidden');
    blockExamShortcuts();
    render();

    setInterval(syncClock, 1_000);
    setInterval(sendHeartbeat, 30_000);
    setInterval(persistOfflineCache, 5_000);

    const events = new EventSource('/api/proctor/stream', { withCredentials: false });
    events.onmessage = () => {};
    events.addEventListener('proctor-warning', (ev) => {
      const data = JSON.parse(ev.data);
      if (data.attemptId === attemptId) {
        warningEl.textContent = data.warning.message;
      }
    });
  } catch (err) {
    authMsg.textContent = err.message;
  }
};

document.getElementById('saveNext').onclick = async () => {
  const questions = flattenQuestions();
  const q = questions[questionIndex];
  const value = readCurrentAnswer();
  await api(`/api/attempts/${attemptId}/answer`, 'POST', { questionId: q.id, value });
  questionIndex = Math.min(questionIndex + 1, questions.length - 1);
  render();
};

document.getElementById('submitExam').onclick = async () => {
  persistOfflineCache();
  const result = await api(`/api/attempts/${attemptId}/submit`, 'POST', {});
  alert(`Submitted. Objective score: ${result.objectiveScore}`);
  await sendEvent('exam_submitted');
};
