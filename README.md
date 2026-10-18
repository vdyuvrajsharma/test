# Full Examination System (Node.js)

This repository now includes a runnable, multi-tenant online examination system with:

- JWT-based authentication + RBAC (`super_admin`, `examiner`, `proctor`, `examinee`)
- Exam + section builder (timed sections, randomization, shuffling, schedule windows, negative marking)
- Question bank support for `mcq`, `multi`, `numerical`, `matching`, and `subjective`
- NTA-style exam attempt UI with fullscreen enforcement, blur/tab/copy-paste/right-click telemetry
- Heartbeat logging (with optional webcam snapshot) and proctor warning broadcast stream
- Objective auto-grading + manual rubric grading for subjective responses
- Candidate roster CSV bulk import with generated secure access codes
- Immutable audit logs and item-analysis exports (`json`, `csv`, `pdf` response)

## Run

```bash
npm start
```

Open: `http://localhost:3000`

## Test

```bash
npm test
```
