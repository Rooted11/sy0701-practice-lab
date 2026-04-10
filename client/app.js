const state = {
  questions: [],
  answers: [],
  currentIndex: 0,
  startTime: null,
  timerId: null
};

const els = {
  fileInput: document.getElementById("fileInput"),
  loadFileBtn: document.getElementById("loadFileBtn"),
  importStatus: document.getElementById("importStatus"),
  quizPanel: document.getElementById("quizPanel"),
  resultPanel: document.getElementById("resultPanel"),
  progressText: document.getElementById("progressText"),
  timerText: document.getElementById("timerText"),
  scoreLive: document.getElementById("scoreLive"),
  questionCard: document.getElementById("questionCard"),
  prevBtn: document.getElementById("prevBtn"),
  nextBtn: document.getElementById("nextBtn"),
  finishBtn: document.getElementById("finishBtn"),
  resultSummary: document.getElementById("resultSummary"),
  reviewList: document.getElementById("reviewList"),
  restartBtn: document.getElementById("restartBtn"),
  statTotal: document.getElementById("statTotal"),
  statAnswered: document.getElementById("statAnswered"),
  statKnown: document.getElementById("statKnown"),
  sessionMeterFill: document.getElementById("sessionMeterFill"),
  sessionMeterLabel: document.getElementById("sessionMeterLabel"),
  exportBtn: document.getElementById("exportBtn"),
  resetProgressBtn: document.getElementById("resetProgressBtn")
};

const root = document.documentElement;
let statusPulseTimer = null;

const pbqListEl = document.getElementById("pbqList");
const practicalPBQs = [
  {
    id: "pbq1",
    title: "Contain suspicious SSH access",
    scenario:
      "An admin reports repeated brute-force failures against a jump host. Your goal is to stop the attack without disrupting the entire network.",
    steps: [
      "Identify the offending IP range in the logs and confirm it is external.",
      "Block the IP(s) at the firewall or via host-based firewall rules.",
      "Implement temporarily higher authentication requirements (MFA/allowed key rotation) on the jump host."
    ],
    hint: "Use correlation between IDS alerts and SSH logs to target the block."
  },
  {
    id: "pbq2",
    title: "Secure a new wireless guest network",
    scenario:
      "A small branch is launching a guest SSID for visitors. Document the steps needed to keep the guest access segmented.",
    steps: [
      "Create the SSID with WPA3 or WPA2-Enterprise if supported, otherwise strong PSK.",
      "Assign the guest VLAN and verify it only routes through the internet firewall.",
      "Apply ACLs that prevent guest users from reaching internal subnets."
    ],
    hint: "Pair the VLAN with a captive portal if you need to log usage."
  },
  {
    id: "pbq3",
    title: "Respond to ransomware ignition",
    scenario:
      "A workstation displays encrypted file notifications. Outline your immediate containment & evidence preservation steps.",
    steps: [
      "Disconnect the host from the network and isolate storage.",
      "Capture memory and disk images before powering down (if policies allow).",
      "Collect relevant logs (EPP alerts, domain controllers) and notify leadership."
    ],
    hint: "Speed is critical—think ‘isolate first, then investigate.’"
  }
];
const pbqDone = new Set();

function setStatus(text, isError = false) {
  els.importStatus.textContent = text;
  els.importStatus.classList.remove("success", "error", "status-pulse");
  els.importStatus.classList.add(isError ? "error" : "success", "status-pulse");
  if (statusPulseTimer) {
    clearTimeout(statusPulseTimer);
  }
  statusPulseTimer = setTimeout(() => {
    els.importStatus.classList.remove("status-pulse");
  }, 1000);
  triggerHeroGlow(isError);
}

function triggerHeroGlow(isError) {
  const target = isError ? 0.4 : 0.85;
  root.style.setProperty("--pulse-progress", target);
  setTimeout(() => {
    root.style.setProperty("--pulse-progress", 0);
  }, 600);
}

function setUploadDisabled(disabled) {
  els.loadFileBtn.disabled = disabled;
}

function getFileExtension(file) {
  const name = file.name || "";
  const segments = name.split(".");
  return segments.length > 1 ? segments.pop().toLowerCase() : "";
}

function arrayBufferToBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode.apply(null, chunk);
  }
  return btoa(binary);
}

async function buildUploadPayload(file) {
  const extension = getFileExtension(file);
  if (binaryExtensions.has(extension)) {
    const buffer = await file.arrayBuffer();
    return {
      binary: arrayBufferToBase64(buffer),
      extension
    };
  }
  const text = await file.text();
  return {
    text,
    extension
  };
}

function updateStats() {
  const total = state.questions.length;
  const answered = state.answers.filter(Boolean).length;
  const knownAnswers = state.questions.filter((q) => !!q.answer).length;

  if (els.statTotal) {
    els.statTotal.textContent = total;
  }
  if (els.statAnswered) {
    els.statAnswered.textContent = answered;
  }
  if (els.statKnown) {
    els.statKnown.textContent = knownAnswers;
  }

  const percentAnswered = total ? Math.round((answered / total) * 100) : 0;
  if (els.sessionMeterLabel) {
    els.sessionMeterLabel.textContent = `${percentAnswered}%`;
  }
  if (els.sessionMeterFill) {
    els.sessionMeterFill.style.setProperty("--progress", (percentAnswered / 100).toFixed(2));
  }
}

function exportReview() {
  const payload = state.questions.map((q, idx) => ({
    prompt: q.prompt,
    selected: state.answers[idx] || null,
    expected: q.answer || null
  }));
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const anchor = document.createElement("a");
  anchor.href = URL.createObjectURL(blob);
  anchor.download = "sy0-701-review.json";
  anchor.click();
  URL.revokeObjectURL(anchor.href);
}

function resetProgress() {
  state.answers = new Array(state.questions.length).fill(null);
  state.currentIndex = 0;
  setStatus("Answers reset, ready for a fresh pass.");
  renderCurrentQuestion();
  updateStats();
}

function applyImportedQuestions(payload) {
  state.questions = payload.questions || [];
  state.answers = new Array(state.questions.length).fill(null);
  state.currentIndex = 0;
  state.startTime = Date.now();

  if (state.timerId) {
    clearInterval(state.timerId);
  }

  state.timerId = setInterval(updateTimer, 1000);
  updateTimer();

  els.quizPanel.classList.remove("hidden");
  els.resultPanel.classList.add("hidden");
  renderCurrentQuestion();
  updateStats();
}

const binaryExtensions = new Set(["pdf", "vce"]);

async function importFromCipherSource(payload, label) {
  const hasText = typeof payload?.text === "string" && payload.text.trim();
  const hasData = payload?.binary || hasText;
  if (!hasData) {
    const message = payload?.binary ? "Cipher file decoded empty output." : "Provided text is empty.";
    setStatus(message, true);
    return;
  }

  const typeLabel = payload.extension ? payload.extension.toUpperCase() : "TEXT";
  setStatus(label ? `Importing ${label}...` : `Importing ${typeLabel} data...`);
  setUploadDisabled(true);

  try {
    const response = await fetch("/api/import", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ ...payload, sourceLabel: label })
    });

    const rawResponse = await response.text();
    let data = null;
    if (rawResponse) {
      try {
        data = JSON.parse(rawResponse);
      } catch (parseError) {
        throw new Error(
          `Unexpected server response${response.status ? ` (${response.status})` : ""}: ${rawResponse}`
        );
      }
    }

    if (!response.ok) {
      const message =
        data?.error ||
        rawResponse ||
        `Server responded with ${response.status} ${response.statusText}`;
      throw new Error(message);
    }

    if (!data.questions || !data.questions.length) {
      throw new Error("No questions were extracted from the file.");
    }

    applyImportedQuestions(data);
    const sourceText = label || data.source || "local file";
    setStatus(`Loaded ${state.questions.length} questions from ${sourceText}.`);
  } catch (error) {
    setStatus(error.message, true);
  } finally {
    setUploadDisabled(false);
  }
}

async function importFromFile() {
  const file = els.fileInput.files?.[0];
  if (!file) {
    setStatus("Choose a cipher exam file first.", true);
    return;
  }

  try {
    const payload = await buildUploadPayload(file);
    await importFromCipherSource(payload, file.name);
  } catch (error) {
    setStatus(error?.message || "Unable to read the file.", true);
  }
}

function elapsedSeconds() {
  if (!state.startTime) {
    return 0;
  }
  return Math.floor((Date.now() - state.startTime) / 1000);
}

function updateTimer() {
  const secs = elapsedSeconds();
  const m = String(Math.floor(secs / 60)).padStart(2, "0");
  const s = String(secs % 60).padStart(2, "0");
  els.timerText.textContent = `${m}:${s}`;
}

function calculateScore() {
  let correct = 0;

  state.questions.forEach((q, idx) => {
    const picked = state.answers[idx];
    if (picked && q.answer && picked === q.answer) {
      correct += 1;
    }
  });

  return correct;
}

function renderCurrentQuestion() {
  if (!state.questions.length) {
    return;
  }

  const q = state.questions[state.currentIndex];
  const selected = state.answers[state.currentIndex];

  els.progressText.textContent = `Question ${state.currentIndex + 1} of ${state.questions.length}`;
  els.scoreLive.textContent = `Score: ${calculateScore()}`;

  const optionsHtml = q.choices.map((choice) => {
    const isChecked = selected === choice.id;
    return `
      <label class="option ${isChecked ? "selected" : ""}">
        <input type="radio" name="answer" value="${choice.id}" ${isChecked ? "checked" : ""} />
        <div><strong>${choice.id}.</strong> ${choice.text}</div>
      </label>
    `;
  }).join("");

  const answerKnown = q.answer ? "Known answer available for scoring." : "No official answer parsed for this question.";

  els.questionCard.innerHTML = `
    <p>${q.prompt}</p>
    <div>${optionsHtml}</div>
    <p class="mono">${answerKnown}</p>
  `;

  [...els.questionCard.querySelectorAll("input[name='answer']")].forEach((input) => {
    input.addEventListener("change", () => {
      state.answers[state.currentIndex] = input.value;
      renderCurrentQuestion();
    });
  });

  els.prevBtn.disabled = state.currentIndex === 0;
  els.nextBtn.disabled = state.currentIndex >= state.questions.length - 1;
  updateStats();
}

function finishQuiz() {
  if (state.timerId) {
    clearInterval(state.timerId);
    state.timerId = null;
  }

  const total = state.questions.length;
  const knownAnswerCount = state.questions.filter((q) => !!q.answer).length;
  const correct = calculateScore();
  const attempted = state.answers.filter(Boolean).length;
  const percent = knownAnswerCount > 0 ? Math.round((correct / knownAnswerCount) * 100) : 0;

  els.resultSummary.textContent = `${correct}/${knownAnswerCount} correct on questions with known answers. Attempted ${attempted}/${total}. Time: ${els.timerText.textContent}. Score: ${percent}%`;

  renderReview();

  els.resultPanel.classList.remove("hidden");
  els.quizPanel.classList.add("hidden");
}

function renderReview() {
  const html = state.questions.map((q, idx) => {
    const picked = state.answers[idx] || "(none)";
    const answer = q.answer || "(unknown)";
    const isWrong = q.answer && picked !== q.answer;

    return `
      <div class="review-item ${isWrong ? "wrong" : ""}">
        <div><strong>Q${idx + 1}.</strong> ${q.prompt}</div>
        <div class="mono">Your answer: ${picked} | Expected: ${answer}</div>
      </div>
    `;
  }).join("");

  els.reviewList.innerHTML = html;
}

function renderPracticalPBQs() {
  if (!pbqListEl) {
    return;
  }

  const html = practicalPBQs
    .map((pbq) => {
      const done = pbqDone.has(pbq.id);
      return `
        <div class="pbq-card ${done ? "done" : ""}">
          <div class="pbq-body">
            <h3>${pbq.title}</h3>
            <button type="button" data-pbq-id="${pbq.id}">
              ${done ? "Reset" : "Mark done"}
            </button>
          </div>
          <p>${pbq.scenario}</p>
          <ul>
            ${pbq.steps.map((step) => `<li>${step}</li>`).join("")}
          </ul>
          <p class="hint">Hint: ${pbq.hint}</p>
        </div>
      `;
    })
    .join("");

  pbqListEl.innerHTML = html;
}

function togglePBQ(id) {
  if (pbqDone.has(id)) {
    pbqDone.delete(id);
  } else {
    pbqDone.add(id);
  }
  renderPracticalPBQs();
}

function restartQuiz() {
  state.currentIndex = 0;
  state.answers = new Array(state.questions.length).fill(null);
  state.startTime = Date.now();

  if (state.timerId) {
    clearInterval(state.timerId);
  }

  state.timerId = setInterval(updateTimer, 1000);
  updateTimer();

  els.resultPanel.classList.add("hidden");
  els.quizPanel.classList.remove("hidden");
  renderCurrentQuestion();
}

els.loadFileBtn.addEventListener("click", importFromFile);
els.prevBtn.addEventListener("click", () => {
  if (state.currentIndex > 0) {
    state.currentIndex -= 1;
    renderCurrentQuestion();
  }
});
els.nextBtn.addEventListener("click", () => {
  if (state.currentIndex < state.questions.length - 1) {
    state.currentIndex += 1;
    renderCurrentQuestion();
  }
});
els.finishBtn.addEventListener("click", finishQuiz);
els.restartBtn.addEventListener("click", restartQuiz);
if (els.exportBtn) {
  els.exportBtn.addEventListener("click", exportReview);
}
if (els.resetProgressBtn) {
  els.resetProgressBtn.addEventListener("click", resetProgress);
}

if (pbqListEl) {
  pbqListEl.addEventListener("click", (event) => {
    const btn = event.target.closest("button[data-pbq-id]");
    if (!btn) {
      return;
    }
    togglePBQ(btn.dataset.pbqId);
  });
}

window.addEventListener("pointermove", (event) => {
  const x = (event.clientX / window.innerWidth) * 100;
  const y = (event.clientY / window.innerHeight) * 100;
  root.style.setProperty("--pointer-x", x.toString());
  root.style.setProperty("--pointer-y", y.toString());
});

renderPracticalPBQs();
