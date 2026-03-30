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
  restartBtn: document.getElementById("restartBtn")
};

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
  els.importStatus.style.color = isError ? "#b4372b" : "#5e6470";
}

function setUploadDisabled(disabled) {
  els.loadFileBtn.disabled = disabled;
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
}

async function importFromDump(text, label) {
  if (!text) {
    setStatus("Provided text is empty.", true);
    return;
  }

  setStatus(label ? `Importing ${label}...` : "Importing questions...");
  setUploadDisabled(true);

  try {
    const response = await fetch("/api/import", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ text, sourceLabel: label })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Failed to import questions from file.");
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
    setStatus("Choose a dump text file first.", true);
    return;
  }

  try {
    const text = await file.text();
    await importFromDump(text, file.name);
  } catch (error) {
    setStatus("Unable to read the file.", true);
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

if (pbqListEl) {
  pbqListEl.addEventListener("click", (event) => {
    const btn = event.target.closest("button[data-pbq-id]");
    if (!btn) {
      return;
    }
    togglePBQ(btn.dataset.pbqId);
  });
}

renderPracticalPBQs();
