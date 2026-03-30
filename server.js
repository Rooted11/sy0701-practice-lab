const http = require("http");
const fs = require("fs");
const path = require("path");
const { URL } = require("url");

const PORT = 3000;
const HOST = "127.0.0.1";
const PUBLIC_DIR = path.join(__dirname, "client");

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*"
  });
  res.end(JSON.stringify(payload));
}

function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function parseDumpText(rawText) {
  const normalized = rawText.replace(/\r/g, "");
  const blockRegex = /NEW QUESTION\s+\d+[\s\S]*?(?=NEW QUESTION\s+\d+|$)/gi;
  const blocks = normalized.match(blockRegex) || [];

  return blocks
    .map((block) => parseDumpBlock(block))
    .filter(Boolean);
}

function parseDumpBlock(block) {
  const lines = block
    .split("\n")
    .map((line) => line.replace(/\s+/g, " ").trim())
    .filter((line) => line && !line.startsWith("== PAGE"));

  const promptLines = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    if (line.startsWith("NEW QUESTION") || line.startsWith("- (")) {
      i += 1;
      continue;
    }
    if (/^[A-D]\./.test(line) || line.startsWith("Answer:") || line.startsWith("Explanation")) {
      break;
    }
    promptLines.push(line);
    i += 1;
  }

  const prompt = promptLines.join(" ").trim();
  if (!prompt) {
    return null;
  }

  const choices = [];

  for (; i < lines.length; i++) {
    const optionMatch = lines[i].match(/^([A-D])\.\s*(.*)$/);
    if (!optionMatch) {
      continue;
    }

    const letter = optionMatch[1];
    let text = optionMatch[2];

    i += 1;

    while (
      i < lines.length &&
      !/^[A-D]\./.test(lines[i]) &&
      !/^Answer:/.test(lines[i]) &&
      !/^Explanation:?/.test(lines[i])
    ) {
      text += " " + lines[i];
      i += 1;
    }

    choices.push({ id: letter, text: text.trim() });
    i -= 1;
  }

  if (choices.length < 2) {
    return null;
  }

  const answerLine = lines.find((line) => line.startsWith("Answer:"));
  const answerMatch = answerLine ? answerLine.match(/Answer:\s*([A-Z])/i) : null;
  const answer = answerMatch ? answerMatch[1].toUpperCase() : null;

  return {
    prompt,
    choices,
    answer
  };
}

function inferAnswer(question) {
  // If no official answer is exposed in the free page, use a best-effort heuristic
  // and keep the answer nullable in case no confidence exists.
  const text = `${question.prompt} ${question.choices.map((c) => c.text).join(" ")}`.toLowerCase();
  const keywordToChoice = [
    ["hash", "C"],
    ["vpn", "B"],
    ["acl", "C"],
    ["full disk", "A"],
    ["nation-state", "C"],
    ["jump server", "C"],
    ["data exfiltrated", "A"],
    ["removable devices", "D"],
    ["certification", "D"],
    ["escalation", "C"]
  ];

  for (const [keyword, candidate] of keywordToChoice) {
    if (text.includes(keyword)) {
      const exists = question.choices.some((c) => c.id === candidate);
      if (exists) {
        return candidate;
      }
    }
  }

  return null;
}

function enrichAnswers(questions) {
  return questions.map((q) => ({
    ...q,
    answer: q.answer || inferAnswer(q)
  }));
}

function contentType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  switch (ext) {
    case ".html":
      return "text/html; charset=utf-8";
    case ".css":
      return "text/css; charset=utf-8";
    case ".js":
      return "application/javascript; charset=utf-8";
    case ".json":
      return "application/json; charset=utf-8";
    default:
      return "text/plain; charset=utf-8";
  }
}

function serveStatic(req, res) {
  const requestPath = req.url === "/" ? "/index.html" : req.url;
  const safePath = path.normalize(requestPath).replace(/^([.][.][/\\])+/, "");
  const filePath = path.join(PUBLIC_DIR, safePath);

  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end("Not found");
      return;
    }

    res.writeHead(200, { "Content-Type": contentType(filePath) });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  const parsed = new URL(req.url, `http://${req.headers.host}`);

  if (parsed.pathname === "/api/import") {
    if (req.method === "POST") {
      try {
        const rawBody = await readRequestBody(req);
        if (!rawBody) {
          sendJson(res, 400, { error: "Request body is required." });
          return;
        }

        let body;
        try {
          body = JSON.parse(rawBody);
        } catch {
          sendJson(res, 400, { error: "Invalid JSON payload." });
          return;
        }

        const text = typeof body.text === "string" ? body.text : "";
        if (!text.trim()) {
          sendJson(res, 400, { error: "Missing text payload in request." });
          return;
        }

        const questions = parseDumpText(text);
        if (questions.length === 0) {
          sendJson(res, 422, {
            error: "No question blocks were parsed from the provided text."
          });
          return;
        }

        const enriched = enrichAnswers(questions);
        sendJson(res, 200, {
          source: body.sourceLabel || "uploaded dump",
          totalQuestions: enriched.length,
          questions: enriched
        });
      } catch (error) {
        sendJson(res, 500, { error: error.message || "Import failed." });
      }
      return;
    }

    sendJson(res, 405, { error: "Method not allowed. POST only." });
    return;
  }

  serveStatic(req, res);
});

server.listen(PORT, HOST, () => {
  console.log(`Practice test taker running at http://${HOST}:${PORT}`);
});
