const http = require("http");
const fs = require("fs");
const path = require("path");
const { URL } = require("url");
const crypto = require("crypto");
const pdfParse = require("pdf-parse");
const unzipper = require("unzipper");

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

function decodeBufferAsText(buffer) {
  if (!buffer || !buffer.length) {
    return "";
  }

  if (buffer[0] === 0xff && buffer[1] === 0xfe) {
    return buffer.toString("utf16le");
  }
  if (buffer[0] === 0xfe && buffer[1] === 0xff) {
    return buffer.toString("utf16be");
  }
  return buffer.toString("utf8");
}

async function extractTextFromPdf(base64) {
  if (!base64) {
    return "";
  }

  const buffer = Buffer.from(base64, "base64");
  const parsed = await pdfParse(buffer);
  return parsed.text || "";
}

function stripHtmlEntities(str) {
  return str
    .replace(/<[^>]+>/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#0?39;/g, "'")
    .replace(/&nbsp;/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function extractTagContent(xml, tagName) {
  const regex = new RegExp(
    `<${tagName}[^>]*>([\\s\\S]*?)<\\/${tagName}>`,
    "i"
  );
  const match = xml.match(regex);
  if (!match) {
    return null;
  }
  let content = match[1];
  const cdata = content.match(/<!\[CDATA\[([\s\S]*?)\]\]>/);
  if (cdata) {
    content = cdata[1];
  }
  return content;
}

function parseVceXml(xml) {
  const questions = [];
  const letters = ["A", "B", "C", "D", "E", "F", "G", "H"];
  const clean = xml.replace(/<\?xml[^?]*\?>/gi, "");

  const qBlocks =
    clean.match(/<Question[\s>][\s\S]*?<\/Question>/gi) || [];

  for (const qBlock of qBlocks) {
    let prompt =
      extractTagContent(qBlock, "QuestionText") ||
      extractTagContent(qBlock, "Text") ||
      extractTagContent(qBlock, "question_text");

    if (!prompt) {
      continue;
    }
    prompt = stripHtmlEntities(prompt);
    if (!prompt) {
      continue;
    }

    const choices = [];
    let correctAnswer = null;

    const answerBlocks =
      qBlock.match(/<Answer[\s>][\s\S]*?<\/Answer>/gi) || [];

    answerBlocks.forEach((aBlock, idx) => {
      if (idx >= letters.length) {
        return;
      }

      let text =
        extractTagContent(aBlock, "AnswerText") ||
        extractTagContent(aBlock, "Text") ||
        extractTagContent(aBlock, "answer_text");

      if (!text) {
        text = aBlock.replace(/<\/?Answer[^>]*>/gi, "");
      }

      text = stripHtmlEntities(text);
      const letter = letters[idx];
      choices.push({ id: letter, text });

      const correctAttr = aBlock.match(
        /(?:Correct|IsCorrect|correct|isCorrect)\s*=\s*["']([^"']+)["']/i
      );
      const correctElem =
        extractTagContent(aBlock, "IsCorrect") ||
        extractTagContent(aBlock, "Correct");

      const correctVal = correctAttr ? correctAttr[1] : (correctElem || "").trim();
      if (correctVal === "1" || correctVal.toLowerCase() === "true") {
        correctAnswer = letter;
      }
    });

    if (choices.length >= 2) {
      questions.push({ prompt, choices, answer: correctAnswer });
    }
  }

  return questions;
}

// --- Avanset VCE binary format parser (v6+, AES-256-CBC) ---
// Format reverse-engineered from Bo0m21/Converter (C# reference implementation)

// Avanset uses a 5-byte obfuscated length prefix before every data block.
// First byte is discarded; next 4 bytes are XOR-decoded with a running key.
function vceReadLength(buf, pos) {
  pos += 1; // discard first byte (its value drives v1/v2 but both collapse to constants)
  let v2 = 0x100;
  const bytes = [];
  for (let c = 0; c < 4; c++) {
    const b = buf[pos++];
    bytes.push((v2 ^ b) & 0xff);
    v2 = (v2 + (v2 & 0xff)) | (c + 1);
  }
  return { len: Buffer.from(bytes).readInt32LE(0), pos };
}

function vceReadArray(buf, pos) {
  const { len, pos: p } = vceReadLength(buf, pos);
  return { data: buf.slice(p, p + len), pos: p + len };
}

function vceDecryptArray(buf, pos, keys, decryptKeys, version) {
  const { len: totalLen, pos: p } = vceReadLength(buf, pos);
  if (totalLen === 0) return { data: Buffer.alloc(0), pos: p };

  let messageLen = totalLen - 1;
  const selectKey = buf[p];
  let pp = p + 1;
  const selectedKey = selectKey < 0x80 ? keys : decryptKeys;

  let globalOffset = 0;
  if (version >= 61) {
    messageLen -= 4;
    globalOffset = buf.readInt32LE(pp);
    pp += 4;
  }

  const key = selectedKey.slice(globalOffset, globalOffset + 32);
  const iv = selectedKey.slice(globalOffset + 32, globalOffset + 48);
  const encrypted = buf.slice(pp, pp + messageLen);
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  decipher.setAutoPadding(false);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return { data: decrypted, pos: pp + messageLen };
}

function vceGetString(bytes) {
  return Buffer.from(Array.from(bytes).filter((b) => b >= 0x20)).toString("utf8").trim();
}

// Each section in questionBytes is separated by this literal marker.
// It corresponds to "-8 1 3 1" in ASCII (Avanset internal format tag).
const VCE_SECTION_SEP = Buffer.from([0x2d, 0x38, 0x20, 0x31, 0x20, 0x33, 0x20, 0x31]);

function splitBuffer(data, pattern) {
  const parts = [];
  let start = 0;
  outer: for (let i = 0; i <= data.length - pattern.length; i++) {
    for (let j = 0; j < pattern.length; j++) {
      if (data[i + j] !== pattern[j]) continue outer;
    }
    parts.push(data.slice(start, i));
    start = i + pattern.length;
  }
  parts.push(data.slice(start));
  return parts;
}

// Extract readable text from a VCE section blob.
// Decrypted content is UTF-16LE, so null bytes appear between every character.
// We strip control/null bytes first (mirrors C# GetString behavior), then
// split by lines, drop pure format-code lines (numbers only), and strip
// the ') ...' artifact that Avanset uses as an internal text delimiter.
function vceExtractText(sectionBytes) {
  // Keep printable bytes and CR/LF for line splitting; drop nulls and other controls.
  const filtered = Buffer.from(
    Array.from(sectionBytes).filter((b) => b >= 0x20 || b === 0x0a || b === 0x0d)
  );
  const str = filtered.toString("utf8");
  const lines = str.split(/\r\n|\r|\n/);
  const out = [];
  for (const line of lines) {
    const t = line.trim();
    if (!t) continue;
    if (/^[-\d\s]+$/.test(t)) continue; // formatting code — skip
    out.push(t.replace(/\)\s.*$/, "").trim());
  }
  return out
    .filter(Boolean)
    .join(" ")
    .replace(/\s+/g, " ")
    .trim();
}

function parseAvansetQuestions(buf, pos, keys, decryptKeys, version, qCount) {
  const LETTERS = ["A", "B", "C", "D", "E", "F", "G", "H"];
  const questions = [];

  for (let q = 0; q < qCount; q++) {
    // v6.1+ has an extra length-prefixed block before each question
    if (version >= 61) {
      const { pos: p } = vceReadLength(buf, pos);
      pos = p;
    }

    let r = vceDecryptArray(buf, pos, keys, decryptKeys, version);
    pos = r.pos; // td1 (internal question id data)

    const qType = buf[pos++];
    pos += 12; // sectionId (4) + complexity (4) + td2 (4)

    if (qType === 0 || qType === 1) {
      // SingleChoice (0) or MultipleChoice (1)
      r = vceDecryptArray(buf, pos, keys, decryptKeys, version);
      const questionBytes = r.data;
      pos = r.pos;

      r = vceDecryptArray(buf, pos, keys, decryptKeys, version);
      const answersBytes = r.data;
      pos = r.pos;

      const variantsCount = buf.readInt32LE(pos);
      pos += 4 + 3; // variantsCount + td3 + td4 + td5

      r = vceDecryptArray(buf, pos, keys, decryptKeys, version);
      pos = r.pos; // td6

      const parts = splitBuffer(questionBytes, VCE_SECTION_SEP);
      // Layout: [header, questionText, choice0, choice1, ..., reference]
      const prompt = parts.length > 1 ? vceExtractText(parts[1]) : "";
      if (!prompt) continue;

      const choices = [];
      for (let v = 0; v < variantsCount && v + 2 < parts.length; v++) {
        const text = vceExtractText(parts[v + 2]);
        if (text && v < LETTERS.length) {
          choices.push({ id: LETTERS[v], text });
        }
      }
      if (choices.length < 2) continue;

      const answerRaw = vceGetString(answersBytes);
      const answerMatch = answerRaw.match(/^([A-H]+)/);
      const answer = answerMatch ? answerMatch[1][0] : null;

      questions.push({ prompt, choices, answer });
    } else {
      // Unsupported question type (DragAndDrop, HotArea, etc.) — skip safely
      // by reading the two encrypted blobs and the fixed fields
      r = vceDecryptArray(buf, pos, keys, decryptKeys, version); pos = r.pos;
      r = vceDecryptArray(buf, pos, keys, decryptKeys, version); pos = r.pos;
      buf.readInt32LE(pos); pos += 4 + 3;
      r = vceDecryptArray(buf, pos, keys, decryptKeys, version); pos = r.pos;
    }
  }

  return { questions, pos };
}

function parseAvansetVce(buffer) {
  if (buffer[0] !== 0x85 || buffer[1] !== 0xa8) return [];

  let pos = 2;
  const verHi = buffer[pos++];
  const verLo = buffer[pos++];
  const version = verHi * 10 + verLo;

  pos += 4; // typeCodeLen (int32)

  let r = vceReadArray(buffer, pos);
  const keys = r.data;
  pos = r.pos;

  r = vceReadArray(buffer, pos);
  const decryptKeys = r.data;
  pos = r.pos;

  pos += 1; // td3 (byte)

  // Exam metadata
  r = vceDecryptArray(buffer, pos, keys, decryptKeys, version); pos = r.pos; // number
  r = vceDecryptArray(buffer, pos, keys, decryptKeys, version); pos = r.pos; // title
  pos += 8; // passingScore (int32) + timeLimit (int32)
  r = vceDecryptArray(buffer, pos, keys, decryptKeys, version); pos = r.pos; // fileVersion
  pos += 16; // td7 + td8 (int64 each)

  if (version <= 61) {
    pos += 18; // td9 + td10 (int64 each) + td11 + td12 (byte each)
    r = vceDecryptArray(buffer, pos, keys, decryptKeys, version); pos = r.pos; // td13
  }

  r = vceDecryptArray(buffer, pos, keys, decryptKeys, version); pos = r.pos; // style
  r = vceDecryptArray(buffer, pos, keys, decryptKeys, version); pos = r.pos; // description

  const sectionsCount = buffer.readInt32LE(pos); pos += 4;
  for (let i = 0; i < sectionsCount; i++) {
    pos += 4; // sectionId
    r = vceDecryptArray(buffer, pos, keys, decryptKeys, version); pos = r.pos;
  }

  r = vceDecryptArray(buffer, pos, keys, decryptKeys, version); pos = r.pos; // td17

  const examsCount = buffer.readInt32LE(pos); pos += 4;
  const allQuestions = [];

  for (let e = 0; e < examsCount; e++) {
    const examType = buffer[pos++]; // 0=Question, 1=Section
    r = vceDecryptArray(buffer, pos, keys, decryptKeys, version); pos = r.pos; // examName

    if (examType === 0) {
      const qCount = buffer.readInt32LE(pos); pos += 4;
      const { questions, pos: newPos } = parseAvansetQuestions(
        buffer, pos, keys, decryptKeys, version, qCount
      );
      allQuestions.push(...questions);
      pos = newPos;
    } else if (examType === 1) {
      const sCount = buffer.readInt32LE(pos); pos += 4;
      for (let s = 0; s < sCount; s++) {
        const sectionType = buffer[pos++];
        pos += 4; // timeLimit (int32)
        if (sectionType === 0) {
          // QuestionSet
          const qCount = buffer.readInt32LE(pos); pos += 4;
          const { questions, pos: newPos } = parseAvansetQuestions(
            buffer, pos, keys, decryptKeys, version, qCount
          );
          allQuestions.push(...questions);
          pos = newPos;
        } else if (sectionType === 1) {
          // Testlet
          r = vceDecryptArray(buffer, pos, keys, decryptKeys, version); pos = r.pos; // title
          pos += 4; // t1
          r = vceDecryptArray(buffer, pos, keys, decryptKeys, version); pos = r.pos; // t2
          r = vceDecryptArray(buffer, pos, keys, decryptKeys, version); pos = r.pos; // description
          pos += 8; // t3 + qCount int32 each... wait: t3 (int32) + qCount (int32)
          const qCount = buffer.readInt32LE(pos - 4);
          const { questions, pos: newPos } = parseAvansetQuestions(
            buffer, pos, keys, decryptKeys, version, qCount
          );
          allQuestions.push(...questions);
          pos = newPos;
        }
      }
    }
  }

  return allQuestions;
}

// --- Legacy fallback: ZIP-wrapped XML (older VCE format) ---

async function tryZipXml(buffer) {
  try {
    const archive = await unzipper.Open.buffer(buffer);
    let xmlContent = null;

    for (const entry of archive.files) {
      if (entry.type !== "File") continue;
      const name = entry.path.toLowerCase();
      if (name.endsWith(".xml") || name.endsWith(".exam")) {
        const chunk = await entry.buffer();
        xmlContent = decodeBufferAsText(chunk);
        break;
      }
    }

    if (!xmlContent) {
      for (const entry of archive.files) {
        if (entry.type !== "File") continue;
        const chunk = await entry.buffer();
        const text = decodeBufferAsText(chunk);
        if (/<Question[\s>]/i.test(text)) {
          xmlContent = text;
          break;
        }
      }
    }

    if (xmlContent) return parseVceXml(xmlContent);
  } catch {
    // not a ZIP
  }
  return [];
}

function tryRawXml(buffer) {
  const raw = buffer.toString("utf8");
  const start = raw.search(/<(?:Exam|VCE|ExamFile|Questions)[\s>]/i);
  return start !== -1 ? parseVceXml(raw.slice(start)) : [];
}

// --- Main entry point ---

async function parseVceFile(base64) {
  if (!base64) return [];

  const buffer = Buffer.from(base64, "base64");

  // Primary: Avanset native binary format (magic 0x85 0xA8)
  if (buffer[0] === 0x85 && buffer[1] === 0xa8) {
    try {
      const questions = parseAvansetVce(buffer);
      if (questions.length > 0) return questions;
    } catch {
      // fall through to legacy
    }
  }

  // Legacy fallbacks for older XML-based VCE files
  const fromZip = await tryZipXml(buffer);
  if (fromZip.length) return fromZip;

  return tryRawXml(buffer);
}

async function resolveIncomingText(body) {
  if (body.binary) {
    const extension = (body.extension || "").toLowerCase();
    if (extension === "pdf") {
      return extractTextFromPdf(body.binary);
    }
    return Buffer.from(body.binary, "base64").toString("utf8");
  }

  return typeof body.text === "string" ? body.text : "";
}

function parseCipherSections(rawText) {
  const normalized = rawText.replace(/\r/g, "");
  const blockRegex = /NEW QUESTION\s+\d+[\s\S]*?(?=NEW QUESTION\s+\d+|$)/gi;
  const blocks = normalized.match(blockRegex) || [];

  return blocks
    .map((block) => parseCipherBlock(block))
    .filter(Boolean);
}

function parseCipherBlock(block) {
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

        const extension = (body.extension || "").toLowerCase();
        let questions;

        if (extension === "vce" && body.binary) {
          questions = await parseVceFile(body.binary);
          if (questions.length === 0) {
            sendJson(res, 422, {
              error: "No questions were extracted from the VCE file. The file may use an unsupported format."
            });
            return;
          }
        } else {
          const text = await resolveIncomingText(body);
          if (!text || !text.trim()) {
            const hint = body.binary
              ? "No question text could be decoded from the uploaded binary; export the file as text (or try a different bank)."
              : "Missing text payload in request.";
            sendJson(res, 422, {
              error: `Missing text payload in request. ${hint}`
            });
            return;
          }

          questions = parseCipherSections(text);
          if (questions.length === 0) {
            sendJson(res, 422, {
              error: "No question blocks were parsed from the provided text."
            });
            return;
          }
        }

        const enriched = enrichAnswers(questions);
        sendJson(res, 200, {
          source: body.sourceLabel || "uploaded cipher exam",
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
  console.log(`CipherRun Gauntlet server running at http://${HOST}:${PORT}`);
});
