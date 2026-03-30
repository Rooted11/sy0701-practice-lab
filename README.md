# CipherRun SY0-701

CipherRun SY0-701 is a lightweight client/server practice tester tailored around the CompTIA Security+ exam. The app
lets you upload existing `.txt`/`.json` exports, run a timed multiple-choice session, track scoring (including
known answers), and add a short “Practical PBQ” tracker for hands-on scenario prep.

## Features

- Drag/drop (or browse) a `.txt`/`.json`/`.dump` export that contains the `NEW QUESTION … Answer:` format and upload it directly from the browser.
- Server-side parser that extracts prompts, choices, and documented answers, then enriches them via simple heuristics if the answer is missing.
- Timed quiz UI with navigation controls, live score, review screen, and ability to retake the test.
- Dashboard stats showing total/answered/known answers plus buttons to download the current review or reset cleared answers.
- Practical PBQ panel to track three made-up scenario prompts (contain SSH brute force, guest Wi-Fi segmentation, ransomware response).

## Getting started

1. Install dependencies (only Node built-ins are required):
   ```sh
   npm install
   ```
2. Start the server:
   ```sh
   node server.js
   ```
3. Open `http://127.0.0.1:3000` in your browser; the server serves everything out of the `client/` directory.
4. Choose your dump file and click **Load questions**.

## Dump requirements

- The importer expects plain text that includes `NEW QUESTION <number>` blocks, followed
  by “Answer: <letter>” and optionally an explanation. This matches most VCE/PDF-to-text conversions from popular dumps.
- Keep spacing simple (no fancy tables) so the parser can split on `NEW QUESTION` and `A.`/`B.` options.

## Notes

- The server now only supports `POST /api/import`. All import logic runs locally to avoid relying on remote scraping.
- Practical PBQs are static cards rendered client-side; you can reset a card by clicking “Reset”.
- You can create more dumps for additional question banks (FreeCram, Exambible, etc.) by exporting them as text files and uploading them.
