# CipherRun Gauntlet

CipherRun Gauntlet is a lightweight client/server practice tester designed for cyber certification study. The platform
lets you upload `.txt`, `.json`, `.exam`, `.pdf`, and `.vce` sources, run a timed multiple-choice session, track
scoring (including known answers), and add a short "Practical PBQ" tracker for hands-on scenario prep.

## Features

- Drag/drop (or browse) a `.txt`/`.json`/`.exam`/`.pdf`/`.vce` export; the server now decodes PDF and VCE binaries before pulling the `NEW QUESTION ... Answer:` blocks for parsing.
- Server-side parser that extracts prompts, choices, and documented answers, then enriches them via simple heuristics if the answer is missing.
- Timed quiz UI with navigation controls, live score, review screen, and the ability to retake the test.
- Dashboard stats showing total/answered/known answers plus buttons to download the current review or reset cleared answers.
- Practical PBQ panel to track three made-up scenario prompts (contain SSH brute force, guest Wi-Fi segmentation, ransomware response).

## Getting started

1. Install dependencies:
   ```sh
   npm install
   ```
2. Start the server:
   ```sh
   npm start
   ```
3. Open `http://127.0.0.1:3000` in your browser; the server serves everything out of the `client/` directory.
4. Choose your cipher exam file (text/PDF/VCE) and click **Load questions**.

## File requirements

- The importer expects plain text that includes `NEW QUESTION <number>` blocks followed by `Answer: <letter>`, optionally with an explanation. PDF and VCE uploads are decoded to plain text before this parser runs.
- Keep spacing simple (no fancy tables) so the parser can split on `NEW QUESTION` and `A.`/`B.` options.

## Notes

- All import logic runs locally via `POST /api/import`. No remote scraping is required.
- Practical PBQs are static cards rendered client-side; you can reset a card by clicking "Reset."
- Create more files for additional question banks (FreeCram, Exambible, etc.) by exporting modern formats (plain text, PDF, or VCE) and uploading them.
