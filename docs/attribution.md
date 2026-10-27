# Attribution: human versus AI

aitrace gives each relevant file a verdict and each event an actor. The verdict comes from fixed rules over recorded signals. It is not a statistical guess about writing style.

Verdicts: `ai_generated`, `ai_assisted`, `human_authored`, `undetermined`. Actors: `human`, `ai`, `system`, `unknown`.

## Rubric

The text below is the rubric exactly as the tool implements it.

0. AGENT_TOOL_WRITE fires when a file's normalized path equals an AI_TOOL_CALL Write/Edit/MultiEdit `file_path` (Windows paths: strip drive letter, backslash->slash, case-insensitive). Weight = cap (0.90) if file content sha256 equals the tool-call content sha256 (exact), else 0.6 * cap (0.54). HUMAN_EDIT_AFTER fires when content differs from the last tool-call content AND file mtime > tool-call ts + 60 s. Worked: C.1 proposal.md exact -> ai_generated 0.90 strong; edited.md path match 0.54 + HUMAN_EDIT_AFTER -> ai_assisted 0.54 moderate; C.3 dump.py exact -> ai_generated; DALL-E PNG C2PA 0.90 + filename 0.60 + download origin 0.75 -> ai_generated 0.95 strong.
1. Collect signals per subject. Weight of a signal = its cap from SIGNAL_CAPS (CONTENT_MATCH weight = cap * jaccard, min 0.5*cap).
2. ai_score = max weight over ai-direction signals; plus 0.05 per additional distinct ai signal type, total capped at 0.95. human_score = max over human-direction signals.
3. Verdict: ai_score >= 0.5 and no HUMAN_EDIT_AFTER -> ai_generated, confidence ai_score; ai_score >= 0.5 and HUMAN_EDIT_AFTER -> ai_assisted, confidence min(ai_score, 0.75); ai_score < 0.5 and human_score >= 0.5 and ai_score < 0.2 -> human_authored, confidence human_score; otherwise undetermined, confidence max(ai_score, human_score).
4. band = band_for(confidence). rationale lists each signal with weight. limitations = LIMITATIONS of each signal type + GLOBAL "absence of AI traces does not prove human authorship".
5. Never emit human_authored without a HUMAN_PROCESS or HUMAN_EDIT_AFTER signal.

## Limitations

- Every attribution carries a non-empty list of limitations: the limits of each signal type that fired, plus the global statement that absence of AI traces does not prove human authorship.
- A file with no signals is `undetermined`, never `human_authored`.
- A path match with an AI tool call shows that the tool was asked to write that path. It doesn't prove who typed the prompt or who owned the account.
- Signals come from logs and files that a user can delete, copy or rename. Missing logs weaken a finding, they don't contradict it.
- Image provenance (C2PA, XMP, EXIF, file names) can be stripped or forged. Treat it as one signal among several.
- Time comparisons use file timestamps, which tools and users can change.
- No machine-learning detector is used, because such scores aren't reliable enough as evidence.
