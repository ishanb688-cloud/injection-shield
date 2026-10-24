# Injection Shield

A security layer that stops hidden instructions on web pages from hijacking AI assistants.

**Live demo:** (https://injection-shield.onrender.com)
(The free host sleeps when idle, so the first load may take up to a minute.)

**Demo video:** VIDEO_LINK_HERE

## The problem

AI assistants now read web pages for us. An attacker can hide a command on a normal-looking page (tiny text, white-on-white text, comments), and a naive assistant will obey it and leak private data. People viewing the page see nothing wrong.

## What it does

Injection Shield sits between the page and the AI and works in three layers:

1. **Hidden content detector.** Finds text people cannot see (tiny font, matching colors, display:none, off-screen, comments, invisible characters) and removes it.
2. **Instruction language detector.** Scores text that talks to an AI ("ignore your previous instructions", requests for secrets, output-control phrases) and blocks pages above a threshold.
3. **Output checker.** Inspects the AI's answer for secrets, auto-loading images and outside links, and redacts them. This catches attacks the first two layers miss.

## Results

All tests use a deliberately naive demo assistant (instructions, user data and page text in one prompt) on one smaller model, and a **fake** secret token.

**Original set (5 attack pages, 2 clean pages)**
- Shield OFF: token leaked in 9 of 15 attack runs
- Shield ON: token leaked on 0 of 5 attack pages
- Input layers flagged 4 of 5 attacks; 0 of 2 clean pages wrongly flagged

**Held-out set (5 attack pages, 10 clean pages, written after the rules were frozen)**
- Shield OFF: token leaked in 12 of 15 attack runs
- Shield ON: token leaked on 0 of 5 attack pages
- Input layers flagged 3 of 5 attacks. The two they missed (text hidden through a stylesheet class, and a politely worded request) were both stopped by the output layer.
- Output layer wrongly fired on 0 of 10 clean pages
- 2 of 10 clean pages were affected at the input stage: an article about prompt injection was blocked (a false positive), and harmless hidden menu text was removed

## Known limits

- Small sample; the same person wrote the rules and the test pages
- Tested against one naive assistant on one smaller model; the leak rates apply to that setup
- Rules are pattern-based, so rewording can slip past the input layers
- The hidden-content layer reads inline styles only, not stylesheet classes
- The output layer protects values the app registers (the demo registers one fake token)
- Assistant answers shown on the dashboard are recorded from real runs, with run counts shown

## Run it locally

```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000. The dashboard needs no API key. To run the live assistant yourself, create a `.env` file with `API_KEY=your_key` and run `python assistant.py <url>` or `python protected_assistant.py <url>`.

## Project layout

- `shield/` the three layers and the pipeline
- `attack_pages/`, `heldout_pages/` test pages
- `tests/run_tests.py` test runner
- `app.py` the dashboard
- `assistant.py`, `protected_assistant.py` demo assistants
- `RESULTS.md` summary of test results

## Ethics

All attack pages are harmless demos with a fake token, built to test a defense. Nothing here targets real users or sites.