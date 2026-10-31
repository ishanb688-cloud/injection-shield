# Threat model

## What is being protected

Private data and behavior of an AI assistant that reads untrusted content on a user's behalf (names, tokens and anything else in its prompt), and the user's trust in its answers.

## The attacker

Controls the content of a page, message or document that the assistant reads. Does not control the assistant, the model or the user's device.

## In scope (and tested)

| Technique | Layer that handles it |
|---|---|
| Text the user cannot see: one-pixel text, text the color of the background, `display:none`, off-screen text, zero opacity | Layer 1 |
| Instructions inside HTML comments | Layer 1 |
| Zero-width characters and messages hidden in invisible Unicode tag characters | Layer 1 |
| Blunt visible instructions ("ignore all previous instructions...") | Layer 2 |
| Requests that make the answer carry a secret out, such as an auto-loading image whose address contains it | Layers 2 and 3 |
| Any of the above that reaches the answer | Layer 3 redacts registered secrets and removes images and outside links |

## Known gaps (tested and documented)

- **Text hidden through stylesheet classes** is not read by the server-side Layer 1, which only parses inline styles. The browser extension reads real computed styles and does not have this gap. See `attack_h2_stylesheet.html`.
- **Politely worded requests** with no known pattern pass Layer 2 (`attack_h3_polite.html`, `attack_subtle.html`). Only Layer 3 stops them, and only for secrets the application registered.
- **False positives**: an article about prompt injection is blocked because it quotes attack phrases (`clean_h4_prompt_article.html`).

## Out of scope or untested

- Attacks carried by images, audio, PDFs, scripts or other tools' outputs
- Instructions in other languages, encodings such as base64, look-alike characters and spelling tricks
- Instructions split across several elements or several turns
- Content inside frames or shadow DOM (extension)
- Attacks on the model itself, such as jailbreaks
- A leak of a secret the application did not register with Layer 3
- Denial of service against the hosted dashboard beyond input-size limits

## Assumptions

- The application registers the secrets Layer 3 should protect.
- The shield is one layer of defense. It does not replace least-privilege design for the assistant itself.
- The evaluation assistant is deliberately naive. Real assistants may be more or less robust.

## Residual risk

A determined attacker who knows the rules can reword around them. The rules are a starting point, and the roadmap adds a larger benchmark and a trained classifier to measure whether that gap can be narrowed.
