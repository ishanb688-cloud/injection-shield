# Injection Shield browser extension (experimental, v0.2.0)

Scans the page you are on for text meant for an AI assistant rather than for you, and can remove hidden text from the page.

## Install (Chrome or Edge)

1. Open `chrome://extensions` (Edge: `edge://extensions`).
2. Turn on **Developer mode**.
3. Click **Load unpacked** and choose **this `extension` folder** (not the whole project).
4. Pin **Injection Shield** to the toolbar.

## Use

Open a page, click the icon, click **Scan this page**. Hidden findings can be removed with **Remove hidden text**. Visible findings are outlined in red on the page. Reloading the page restores it.

## What it checks

It reads each text block with the browser's real computed styles, so it also sees text hidden through stylesheet classes (which the server-side shield cannot). A block is reported only if it is hidden **or** visible and also contains wording aimed at an AI (for example "Note to the AI assistant", "ignore your previous instructions", requests for a token or profile). Hidden text without such wording is ignored, to avoid flooding you with harmless hidden menus.

## Privacy

- It runs entirely on your device and makes **no network requests**.
- It stores nothing and has no background process.
- Permissions: `activeTab` (only the page you click it on) and `scripting` (to run the scan on that page).

## Limits

- It cannot scan browser pages such as `chrome://` or the extension store.
- It reads only the main document, not frames or shadow DOM.
- It matches a small list of patterns. Reworded or translated instructions can slip past it, and a legitimate page containing chat transcripts ("Assistant: ...") can be flagged.
- It protects only tools that read what is in your browser. An assistant that fetches pages by itself is not affected.
- It has not been evaluated on real-world sites.
