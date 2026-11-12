# ext-analyze rules (v0.2)

How the verdict is built, and every combination rule and detector with its condition, the
closest legitimate pattern it must not fire on, and its ATT&CK mapping. The engine contains
no IOC literals for these rules; they look only at code structure.

## Pipeline

1. **Unpack** (`unpack.py`): `.crx`/`.zip`/folder, with traversal, symlink and size guards.
2. **Manifest and pattern scan** (`manifest.py`, `code_scan.py`): the v0.1 detectors.
3. **Syntax trees** (`jsast.py`): tree-sitter parses every `.js` and each inline `<script>`.
   Minified files are parsed in their beautified copy, so line numbers match the findings.
4. **Reachability** (`reach.py`): entry points from the manifest, then a reference graph.
   Every finding gets `reachability`: `reachable`, `unreachable`, `unknown` (file not parsed)
   or `n/a` (manifest, non-code files).
5. **Flows** (`flows.py`): source → sink taint tracking inside functions and their callbacks.
6. **Combination rules** (`combine.py`): below. Written to `behaviors.json`.
7. **Detectors** (`detectors.py`): B1–B9, below. Written to `behaviors.json` (`detectors[]`).
8. **Score** (`score.py`): `score_v0.1` and `score_v0.2`, both in `report.json`.

## Reachability

Entry points: `background` (service worker, scripts, page), `content_scripts[].js`, popups
(`action`, `browser_action`, `page_action`), `options_page`/`options_ui`, `devtools_page`,
`side_panel`, `chrome_url_overrides`, `sandbox.pages`, `web_accessible_resources` (globs),
and the scripts each of those pages loads.

From reached code, a function is reached when:

- reached code mentions its name (a call, a reference, `addListener(handler)`), or
- it is an inline function (callback argument, object/array value, method, IIFE) inside reached code, or
- reached code names its file in a string (`getURL`, `executeScript({files})`, `importScripts`, `new Worker`).

Limits, on purpose biased towards keeping code reachable:

- names resolve package-wide without lexical scope, so a name collision makes code reachable, never less;
- `obj[k]()` and other computed calls are not resolved; anything referenced as a value stays reachable;
- a file that fails to parse is `unknown` and still counts for the score.

## Flow sources and sinks

| Kind | Examples |
| --- | --- |
| source `session` | `chrome.cookies.get/getAll`, `document.cookie`, `localStorage`, `sessionStorage` |
| source `input` | parameters of `keydown/keypress/keyup/input/change/submit` listeners, password fields |
| source `network` | `fetch`/XHR/axios/`$.ajax` responses |
| source `message` | `chrome.runtime.onMessage(External)`, ports, window `message` events |
| source `storage` | `chrome.storage.*.get` |
| source `auth-response` | response of a credentialed request whose URL came from network/message/storage |
| sink `network-send` | `fetch` body/headers/URL data, `XMLHttpRequest.send`, `sendBeacon`, `WebSocket.send`, `*.src =` |
| sink `code-exec` | `eval`, `Function`, string timers, `executeScript({code/files})`, `importScripts`, script `src` from data |
| sink `privileged` | `chrome.tabs.create/update`, `chrome.windows.*`, `chrome.scripting.*`, location changes, request URL from data (`fetch`, `XMLHttpRequest.open`) |
| sink `dispatch` | `switch` on network data whose branches use privileged APIs; `handlers[cmd]()` keyed by network data |

WebSocket messages (`ws.onmessage`, `ws.addEventListener("message")` on a `new WebSocket(...)`) are
`network`; `xhr.withCredentials = true` marks that object's requests as credentialed.

Variables are tracked per function scope (closures read enclosing scopes), plus one step into a
named function that receives tainted arguments. Taint does not cross `chrome.storage` between
runs, generic event buses, or other contexts except through message listeners as sources.

**Destination classes.** `primary`: registrable domain of `homepage_url`, explicit (non-wildcard)
`host_permissions` hosts (MV2: host patterns in `permissions`) or `externally_connectable` matches.
`self`: relative or `chrome-extension://` URLs. `third_party`: any other literal host. `unknown`:
URL computed at runtime (rules still fire, with confidence `medium`).

## Combination rules

| Rule | Condition (reachable code) | Severity | Not fired on (closest legitimate pattern) | ATT&CK |
| --- | --- | --- | --- | --- |
| COMB-SESSION-EXFIL | `session` data reaches `network-send` to `third_party`/`unknown` | critical | session data sent to the extension's own declared API (`tests/cases/session-exfil-neg`) | T1539, T1041 |
| COMB-INPUT-EXFIL | `input` data in a content script reaches `network-send` to `third_party`/`unknown` | critical | keyboard shortcut that only messages the background (`input-exfil-neg`) | T1056.001, T1056.003, T1041 |
| COMB-REMOTE-CODE | `network` data reaches `code-exec` | critical | remote JSON stored as data (`remote-code-neg`) | T1105, T1059.007 |
| COMB-C2 | in code run from `setInterval`/`chrome.alarms`, `network` data reaches `privileged` or `code-exec` | high; critical if COMB-SESSION-EXFIL also fires | periodic list refresh stored as data (`c2-neg`) | T1071.001, T1102, T1059.007 — gap: no technique for remote task execution in end-user browsers |
| COMB-AUTH-PROXY | `auth-response` reaches `network-send` | critical | credentialed call to a fixed own API (`auth-proxy-neg`) | T1185, T1041 — gap: browser-session proxying has no dedicated technique |

Each match becomes a finding (`category: behavior`) with the flow in its reason, a snippet at
the sink, and an entry in `behaviors.json` (`combinations[]`, with the full flow).

## Detectors (B1–B9)

Single-pattern detectors (`category: detector`, ids `DET-*`). They raise the score but, unlike the
combination rules, do not decide the label on their own, except where noted.

| Id (plan) | Condition | Severity | Not fired on (closest legitimate pattern) | ATT&CK |
| --- | --- | --- | --- | --- |
| DET-SESSION-SEND (B1) | `session` flow to `network-send` (body, URL or headers) whose destination is not `primary`/`self` | high (critical via COMB-SESSION-EXFIL) | sync to the declared API (`b1-session-send-neg`) | T1539, T1041 |
| DET-CRED-DYNURL (B2) | `credentials:'include'`/`withCredentials` request whose URL comes from network/message/storage | high (critical via COMB-AUTH-PROXY) | credentialed call to a constant own URL (`b2-…-neg`) | T1185 |
| DET-CMD-DISPATCH (B3) | `dispatch` flow: network/WebSocket data picks a privileged branch or handler | high; switch form raises the label to at least `likely_malicious` | remote config whose branches only store data (`b3-…-neg`) | T1071.001, T1102 — gap: remote tasks in browsers |
| DET-WEAK-ORIGIN (B4) | in a `message`/`onMessage(External)`/`onConnect(External)` handler: `origin`/`url`/`hostname` tested with `indexOf`/`includes`/`match`/`search`, an unanchored regex, `startsWith` without a `/` after the host, or `endsWith` without a leading `.` | high if the handler uses privileged APIs, else medium | strict equality, exact allow-list (`b4-…-neg`) | gap: a vulnerability, not a technique |
| DET-HIDDEN-WINDOW (B5) | `windows.create/update` with width/height ≤ 100, left/top < 0 or ≥ 10000, `state:'minimized'`; `focused:false` alone is low | medium; high with `idle.queryState`/`onStateChanged` in the package | normal popup window (`b5-…-neg`) | T1564.003; + T1497.002 with idle gating |
| DET-IDENTITY-HEADERS (B6) | `requestHeaders` set/remove of `user-agent`, `referer`, `sec-ch-ua*`, `sec-fetch-*` in `updateDynamicRules`/`updateSessionRules`, static rulesets of the manifest, or `webRequest.onBeforeSendHeaders` | medium; high with DET-CRED-DYNURL | non-identity header such as `x-client-version` (`b6-…-neg`) | gap; + T1185 with B2 |
| DET-OBF-STRING (B7) | a URL, domain or sensitive API name recovered by folding `String.fromCharCode` (numeric literals, XOR/arithmetics), array `join`, `split/reverse/join`, `atob`/percent-decoding of literals, or concatenation where no single fragment holds the host/name | high if the value feeds network/cookie APIs or a computed property (`chrome[k]`), else medium | ordinary text from `fromCharCode`, URL built from a base constant (`b7-…-neg`) | T1027 |
| DET-CODE-INJECT (B8) | `executeScript` with `code` (high if non-constant) or computed `files`; `eval`/`Function` on data from a source (high) or on an unresolved non-literal (low); script element `src` remote or computed | high/medium; `executeScript({func, args})` is low | packaged `func`/`files` (`b8-…-neg`, low only) | T1059.007; + T1105 for remote data |
| DET-FORCED-UI (B9) | `alert`/`confirm`/`prompt` in a content script and a reachable `windows.update` with `focused:true`, `drawAttention:true` or `state` `maximized`/`fullscreen` | medium, confidence low | dialog on its own (`b9-…-neg`) | gap: UI coercion |

B7 folds literals only (depth 40, 4096 characters) in Python; no JavaScript is evaluated. Detectors
are capped at 50 findings each per sample.

## Score

- **v0.1** (`score_v0.1`): previous method, unchanged. Sum of severity × confidence over the v0.1
  findings (all code, reachable or not), max 3 per rule, capped at 100.
- **v0.2** (`score_v0.2`, also `verdict`): the same sum over findings that are not `unreachable`,
  including behaviour findings (critical = 50). Then:
  - any reachable **critical** combination rule → `malicious`, score 100;
  - a reachable **high/high** combination rule (COMB-C2) or DET-CMD-DISPATCH (switch form) → at least
    `likely_malicious` (70);
  - otherwise `likely_malicious` (≥ 70 and a high/high finding), `suspicious` (≥ 30), `low_risk`.
- Unreachable findings stay in the report (own section) and in `report.json`; the count excluded
  is in `score_v0.2.unreachable_findings_excluded`.

## Adding a rule or detector

Detectors: add an entry to `detectors.DETECTORS`, a `det_*` function called from `analyze()`, a
positive and a negative case in `tests/cases/`, and a row in the table above.


1. Add it to `combine.RULES` (title, severity, attack, attack_gap, why) and its condition to `evaluate()`.
2. Add `tests/cases/<rule>-pos` and `<rule>-neg`: minimal, non-functional shapes using
   `.invalid`/`example.com` hosts, the negative being the closest legitimate pattern.
3. Document it in the table above.
