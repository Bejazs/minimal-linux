# ext-analyze rules (v0.2)

How the verdict is built, and every combination rule with its condition, the closest
legitimate pattern it must not fire on, and its ATT&CK mapping. The engine contains
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
7. **Score** (`score.py`): `score_v0.1` and `score_v0.2`, both in `report.json`.

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
| sink `privileged` | `chrome.tabs.create/update`, `chrome.windows.*`, `chrome.scripting.*`, location changes, request URL from data |

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

## Score

- **v0.1** (`score_v0.1`): previous method, unchanged. Sum of severity × confidence over the v0.1
  findings (all code, reachable or not), max 3 per rule, capped at 100.
- **v0.2** (`score_v0.2`, also `verdict`): the same sum over findings that are not `unreachable`,
  including behaviour findings (critical = 50). Then:
  - any reachable **critical** combination rule → `malicious`, score 100;
  - a reachable **high/high** combination rule (COMB-C2) → at least `likely_malicious` (70);
  - otherwise `likely_malicious` (≥ 70 and a high/high finding), `suspicious` (≥ 30), `low_risk`.
- Unreachable findings stay in the report (own section) and in `report.json`; the count excluded
  is in `score_v0.2.unreachable_findings_excluded`.

## Adding a rule

1. Add it to `combine.RULES` (title, severity, attack, attack_gap, why) and its condition to `evaluate()`.
2. Add `tests/cases/<rule>-pos` and `<rule>-neg`: minimal, non-functional shapes using
   `.invalid`/`example.com` hosts, the negative being the closest legitimate pattern.
3. Document it in the table above.
