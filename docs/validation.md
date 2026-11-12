# Validation report (v0.2)

This report covers what can be measured without real extensions: the synthetic cases, and benign
JavaScript bundles analysed as if they were extensions. Detection rates on real benign and malicious
corpora have to be measured on the analysis instance with `ext-analyze --validate` (below), because
real samples, and malware above all, are not handled outside that instance.

## 1. Synthetic cases (`tests/cases/`, run in CI)

Each combination rule and each detector has a positive case and a negative one. The negative case is
the closest legitimate pattern. Hosts use `.invalid`/`example.*`, and no case is a working attack.
Regenerate this table with
`PYTHONPATH=static python3 -m extanalyzer --validate-cases tests/cases --out /tmp/v`.

| Case | Expected | v0.2 label | v0.1 label | Result |
|---|---|---|---|---|
| auth-proxy-neg | absent: COMB-AUTH-PROXY; not_label: malicious | low_risk | low_risk | pass |
| auth-proxy-pos | present: COMB-AUTH-PROXY; label: malicious | malicious | low_risk | pass |
| b1-session-send-neg | absent: DET-SESSION-SEND, COMB-SESSION-EXFIL | low_risk | low_risk | pass |
| b1-session-send-pos | present: DET-SESSION-SEND | malicious | low_risk | pass |
| b2-cred-dynurl-neg | absent: DET-CRED-DYNURL | low_risk | low_risk | pass |
| b2-cred-dynurl-pos | present: DET-CRED-DYNURL; not_label: malicious | suspicious | low_risk | pass |
| b3-cmd-dispatch-neg | absent: DET-CMD-DISPATCH, COMB-C2 | low_risk | low_risk | pass |
| b3-cmd-dispatch-pos | present: DET-CMD-DISPATCH; label: likely_malicious | likely_malicious | low_risk | pass |
| b4-weak-origin-neg | absent: DET-WEAK-ORIGIN | low_risk | low_risk | pass |
| b4-weak-origin-pos | present: DET-WEAK-ORIGIN | low_risk | low_risk | pass |
| b5-hidden-window-neg | absent: DET-HIDDEN-WINDOW | low_risk | low_risk | pass |
| b5-hidden-window-pos | present: DET-HIDDEN-WINDOW | low_risk | low_risk | pass |
| b6-identity-headers-neg | absent: DET-IDENTITY-HEADERS | low_risk | low_risk | pass |
| b6-identity-headers-pos | present: DET-IDENTITY-HEADERS | low_risk | low_risk | pass |
| b7-obf-string-neg | absent: DET-OBF-STRING | low_risk | low_risk | pass |
| b7-obf-string-pos | present: DET-OBF-STRING | suspicious | low_risk | pass |
| b8-code-inject-neg | max_severity: DET-CODE-INJECT ≤ low | low_risk | low_risk | pass |
| b8-code-inject-pos | present: DET-CODE-INJECT | suspicious | low_risk | pass |
| b9-forced-ui-neg | absent: DET-FORCED-UI | low_risk | low_risk | pass |
| b9-forced-ui-pos | present: DET-FORCED-UI | low_risk | low_risk | pass |
| c2-neg | absent: COMB-C2; not_label: malicious | low_risk | low_risk | pass |
| c2-pos | present: COMB-C2; label: likely_malicious | likely_malicious | low_risk | pass |
| dead-code | present: COMB-REMOTE-CODE; unreachable: COMB-REMOTE-CODE; not_label: malicious | low_risk | low_risk | pass |
| disclosure-mismatch-neg | absent: PRIV-DISCLOSURE | low_risk | low_risk | pass |
| disclosure-mismatch-pos | present: PRIV-DISCLOSURE; label: low_risk | low_risk | low_risk | pass |
| input-exfil-neg | absent: COMB-INPUT-EXFIL; not_label: malicious | low_risk | low_risk | pass |
| input-exfil-pos | present: COMB-INPUT-EXFIL; label: malicious | malicious | low_risk | pass |
| ioc-reference | label: low_risk | low_risk | low_risk | pass |
| library-known | present: CODE-OBF; label: low_risk | low_risk | low_risk | pass |
| line-mapping | present: CODE-EVAL | low_risk | low_risk | pass |
| nonext-content | present: PKG-NONEXT | suspicious | low_risk | pass |
| remote-code-neg | absent: COMB-REMOTE-CODE; not_label: malicious | low_risk | low_risk | pass |
| remote-code-pos | present: COMB-REMOTE-CODE; label: malicious | malicious | low_risk | pass |
| session-exfil-neg | absent: COMB-SESSION-EXFIL; not_label: malicious | low_risk | low_risk | pass |
| session-exfil-pos | present: COMB-SESSION-EXFIL; label: malicious | malicious | suspicious | pass |
| vendor-multi | present: VENDOR-MULTI; label: low_risk | low_risk | low_risk | pass |
| vendor-single | absent: VENDOR-MULTI | low_risk | low_risk | pass |

What it shows: every positive fires and every negative stays quiet. v0.1 labels all but one positive
`low_risk`, because a few medium findings never added up to its thresholds. That is the main gap
v0.2 closes. Some positives stay `low_risk` on purpose: B4, B5, B6 and B9 each add to the score but do
not decide the label alone. The cases are small, so these numbers say the rules behave as documented.
They do not measure detection on real extensions.

## 2. Benign bundles (false-positive check)

Large public JavaScript files, each analysed statically as the background *and* content script of an
otherwise empty extension. That is a harsher setting than real extensions, because everything is
reachable and runs on all pages. Measured on 2026-11-12 with 0.2.2 (0.2.3 only adds validation):

| Bundle | Size | v0.2 | v0.1 | Detector/COMB findings | Domains code / data-only | Time |
|---|---|---|---|---|---|---|
| yarn cli | 5.1 MB | low_risk (29) | low_risk | 8 × DET-CODE-INJECT low (`Function`/`eval` on non-literals) | 5 / 74 | 22 s |
| playwright coreBundle | 3.4 MB | suspicious (47) | suspicious | 6 × DET-CODE-INJECT low, 1 medium (computed script src) | 5 / 10 | 13 s |
| jQuery 3.6.1 | 284 KB | low_risk | low_risk | none (library: jQuery) | 0 / 16 | < 1 s |
| axios (UMD and ESM) | 192 / 152 KB | low_risk | low_risk | none (library: Axios) | 0 / 3 | < 1 s |
| prettier babel plugin | 316 KB | low_risk | low_risk | none | 0 / 0 | 2 s |

No label changed between v0.1 and v0.2 on these bundles. Playwright is `suspicious` under both: it
does evaluate code it builds at runtime, and that is what both versions report.

## 3. Real corpora (on the analysis instance)

```
~/corpus/benign/<category>/<sample>      ad blockers, VPN, password managers, productivity, dev, accessibility, SEO
~/corpus/malicious/<category>/<sample>   cookie exfiltration, remote proxy, command channel, ad injection, credential theft

ext-analyze --validate ~/corpus                                   # first run
ext-analyze --validate ~/corpus --baseline ~/analysis/out/validation-<date>/validation/results.json
```

The run happens in the same offline, read-only container as a normal analysis. It writes
`validation/results.json` and `validation/report.md` with:

- the detection rate per malicious category, for v0.2 and for v0.1 from the same run;
- the false-positive rate per benign category;
- every critical/high finding in benign samples, for manual review;
- malicious samples that were not detected;
- label changes against the baseline, matched by SHA-256.

Both files hold verdicts, rule ids, titles and `path:line` only, never code or snippets from the
samples, so they can be shared without sharing malware.

There is no separate `ext-static:v0.1` image: each report keeps `score_v0.1` next to `score_v0.2`, so
one run gives the before/after comparison. `--baseline` compares two runs of the corpus, for example
before and after a rule change.
