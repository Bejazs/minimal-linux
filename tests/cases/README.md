# Synthetic cases

One positive and one negative case per combination rule (`*-pos`/`*-neg`) and per detector
(`b1-…` to `b9-…`), a reachability case, and report-quality cases (`ioc-reference`, `library-known`,
`nonext-content`, `line-mapping`, `vendor-*`, `disclosure-mismatch-*`) checked in `ReportQualityTests`.
They are minimal, non-functional shapes of each pattern (hosts use `.invalid`/`example.com`),
written to exercise the analyzer, never to run. The negative case is the closest legitimate
pattern. `expected.json` keys: `present`, `absent`, `unreachable` (rule ids), `label`,
`not_label`, `min_severity`, `max_severity` (`{rule: severity}`).
