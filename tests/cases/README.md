# Synthetic cases

One positive and one negative case per combination rule, plus a reachability case.
They are minimal, non-functional shapes of each pattern (hosts use `.invalid`/`example.com`),
written to exercise the analyzer, never to run. The negative case is the closest legitimate
pattern. `expected.json` keys: `present`, `absent`, `unreachable` (rule ids), `label`,
`not_label`, `min_severity`.
