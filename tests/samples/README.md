# Synthetic test samples

Hand-written, inert extensions used only by `tests/test_analyzer.py`.
They are never loaded in a browser. The "suspicious" ones contain the
*patterns* the analyzer looks for (fetch feeding eval, a keyboard listener
next to a network send, an off-store `update_url`), pointing at reserved
`example.net` / `example.org` domains. Do not add real malware to this repo.
