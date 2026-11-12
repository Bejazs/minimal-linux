# Static analysis image for Chrome extensions. Run it through bin/ext-analyze,
# which adds --network none, --read-only, --cap-drop ALL and a non-root user.
FROM python:3.12-slim-bookworm

# wabt: wasm2wat, to turn WebAssembly modules into readable text
RUN apt-get update \
 && apt-get install -y --no-install-recommends wabt \
 && rm -rf /var/lib/apt/lists/*

# Pinned deps: jsbeautifier (readable copies of minified code), yara-python (validates generated rules),
# tree-sitter + JavaScript grammar (syntax trees for reachability and data flows; prebuilt wheels)
RUN pip install --no-cache-dir --only-binary=tree-sitter,tree-sitter-javascript \
      jsbeautifier==1.15.1 yara-python==4.5.4 tree-sitter==0.26.1 tree-sitter-javascript==0.25.0 \
 && python3 -c "import tree_sitter_javascript, tree_sitter; tree_sitter.Language(tree_sitter_javascript.language())"

COPY extanalyzer /opt/extanalyzer/extanalyzer
COPY intel /opt/extanalyzer/intel
ENV PYTHONPATH=/opt/extanalyzer PYTHONDONTWRITEBYTECODE=1

USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["python3", "-m", "extanalyzer", "--out", "/out"]
