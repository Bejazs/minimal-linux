# Static analysis image for Chrome extensions. Run it through bin/ext-analyze,
# which adds --network none, --read-only, --cap-drop ALL and a non-root user.
FROM python:3.12-slim-bookworm

# wabt: wasm2wat, to turn WebAssembly modules into readable text
RUN apt-get update \
 && apt-get install -y --no-install-recommends wabt \
 && rm -rf /var/lib/apt/lists/*

# Pinned deps: jsbeautifier (readable copies of minified code), yara-python (validates generated rules)
RUN pip install --no-cache-dir jsbeautifier==1.15.1 yara-python==4.5.4

COPY extanalyzer /opt/extanalyzer/extanalyzer
ENV PYTHONPATH=/opt/extanalyzer PYTHONDONTWRITEBYTECODE=1

USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["python3", "-m", "extanalyzer", "--out", "/out"]
