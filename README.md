# minimal-linux

Setup script and offline static analyzer for threat-hunting Chrome extensions (MV2/MV3) on throwaway cloud VMs, used through Chrome Remote Desktop.

Two modes, **one instance each**, so LLM credentials and extension execution never share a machine:

| | `static` (default) | `gui` |
|---|---|---|
| Purpose | Static analysis, one command per sample, batch, version diff | Interactive/dynamic analysis with Burp/ZAP and a test account |
| Extension code runs? | **Never**: read only, inside an offline container | Yes, in Chrome on this instance only |
| LLM (Antigravity, Claude Code) | Yes, restricted to `~/analysis` | **No** |
| Installs | CRD, XFCE, Chrome (installed with CRD; never load samples in it), VS Code, Docker, `ext-analyze`, Antigravity, Claude Code | CRD, XFCE, Chrome + FoxyProxy policy, CDP launcher, Burp CE, ZAP, Java, Node 20, uv + crx-analyzer, VS Code + extensions, SecLists (optional) |

## Install

Ubuntu 24.04 LTS, run as your normal user with sudo:

```bash
git clone https://github.com/Bejazs/minimal-linux.git && cd minimal-linux
sudo ./setup_vm.sh --mode static          # or: --mode gui [--seclists]
```

The script asks for the Chrome Remote Desktop command from <https://remotedesktop.google.com/headless> (Begin → Next → copy the command). You can also pass it as the last argument. Without `--mode` it asks which mode to install.

Everything after the prompts is shown on screen and written to `/var/log/minimal-linux-setup.log` (root only; the CRD code is not logged). Follow it from a second SSH session with `sudo tail -f /var/log/minimal-linux-setup.log`. apt gives up on a stalled mirror after 30 s per attempt (3 retries).

Outbound access needed: Ubuntu mirrors, dl.google.com, snapcraft. Static also needs Docker Hub, deb.debian.org, PyPI, antigravity.google, claude.ai, tranco-list.eu, publicsuffix.org and (optional) urlhaus-api.abuse.ch; gui also needs portswigger.net, api.github.com/github.com, deb.nodesource.com and astral.sh.

## Static mode: `ext-analyze`

After install, log out and back in once (docker group). Then:

```bash
ext-analyze ~/analysis/samples/suspect.crx            # .crx (v2/v3), .zip or unpacked folder
ext-analyze ~/analysis/samples/*                      # batch
ext-analyze --diff old-1.2.0.crx new-1.3.0.crx        # what changed between versions
```

Each sample runs in its own `ext-static` container with `--network none`, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, your UID (not root), CPU/memory/PID limits, and the sample mounted read-only. The archive is unpacked with path-traversal, symlink and size checks. Nothing in the extension is executed.

Output per sample in `~/analysis/out/<name>-<sha256[:12]>/`:

| File | Content |
|---|---|
| `report.json` | Machine-readable: sample metadata and hashes, extension ID (from CRX3 header or manifest key), verdict (`score_v0.2`; `score_v0.1` kept beside it for comparison), ATT&CK techniques, findings (each with `reachability`), reachability summary, IOCs, file inventory |
| `behaviors.json` | Entry points, reachable/unreachable files and functions, source → sink data flows, the combination rules that fired and the detector matches (B1–B9) |
| `report.md` | Human summary. Every finding has severity, **confidence (high/medium/low) with the reason**, `path:line`, reachability, and a code snippet (2 lines of context, URLs defanged). Findings in code no entry point reaches are listed separately and not scored |
| `iocs.csv` | Domains, URLs, IPs, other extension IDs, with first location, Tranco rank, URLhaus hits and `reference` (`code-referenced` or `data-only`) |
| `rule.yar` | YARA rule from sample-specific, code-referenced domains/URLs, validated against the sample |
| `sigma/proxy.yml`, `sigma/dns.yml` | Sigma rules for the network IOCs (common domains like googleapis/discord excluded) |
| `unpacked/` | Extracted files; `unpacked/_deob/` has beautified copies of minified/obfuscated JS and `.wat` for WASM |

### Domain lists (offline enrichment)

```bash
ext-analyze --update-lists      # on the host, with network; re-run whenever you want fresher data
```

Downloads public lists to `~/.cache/ext-analyze/lists/`, which is mounted read-only into the container (still `--network none`). Domains are checked locally, so no IOC is sent to any service.

| List | Source | Used for |
|---|---|---|
| Tranco top 1M | tranco-list.eu | `tranco_rank`; registrable domains in the top 10 000 are marked `common` (kept as IOCs, left out of YARA/Sigma) |
| Public Suffix List | publicsuffix.org | `registrable_domain` (`a.b.example.co.uk` → `example.co.uk`) |
| URLhaus (recent) | abuse.ch | exact host match → `urlhaus_hits` and a high/high `IOC-URLHAUS` finding; never `common` |

URLhaus downloads need a free abuse.ch Auth-Key: save it in `~/.config/ext-analyze/urlhaus.key` (`chmod 600`). The key goes in the download URL, as abuse.ch requires, and is not printed. Without it URLhaus is skipped. The report lists which lists were used and their dates. Without any lists the analysis still runs, with a warning. Setup runs `--update-lists` once (Tranco + PSL).

### Intel

```bash
intel-add domain bad.example --source "where it comes from, reviewed by whom" --confidence high [--expires 2027-01-01]
intel-add --check
```

Built-in lists are in `static/intel/` (ignore lists, libraries, disclosure synonyms; the indicator lists start empty). Your own entries go to `~/analysis/intel/`, which is mounted read-only over the built-in lists. Each entry needs a source and a confidence, and expired entries are ignored with a warning. Only IOCs that reachable code references, with high-confidence intel, change the verdict. IOCs that only appear as data (JSON lists, dead code, documentation links) are listed per file and do not go into YARA/Sigma.

### Validation

```bash
ext-analyze --validate ~/corpus [--baseline old/results.json]   # corpus/{benign,malicious}/<category>/<sample>
```

Gives detection and false-positive rates per category, the critical/high findings in benign samples, and changes against a baseline. It writes no sample code, so `validation/report.md` can be shared. Results on the synthetic cases and on benign bundles are in [docs/validation.md](docs/validation.md).

### Verdict (v0.2)

The verdict comes from **combination rules** on data flows in reachable code, then from the score:

- `malicious`: a critical combination rule fired, e.g. cookies or typed input sent to a third-party host, network data executed as code, or authenticated requests to remotely chosen URLs relayed back out;
- `likely_malicious`: a remote command channel (periodic poll, or socket/network data choosing tab/scripting actions), or score ≥ 70 with a high/high finding;
- `suspicious`: score ≥ 30; `low_risk`: below.

Nine **detectors** add findings (`DET-*`, `category: detector`): session data sent to non-primary hosts, credentialed requests to URLs from data, command dispatch on network data, weak origin checks in message handlers, hidden windows (with idle gating), identity-header rewriting (code and static rulesets), URLs/API names hidden with `fromCharCode`/arrays/`atob`/split strings (folded statically, never run), code injection, and dialogs combined with forced window focus.

The report also marks known libraries, which lose one confidence step and get no obfuscation finding. It flags executables and server scripts inside the package, lists brand domains (more than one is flagged for review), and compares the data sent with what the extension's texts disclose (privacy, not scored). Each finding gives the original minified position as `file:line:column` next to the beautified line.

Reachability starts from the manifest's entry points (background, content scripts, extension pages, `web_accessible_resources`). Findings in code nothing reaches are kept in the report but do not count. Every rule, its closest legitimate pattern and its limits are in [docs/rules.md](docs/rules.md). The previous method stays in `report.json` as `score_v0.1`.

Confidence scale: **high** = confirmed by the code flow (e.g. `fetch()` result passed to `eval()` a few lines later); **medium** = dangerous pattern that also has common legitimate uses; **low** = heuristic only. For beautified files, `location.lines_refer_to` points at the `_deob` copy the line numbers belong to.

What it checks: dangerous permissions and host access, content scripts on all sites, CSP (`unsafe-eval`, remote script sources), `externally_connectable`, `update_url` outside the Web Store, `web_accessible_resources`; remote code (`eval`/`Function`/string timers/`importScripts`/remote `src`/`executeScript` fed by network data, `eval(atob(...))`), cookie/history/clipboard/screen collection, keyboard listeners and password fields in content scripts next to network sends, disabling other extensions, debugger, proxy changes, CSP header stripping, Discord/Telegram exfil endpoints, sandbox/headless checks, long delays, crypto addresses, obfuscation signals, WASM.

Limits: static only, so remotely delivered or delayed payloads are only visible as the loader pattern. Data flows are tracked inside a function, its callbacks and one call deep, not through storage between runs (see docs/rules.md). No vulnerable-library database yet (retire.js needs network for its DB).

### Using the LLM safely

`~/analysis/.claude/settings.json` applies to Claude Code sessions started in `~/analysis`: no `Bash`, `WebFetch`, `WebSearch` or MCP tools, no reads outside the folder, bypass mode disabled. Run `cd ~/analysis && claude` and point it at `out/<sample>/report.json`. `AGENTS.md` (shared by Antigravity and, via `~/.claude/CLAUDE.md`, Claude Code) tells both agents that sample content is untrusted data and never instructions. Check with `/status` and `/permissions` in Claude Code.

## GUI mode

For loading an extension and watching its traffic. Use a **separate instance**, a throwaway Chrome profile (`~/launch-chrome-debug.sh` uses `/tmp/chrome-debug` with CDP on 9222), and only a test account. Never put LLM credentials or a real Google session on this instance, and destroy it after the session.

Burp is installed with a 15-minute time limit; if the PortSwigger download is not an installer, it is skipped with a warning.

### To manually set the proxy in chrome
If you want to configure Chrome to use a local proxy (like Burp Suite or ZAP Proxy) on `127.0.0.1:8080`, you can execute the following command:
```bash
sudo mkdir -p "/etc/opt/chrome/policies/managed"
sudo tee "/etc/opt/chrome/policies/managed/proxy.json" > /dev/null <<EOF
{
  "ProxyMode": "fixed_servers",
  "ProxyServer": "127.0.0.1:8080",
  "ProxyBypassList": "localhost,127.0.0.1"
}
EOF
```

### To manually trust ZAP / Burp Certificate
If you are using a proxy like ZAP, you'll need to manually install its Root CA Certificate into Chrome's NSS database.

1. **Start ZAP Proxy** locally to generate the `config.xml` file.
2. Use the following commands to extract the CA Certificate and install it into Chrome's database:

```bash
# Set your user home path
USER_HOME=~

# Extract Base64 certificate from config.xml
awk -F'[<>]' '/<certificate>/{print $3}' "${USER_HOME}/.ZAP/config.xml" > "${USER_HOME}/zap_ca_base64.txt"

# Format as valid PEM
echo "-----BEGIN CERTIFICATE-----" > "${USER_HOME}/zap_ca.crt"
fold -w 64 "${USER_HOME}/zap_ca_base64.txt" >> "${USER_HOME}/zap_ca.crt"
echo "-----END CERTIFICATE-----" >> "${USER_HOME}/zap_ca.crt"

# Create NSS DB if it doesn't exist
mkdir -p "${USER_HOME}/.pki/nssdb"
if [ ! -f "${USER_HOME}/.pki/nssdb/cert9.db" ]; then
    certutil -d sql:${USER_HOME}/.pki/nssdb -N --empty-password
fi

# Import the certificate
certutil -d sql:${USER_HOME}/.pki/nssdb -A -t "C,," -n "ZAP Root CA" -i "${USER_HOME}/zap_ca.crt"

# Cleanup temp files
rm "${USER_HOME}/zap_ca_base64.txt" "${USER_HOME}/zap_ca.crt"
```
*(For Burp Suite, you can export its certificate via the UI and import it using the `certutil` command above).*


## Development

```bash
PYTHONPATH=static python3 -m unittest discover -s tests -v   # needs: pip install jsbeautifier yara-python tree-sitter tree-sitter-javascript
docker build -t ext-static:latest static && bin/ext-analyze tests/samples/suspicious-helper-1.1
```

`tests/samples/` holds small, inert, hand-written extensions (benign and "suspicious" patterns pointing at reserved `example.*` domains). `tests/cases/` has one positive and one negative synthetic case per combination rule, plus a dead-code case. Never commit real malware. CI runs the unit tests and shellcheck.

## Default settings

- **Remote Desktop PIN**: `123456` (change `PRE_CONFIGURED_PIN` in `setup_vm.sh`)
- **Timezone**: Europe/Lisbon
