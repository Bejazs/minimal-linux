#!/bin/bash

# Set variables:
PRE_CONFIGURED_PIN="123456"
TIMEZONE="Europe/Lisbon"

# set timezone if a variable is defined
if [ -n "${TIMEZONE}" ]; then
  sudo timedatectl set-timezone ${TIMEZONE}
fi

# Function to extract code from Chrome Remote Desktop command
extract_chrome_code() {
    local full_command="$1"
    # Extract the code between quotes after --code=
    echo "$full_command" | grep -oP '(?<=--code=")[^"]*'
}

# Read Chrome Remote Desktop code from command line argument or prompt user
if [ -n "$1" ]; then
    # If argument provided, check if it's a full command or just the code
    if [[ "$1" == *"--code="* ]]; then
        # It's a full command, extract the code
        CHROME_REMOTE_DESKTOP_CODE=$(extract_chrome_code "$1")
        echo "Code extracted from command: ${CHROME_REMOTE_DESKTOP_CODE}"
    else
        # It's just the code
        CHROME_REMOTE_DESKTOP_CODE="$1"
        echo "Using provided code: ${CHROME_REMOTE_DESKTOP_CODE}"
    fi
    shift
else
    # Prompt user for the Chrome Remote Desktop command
    echo "Please paste the complete Chrome Remote Desktop command:"
    echo "Example: DISPLAY= /opt/google/chrome-remote-desktop/start-host --code=\"A/AAX4XfWjLm9kR2pQvN8uY5tE3rS6wZ1oI7bV4cD0fG8hJ2kL9mN6pQ3rS5tU8vW1xY4zA7bC\" --redirect-url=\"https://remotedesktop.google.com/_/oauthredirect\" --name=\$(hostname)"
    echo ""
    read -p "Enter command: " FULL_CHROME_COMMAND
    
    if [ -n "$FULL_CHROME_COMMAND" ]; then
        CHROME_REMOTE_DESKTOP_CODE=$(extract_chrome_code "$FULL_CHROME_COMMAND")
        if [ -n "$CHROME_REMOTE_DESKTOP_CODE" ]; then
            echo "Code successfully extracted: ${CHROME_REMOTE_DESKTOP_CODE}"
        else
            echo "Error: Could not extract code from the provided command."
            echo "Please make sure the command contains --code=\"...\" format."
            exit 1
        fi
    else
        echo "No command provided. Chrome Remote Desktop will be skipped."
        CHROME_REMOTE_DESKTOP_CODE=""
    fi
fi

# Prompt user for SecLists installation
echo ""
read -p "Do you want to install SecLists? This may take a considerable amount of time. [y/N]: " INSTALL_SECLISTS_PROMPT
if [[ "$INSTALL_SECLISTS_PROMPT" =~ ^[Yy]$ ]]; then
    INSTALL_SECLISTS=true
    echo "SecLists will be installed."
else
    INSTALL_SECLISTS=false
    echo "SecLists installation will be skipped."
fi

# Start timer now
start_time=$(date +%s)


# Get the user name and remote desktop default pin
CHROME_REMOTE_USER_NAME="${SUDO_USER}"

APT_INSTALL_CMD="apt"


# Update the packages lists and install apt-fast
echo "Installing apt-fast..."
sudo add-apt-repository ppa:apt-fast/stable -y
sudo ${APT_INSTALL_CMD} update -yqq
echo debconf apt-fast/maxdownloads string 16 | sudo debconf-set-selections
echo debconf apt-fast/dlflag boolean true | sudo debconf-set-selections
echo debconf apt-fast/aptmanager string apt-get | sudo debconf-set-selections
sudo ${APT_INSTALL_CMD} install apt-fast -yqq

# Check again if apt-fast is installed after attempting installation
if command -v apt-fast &> /dev/null; then
  APT_INSTALL_CMD="apt-fast"
  echo "apt-fast installed successfully. Using apt-fast for package installations."
 else
  echo "apt-fast installation failed. Using apt for package installations."
fi

# Download all files upfront in parallel - Chrome Remote Desktop, Google Chrome Stable, VS Code, Burp Suite Community Edition.
echo "Downloading installation files in parallel..."
wget -q "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb" -O google-chrome-stable_current_amd64.deb &
wget -q "https://dl.google.com/linux/direct/chrome-remote-desktop_current_amd64.deb" -O chrome-remote-desktop_current_amd64.deb &
wget -q "https://portswigger.net/burp/releases/startdownload?product=community&type=Linux" -O burpsuite &
wait
echo "Downloads completed."

# Install Google Chrome Stable
echo "Installing Google Chrome Stable..."
sudo ${APT_INSTALL_CMD} install -yqq "./google-chrome-stable_current_amd64.deb"
rm "./google-chrome-stable_current_amd64.deb"

# Configure Chrome Enterprise Policies for FoxyProxy
echo "Configuring Chrome Enterprise Policies..."
CHROME_POLICY_DIR="/etc/opt/chrome/policies/managed"
sudo mkdir -p ${CHROME_POLICY_DIR}
sudo tee ${CHROME_POLICY_DIR}/managed_policies.json > /dev/null <<EOF
{
  "ExtensionInstallForcelist": [
    "gcknhkkoolaabfmlnjonogaaifnjlfnp;https://clients2.google.com/service/update2/crx"
  ]
}
EOF

# Install Chrome Remote Desktop
echo "Installing Chrome Remote Desktop..."
sudo ${APT_INSTALL_CMD} install -yqq "./chrome-remote-desktop_current_amd64.deb"
rm "./chrome-remote-desktop_current_amd64.deb"

# Start Chrome Remote Desktop host if code is provided
DISPLAY_INSTALL_STATUS=0
if [ -n "${CHROME_REMOTE_USER_NAME}" -a -n "${CHROME_REMOTE_DESKTOP_CODE}" ]; then
  echo "Starting Chrome Remote Desktop..."
  DISPLAY= /opt/google/chrome-remote-desktop/start-host --code="${CHROME_REMOTE_DESKTOP_CODE}" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=$(hostname) --user-name="${CHROME_REMOTE_USER_NAME}" --pin="${PRE_CONFIGURED_PIN}"
  DISPLAY_INSTALL_STATUS=$?
  wait
  echo "Finish Starting Chrome Remote Desktop"
 else
  echo "Chrome Remote Desktop start skipped because code was not provided."
fi

# Install packages Gui
echo "Installing minimal desktop environment and applications..."
sudo ${APT_INSTALL_CMD} install -yqq xfce4 --no-install-recommends network-manager file-roller dbus-x11 fonts-wqy-microhei fonts-wqy-zenhei fonts-noto-cjk git
wait
echo "GUI installation completed."

# Install Burp Suite Community Edition
echo "Installing Burp Suite Community Edition ..."
sudo chmod +x burpsuite
sudo ./burpsuite -q
rm burpsuite

# Install Java, OpenJFX (for ZAP Browser View) and libnss3-tools (needed for ZAP Proxy)
echo "Installing default-jre, openjfx and libnss3-tools..."
sudo ${APT_INSTALL_CMD} install -yqq default-jre openjfx libnss3-tools

# Download ZAP Proxy
echo "Downloading ZAP Proxy..."
ZAP_URL=$(curl -s https://api.github.com/repos/zaproxy/zaproxy/releases/latest | grep browser_download_url | grep Linux | cut -d '"' -f 4)
wget -q "$ZAP_URL" -O zap.tar.gz

echo "Extracting ZAP Proxy..."
sudo tar -xzf zap.tar.gz -C /opt/
sudo mv /opt/ZAP* /opt/zaproxy
rm zap.tar.gz

# Configure ZAP to use JavaFX JVM arguments
USER_HOME="/home/${CHROME_REMOTE_USER_NAME}"
sudo -u ${CHROME_REMOTE_USER_NAME} mkdir -p "${USER_HOME}/.ZAP"
echo "--module-path /usr/share/openjfx/lib --add-modules javafx.web,javafx.swing,javafx.controls" | sudo -u ${CHROME_REMOTE_USER_NAME} tee "${USER_HOME}/.ZAP/.ZAP_JVM.properties" > /dev/null

# Create ZAP Desktop shortcut
echo "Creating ZAP desktop shortcut..."
cat << 'DESKTOP' | sudo tee /usr/share/applications/zaproxy.desktop > /dev/null
[Desktop Entry]
Name=ZAP Proxy
Comment=Zed Attack Proxy
Exec=/opt/zaproxy/zap.sh
Icon=/opt/zaproxy/zap.ico
Terminal=false
Type=Application
Categories=Development;Security;
DESKTOP

# Install ZAP Addons: Browser View (HTML render) and Wappalyzer
echo "Installing ZAP Addons (Browser View, Wappalyzer)..."
sudo -u ${CHROME_REMOTE_USER_NAME} /opt/zaproxy/zap.sh -cmd -addoninstall browserView -addoninstall wappalyzer > /dev/null 2>&1


# Install Node.js (v20)
echo "Installing Node.js 20.x..."
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo ${APT_INSTALL_CMD} install -yqq nodejs

# Install uv (Python package manager)
echo "Installing uv..."
sudo -u ${CHROME_REMOTE_USER_NAME} curl -LsSf https://astral.sh/uv/install.sh | sudo -u ${CHROME_REMOTE_USER_NAME} sh

# Install crx-analyzer using uv
echo "Installing crx-analyzer..."
sudo -u ${CHROME_REMOTE_USER_NAME} /home/${CHROME_REMOTE_USER_NAME}/.local/bin/uv tool install crx-analyzer

# Ensure .local/bin is in PATH for the user by updating .bashrc
echo 'export PATH="$HOME/.local/bin:$PATH"' | sudo -u ${CHROME_REMOTE_USER_NAME} tee -a /home/${CHROME_REMOTE_USER_NAME}/.bashrc > /dev/null

echo "Installing Antigravity CLI..."
curl -fsSL https://antigravity.google/cli/install.sh | bash -s -- -d /usr/local/bin

# Configure Antigravity CLI global context
echo "Configuring Antigravity global context..."
USER_HOME="/home/${CHROME_REMOTE_USER_NAME}"
ANTIGRAVITY_CONFIG_DIR="${USER_HOME}/.gemini/config"
sudo -u ${CHROME_REMOTE_USER_NAME} mkdir -p "${ANTIGRAVITY_CONFIG_DIR}"
sudo -u ${CHROME_REMOTE_USER_NAME} tee "${ANTIGRAVITY_CONFIG_DIR}/AGENTS.md" > /dev/null << 'EOF'
---

**Role & Identity**

You are an elite Threat Hunting and Threat Intelligence AI Assistant. Your goal is to collaborate with security professionals to analyze emerging threats and design actionable detection strategies. You maintain a rigorous, balanced perspective — distinguishing between legitimate "Dual-Use" functionality and malicious exploitation — and you never produce deployable attack tooling.

---

**Core Directives**

**1. Proactive Threat Discovery**
Search the web for the latest cybersecurity articles and threat intelligence to identify novel attack methods, campaigns, and adversary behaviors. Prioritize primary sources: vendor advisories, CVE disclosures, threat actor reports, and peer-reviewed security research.

**2. Contextual Risk Assessment**
For every TTP or technique discussed, evaluate legitimate use cases before analyzing abuse potential. Never treat a capability as inherently malicious without first establishing whether it deviates from functional norms.

**3. Manifest V3 Weaponization Analysis**
Analyze how an adversary could leverage MV3 constraints and APIs — Service Workers, Offscreen Documents, declarativeNetRequest, content scripts, etc. — to achieve malicious objectives. Explanations are conceptual and analytical; no working exploit code, obfuscated scripts, or deployable payloads will be produced under any circumstances.

**4. Critical Alerting**
Explicitly flag techniques that have a high probability of abuse, lack a common legitimate justification, or represent a meaningful detection gap. Reserve critical alerts for behaviors that cross clearly into MITRE ATT&CK territory.

**5. Framework Adherence**
Map all findings to the MITRE ATT&CK framework (Enterprise and/or Mobile as applicable), citing Tactic, Technique, and Sub-technique IDs.

---

**Response Structure**

**① Threat / Technique Overview**
A precise technical summary of the concept, its mechanism, and why it is relevant to the current threat landscape.

**② Legitimate Use vs. Abuse Potential**
- **Legitimate:** Concrete developer or operational use cases (e.g., "Standard telemetry for UI/UX analytics").
- **Abuse:** How an adversary could exploit the same capability, and what distinguishes malicious use from benign use.

**③ Risk Level**
Rate the technique using the following criteria:

| Rating | Criteria |
|---|---|
| **Low** | Requires significant attacker access; high detection surface; rare abuse in the wild |
| **Medium** | Plausible abuse path; some detection coverage exists; seen in opportunistic campaigns |
| **High** | Easily weaponized; limited detection surface; seen in targeted or widespread campaigns |
| **Critical** | Weaponizable with no user interaction; no reliable detection artifact; actively exploited |

**④ Manifest V3 Weaponization — The Attacker's View**
A conceptual walkthrough of how an adversary would execute this technique within MV3 boundaries. Focus on the logic, data flow, and abuse of legitimate APIs — not implementation code.

**⑤ MITRE ATT&CK Mapping**
List all associated Tactics, Techniques, and Sub-techniques with IDs. Note any gaps where existing ATT&CK coverage is incomplete.

**⑥ Hunting Hypothesis & Detection Artifacts**

- **Hypothesis:** A falsifiable statement of adversarial behavior (e.g., "An extension exfiltrating clipboard data will generate anomalous outbound POST requests from a browser process immediately following a paste event").
- **Telemetry Sources:** Logs, EDR events, network captures, or browser artifacts needed to test the hypothesis.
- **Detection Confidence:** Rate artifact reliability — *High* (hard to spoof), *Medium* (spoofable but costly), or *Low* (easily evaded).
- **False Positive Considerations:** Legitimate behaviors that could trigger the same signal.

---

**Tone & Style**

Be highly technical, objective, and analytical. Function as a Red Team / Blue Team sounding board. If a technique reflects standard extension development practice, say so plainly. Only escalate when behavior deviates from the expected functional norm or maps to clear adversarial intent. Avoid speculation without evidentiary basis; qualify uncertainty explicitly.

**Hard Limits:** Do not produce working exploit code, functional malware, obfuscated scripts, or deployable payloads regardless of framing — including hypothetical, educational, or fictional contexts.

---

EOF

# Create Chrome debug wrapper script
echo "Creating Chrome debug wrapper script..."
sudo -u ${CHROME_REMOTE_USER_NAME} tee "${USER_HOME}/launch-chrome-debug.sh" > /dev/null <<EOF
#!/bin/bash
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-debug
EOF
sudo chmod +x "${USER_HOME}/launch-chrome-debug.sh"

# Install VsCode
echo "Installing VsCode..."
sudo snap install --classic code
wait
echo "VsCode installation completed."
echo "Installing VSCode extensions:"
sudo -u ${CHROME_REMOTE_USER_NAME} code --install-extension esbenp.prettier-vscode
sudo -u ${CHROME_REMOTE_USER_NAME} code --install-extension ipatalas.vscode-postfix-ts
sudo -u ${CHROME_REMOTE_USER_NAME} code --install-extension aaravb.chrome-extension-developer-tools
sudo -u ${CHROME_REMOTE_USER_NAME} code --install-extension solomonkinard.chrome-extension-api
echo "done."

# Clone SecLists repository
if [ "$INSTALL_SECLISTS" = true ]; then
    echo "Cloning SecLists repository to /usr/share/SecLists..."
    sudo git clone https://github.com/danielmiessler/SecLists.git /usr/share/SecLists
else
    echo "Skipping SecLists installation based on user preference."
fi

# End timer
end_time=$(date +%s)
duration=$((end_time - start_time))

# Calculate hours, minutes, and seconds (using 'duration' now)
duration_hours=$((duration / 3600))
duration_minutes=$(((duration % 3600) / 60))
duration_secs=$((duration % 60))

# Format the duration output
if [ $duration_hours -gt 0 ]; then
  duration_output="${duration_hours} hours, ${duration_minutes} minutes, ${duration_secs} seconds"
elif [ $duration_minutes -gt 0 ]; then
  duration_output="${duration_minutes} minutes, ${duration_secs} seconds"
else
  duration_output="${duration_secs} seconds"
fi

echo "All commands executed. Please check for any errors above."
echo "Installation process completed in ${duration_output}."
