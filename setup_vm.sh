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

# Start timer now
start_time=$(date +%s)


# Get the user name and remote desktop default pin
CHROME_REMOTE_USER_NAME="${SUDO_USER}"

APT_INSTALL_CMD="apt"

# Default IP Address and Port
IP_ADDRESS='127.0.0.1'
PORT=8080


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

# Configure Chrome Enterprise Policies for FoxyProxy and Proxy settings
echo "Configuring Chrome Enterprise Policies..."
CHROME_POLICY_DIR="/etc/opt/chrome/policies/managed"
sudo mkdir -p ${CHROME_POLICY_DIR}
sudo tee ${CHROME_POLICY_DIR}/managed_policies.json > /dev/null <<EOF
{
  "ExtensionInstallForcelist": [
    "gcknhkkoolaabfmlnjonogaaifnjlfnp;https://clients2.google.com/service/update2/crx"
  ],
  "ProxyMode": "fixed_servers",
  "ProxyServer": "127.0.0.1:8080"
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

# Run ZAP Headless briefly to generate config and certificates
echo "Initializing ZAP to generate certificates..."
sudo -u ${CHROME_REMOTE_USER_NAME} /opt/zaproxy/zap.sh -daemon -host 127.0.0.1 -port 8080 -config api.disablekey=true > /dev/null 2>&1 &
ZAP_PID=$!

# Wait for ZAP to start and generate config
echo "Waiting for ZAP to generate config..."
sleep 15
kill $ZAP_PID 2>/dev/null || true
wait $ZAP_PID 2>/dev/null || true

# Extract ZAP CA Certificate and install into Chrome NSS database
echo "Installing ZAP CA Certificate to Chrome..."
USER_HOME="/home/${CHROME_REMOTE_USER_NAME}"
ZAP_CONFIG="${USER_HOME}/.ZAP/config.xml"

if [ -f "$ZAP_CONFIG" ]; then
    # Extract Base64 certificate from config.xml
    sudo -u ${CHROME_REMOTE_USER_NAME} awk -F'[<>]' '/<certificate>/{print $3}' "$ZAP_CONFIG" > "${USER_HOME}/zap_ca_base64.txt"

    # Format as valid PEM
    sudo -u ${CHROME_REMOTE_USER_NAME} bash -c 'echo "-----BEGIN CERTIFICATE-----" > "'${USER_HOME}'/zap_ca.crt"'
    sudo -u ${CHROME_REMOTE_USER_NAME} bash -c 'fold -w 64 "'${USER_HOME}'/zap_ca_base64.txt" >> "'${USER_HOME}'/zap_ca.crt"'
    sudo -u ${CHROME_REMOTE_USER_NAME} bash -c 'echo "-----END CERTIFICATE-----" >> "'${USER_HOME}'/zap_ca.crt"'

    # Create NSS DB if it doesn't exist
    sudo -u ${CHROME_REMOTE_USER_NAME} mkdir -p "${USER_HOME}/.pki/nssdb"
    if [ ! -f "${USER_HOME}/.pki/nssdb/cert9.db" ]; then
        sudo -u ${CHROME_REMOTE_USER_NAME} certutil -d sql:${USER_HOME}/.pki/nssdb -N --empty-password
    fi

    # Import the certificate
    sudo -u ${CHROME_REMOTE_USER_NAME} certutil -d sql:${USER_HOME}/.pki/nssdb -A -t "C,," -n "ZAP Root CA" -i "${USER_HOME}/zap_ca.crt"

    # Cleanup temp files
    rm "${USER_HOME}/zap_ca_base64.txt" "${USER_HOME}/zap_ca.crt"
    echo "ZAP CA Certificate installed successfully."
else
    echo "Warning: ZAP config.xml not found. Could not install CA Certificate."
fi

# Install Node.js, npm, and Gemini CLI
echo "Installing Node.js and npm..."
sudo ${APT_INSTALL_CMD} install -yqq nodejs npm

echo "Installing Gemini CLI..."
sudo npm install -g @google/gemini-cli

# Configure MCP server for Gemini CLI
echo "Configuring MCP server for Gemini CLI..."
sudo -u ${CHROME_REMOTE_USER_NAME} gemini mcp add -s user chrome-devtools npx chrome-devtools-mcp@latest

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
echo "Cloning SecLists repository to /usr/share/SecLists..."
sudo git clone https://github.com/danielmiessler/SecLists.git /usr/share/SecLists

## Reload desktop environment for the current user
#if [ $DISPLAY_INSTALL_STATUS -eq 0 ]; then
#  echo "Reload desktop environment for the current user ${CHROME_REMOTE_USER_NAME}..."
#  sudo systemctl restart chrome-remote-desktop@${CHROME_REMOTE_USER_NAME}.service

#  echo "Setting manual proxy settings (${IP_ADDRESS}:${PORT}) for Chrome Remote Desktop session..."
  #
#  # Create proxy configuration for XFCE4
#  USER_HOME="/home/${CHROME_REMOTE_USER_NAME}"
  #
#  # Set environment variables for proxy (system-wide)
#  echo "export http_proxy=http://${IP_ADDRESS}:${PORT}" | sudo tee -a ${USER_HOME}/.bashrc
#  echo "export https_proxy=http://${IP_ADDRESS}:${PORT}" | sudo tee -a ${USER_HOME}/.bashrc
#  echo "export HTTP_PROXY=http://${IP_ADDRESS}:${PORT}" | sudo tee -a ${USER_HOME}/.bashrc
#  echo "export HTTPS_PROXY=http://${IP_ADDRESS}:${PORT}" | sudo tee -a ${USER_HOME}/.bashrc
  #
#  # Create proxy configuration for applications
#  sudo -u ${CHROME_REMOTE_USER_NAME} mkdir -p ${USER_HOME}/.config/environment.d
#  echo "http_proxy=http://${IP_ADDRESS}:${PORT}" | sudo -u ${CHROME_REMOTE_USER_NAME} tee ${USER_HOME}/.config/environment.d/proxy.conf
#  echo "https_proxy=http://${IP_ADDRESS}:${PORT}" | sudo -u ${CHROME_REMOTE_USER_NAME} tee -a ${USER_HOME}/.config/environment.d/proxy.conf
#  echo "HTTP_PROXY=http://${IP_ADDRESS}:${PORT}" | sudo -u ${CHROME_REMOTE_USER_NAME} tee -a ${USER_HOME}/.config/environment.d/proxy.conf
#  echo "HTTPS_PROXY=http://${IP_ADDRESS}:${PORT}" | sudo -u ${CHROME_REMOTE_USER_NAME} tee -a ${USER_HOME}/.config/environment.d/proxy.conf
  #
#  # Configure Chrome browser proxy settings
#  CHROME_POLICY_DIR="/etc/opt/chrome/policies/managed"
#  sudo mkdir -p ${CHROME_POLICY_DIR}
#  sudo tee ${CHROME_POLICY_DIR}/proxy.json > /dev/null <<EOF
#{
#  "ProxyMode": "fixed_servers",
#  "ProxyServer": "localhost:127.0.0.1",
#  "ProxyBypassList": "localhost,127.0.0.1"
#}
#EOF
  #
#  # Set proper ownership
#  sudo chown -R ${CHROME_REMOTE_USER_NAME}:${CHROME_REMOTE_USER_NAME} ${USER_HOME}/.config
#  sudo chown ${CHROME_REMOTE_USER_NAME}:${CHROME_REMOTE_USER_NAME} ${USER_HOME}/.bashrc
  #
#  echo "Manual proxy settings applied for XFCE4 environment."
#else
#   echo "GUI installation failed. Skipping desktop environment reload."
#fi

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
