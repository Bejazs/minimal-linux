# Single Script for Linux VM Setup

```bash
git clone https://github.com/Bejazs/minimal-linux.git && cd minimal-linux && chmod +x setup_vm.sh && sudo ./setup_vm.sh
```

## Linux VM Setup Script

This script automates the installation and configuration of a Linux virtual machine with remote desktop and essential tools.

## What the script installs

- **Google Chrome** - Web browser
- **Chrome Remote Desktop** - Remote access to the VM
- **XFCE4** - Lightweight desktop environment
- **Burp Suite Community Edition** - Web security testing tool
- **ZAP Proxy (Zed Attack Proxy)** - Web security testing tool
- **Visual Studio Code** - Code editor
- **apt-fast** - Accelerated package manager
- **Gemini CLI** - Command line tool for Gemini models
- **Chrome DevTools MCP Server** - Allows Gemini CLI to control Chrome via CDP

## Prerequisites

- Ubuntu/Debian Linux system
- sudo permissions
- Internet connection
- Chrome Remote Desktop authorization code (optional)

## How to use

### 1. Make the script executable

```bash
chmod +x setup_vm.sh
```

### 2. Run the script

There are three ways to run the script:

#### Option A: Interactive execution (recommended)
```bash
sudo ./setup_vm.sh
```

The script will ask you to paste the complete Chrome Remote Desktop command.

#### Option B: Passing the complete command as argument
```bash
sudo ./setup_vm.sh 'DISPLAY= /opt/google/chrome-remote-desktop/start-host --code="YOUR_CODE_HERE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=$(hostname)'
```

#### Option C: Passing only the authorization code
```bash
sudo ./setup_vm.sh "4/0AX4XfWjLm9kR2pQvN8uY5tE3rS6wZ1oI7bV4cD0fG8hJ2kL9mN6pQ3rS5tU8vW1xY4zA7bC"
```

## How to get the Chrome Remote Desktop code

1. Go to [https://remotedesktop.google.com/headless](https://remotedesktop.google.com/headless)
2. Sign in with your Google account
3. Click "Begin"
4. Select "Next"
5. Copy the complete command that appears (similar to the example below):

```bash
DISPLAY= /opt/google/chrome-remote-desktop/start-host --code="4/0AX4XfWjLm9kR2pQvN8uY5tE3rS6wZ1oI7bV4cD0fG8hJ2kL9mN6pQ3rS5tU8vW1xY4zA7bC" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=$(hostname)
```

## Execution example

```bash
# Make executable
chmod +x setup_vm.sh

# Run
sudo ./setup_vm.sh

# When prompted, paste the complete command:
Please paste the complete Chrome Remote Desktop command:
Example: DISPLAY= /opt/google/chrome-remote-desktop/start-host --code="A/AAX4XfWjLm9kR2pQvN8uY5tE3rS6wZ1oI7bV4cD0fG8hJ2kL9mN6pQ3rS5tU8vW1xY4zA7bC" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=$(hostname)

Enter command: [PASTE YOUR COMMAND HERE]
```

## Default settings

- **Remote Desktop PIN**: `123456`
- **Desktop environment**: XFCE4

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

## What happens during execution

1. ✅ Authorization code extraction
2. ✅ apt-fast installation for faster downloads
3. ✅ Parallel download of all installers
4. ✅ Google Chrome installation
5. ✅ Chrome Remote Desktop installation
6. ✅ Remote access configuration
7. ✅ XFCE4 desktop environment installation
8. ✅ Burp Suite installation
9. ✅ ZAP Proxy installation
10. ✅ Node.js, npm, Gemini CLI, MCP Server setup, and Global Context (`Gemini.md`) Configuration
11. ✅ VS Code installation
12. ✅ VS Code extensions: prettier, postfix, chrome-extension-api, chrome-extension-developer-tools

## After installation

1. **Access remotely**: Go to [https://remotedesktop.google.com](https://remotedesktop.google.com)
2. **Sign in**: Use the same Google account used to generate the code
3. **Connect**: Click on your VM name
4. **Enter PIN**: Use `123456` (or change in script if desired)

### Using Gemini CLI with Chrome DevTools Protocol (CDP)

The VM is pre-configured with `gemini-cli` and the `chrome-devtools-mcp` server. This allows Gemini to interact directly with your local Chrome browser via the Chrome DevTools Protocol, enabling real-time monitoring of network traffic, evaluating arbitrary JavaScript, and more.

To use this feature:
1. Open a terminal and run the provided wrapper script to launch Chrome with the remote debugging port enabled:
   ```bash
   ~/launch-chrome-debug.sh
   ```
2. In another terminal window, launch `gemini-cli` and instruct it to perform a browser task:
   ```bash
   gemini
   ```

## Troubleshooting

### Script fails to extract code
- Check if the command contains `--code="..."`
- Make sure quotes are included

### Chrome Remote Desktop doesn't start
- Check if you have sudo permissions
- Confirm the code hasn't expired (codes have limited validity)

### Slow downloads
- The script automatically installs apt-fast to speed up downloads
- Check your internet connection

## Project structure

```
script-linux/
├── setup_vm.sh    # Main script
└── README.md      # This file
```

## Important notes

- ⚠️ **Always run with sudo**: The script needs administrative privileges
- ⚠️ **Temporary code**: Chrome Remote Desktop codes expire quickly
- ⚠️ **Connectivity**: Make sure you have good connection for downloads
- ✅ **Security**: Change the default PIN if necessary

## Estimated execution time

- **With good connection**: 2-5 minutes
- **With slow connection**: 6-10 minutes

The script shows the total execution time at the end.
