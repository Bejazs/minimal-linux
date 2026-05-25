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
- **Default proxy**: `127.0.0.1:8080` (configured for Burp Suite)
- **Desktop environment**: XFCE4

### To set the proxy in chrome execute the command
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

## What happens during execution

1. ✅ Authorization code extraction
2. ✅ apt-fast installation for faster downloads
3. ✅ Parallel download of all installers
4. ✅ Google Chrome installation
5. ✅ Chrome Remote Desktop installation
6. ✅ Remote access configuration
7. ✅ XFCE4 desktop environment installation
8. ✅ Burp Suite installation
9. ✅ ZAP Proxy installation and Chrome CA Certificate Trust
10. ✅ VS Code installation
11. ✅ VS Code extensions: prettier, postfix, chrome-extension-api, chrome-extension-developer-tools

## After installation

1. **Access remotely**: Go to [https://remotedesktop.google.com](https://remotedesktop.google.com)
2. **Sign in**: Use the same Google account used to generate the code
3. **Connect**: Click on your VM name
4. **Enter PIN**: Use `123456` (or change in script if desired)

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
