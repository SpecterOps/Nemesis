# Chrome Collector

Chrome Collector is a browser extension that interfaces with the Nemesis server. This README provides detailed steps on building, adding, and configuring the extension.

## Table of Contents

- [Building the Extension](#building-the-extension)
- [Installing to Chrome](#installing-to-chrome)
- [Configuration](#configuration)
    * [Basic Configuration](#basic-configuration)
    * [Allowlist](#allowlist)

## Building the Extension

To build the extension, follow these steps:

```bash
cd $NEMESIS_ROOT/cmd/chrome-extension
npm install
npm run build
```

## Installing to Chrome

1. Open your Chrome browser.
2. Navigate to `chrome://extensions` in the omnibar.
3. Enable Developer Mode by toggling the switch in the top right corner.
4. Click the "Load Unpacked" button.
5. Navigate to `$NEMESIS_ROOT/cmd/chrome-extension/dist` in the file explorer and select it.

**Note:** If the Nemesis options page appears, it means the extension was loaded successfully.

## Configuration

### Basic Configuration

1. Start the Nemesis base server.
2. In the extension's options page, provide the following details:
    * Nemesis base URL
    * Web API username
    * Web API password

The agent ID helps identify the data source in Nemesis. It is set in the metadata field for every file uploaded by the Chrome application.

**Tip:** The options page typically opens automatically upon installation. If you need to revisit the options page later, click on the extension's icon in the Chrome toolbar and select "Options."

### Allowlist

1. Navigate to the extension's options page.
2. Enable the "Use Domain Allowlist" switch.
3. Add domains and/or IPs to the allowlist.
  
**Note:** IPs should be specified with a CIDR range. For a single IP, use the /32 CIDR range. E.g., `127.0.0.1/32`.