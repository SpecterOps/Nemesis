# Nemesis Chromium Analysis

Nemesis includes comprehensive support for analyzing Chromium-based browser data including Chrome, Edge, Brave, and other Chromium-based browsers. The system automatically detects and processes various Chromium database files to extract browsing history, saved credentials, cookies, downloads, and encryption state information.

## Overview

Nemesis currently analyzes the following Chromium data sources:

| Data Type    | File Source      | Purpose                                                                      |
| ------------ | ---------------- | ---------------------------------------------------------------------------- |
| History      | `History`        | Extracts browsing history including URLs, titles, visit counts, and timestamps |
| Downloads    | `History`        | Extracts download history with file paths, URLs, and download metadata     |
| Logins       | `Login Data`     | Extracts saved login credentials including usernames and encrypted passwords |
| Cookies      | `Cookies`        | Extracts browser cookies with domain, name, value, and expiration data     |
| State Keys   | `Local State`    | Extracts OS encryption keys used to decrypt passwords and sensitive data   |

## File Enrichment Modules

### Chromium History Parser

The `chromium_history` enrichment module automatically processes Chromium `History` database files. It uses YARA rules to detect valid Chromium History databases and extracts both browsing history and download records.

**Detection Criteria:**
- Files containing `CREATE TABLE downloads_url_chains` and `CREATE TABLE downloads_slices` strings
- SQLite database format with standard Chromium History schema

### Chromium Login Data Parser

The `chromium_logins` enrichment module processes Chromium `Login Data` database files to extract saved login credentials.

**Detection Criteria:**
- Files containing `CREATE TABLE logins` string
- SQLite database format with standard Chromium Login Data schema

### Chromium Cookies Parser

The `chromium_cookies` enrichment module processes Chromium `Cookies` database files to extract browser cookies.

**Detection Criteria:**
- Files containing `CREATE TABLE cookies` string
- SQLite database format with standard Chromium Cookies schema

### Chromium Local State Parser

The `chromium_localstate` enrichment module processes Chromium `Local State` JSON files to extract OS encryption keys and browser state information.

**Detection Criteria:**
- JSON files containing `os_crypt` configuration data
- Standard Chromium Local State file format

## The Nemesis Web Interface

### Chromium Data Viewer

The Nemesis frontend provides a dedicated Chromium interface accessible through the main navigation. This interface organizes all extracted Chromium data into five main categories:

### History Tab

The History tab displays extracted browsing history with searchable and filterable tables. Each entry includes:

- **URL**: The visited website URL
- **Title**: Page title as recorded by the browser
- **Visit Count**: Number of times the URL was visited
- **Last Visit**: Timestamp of most recent visit
- **Username/Browser**: Extracted from file path context

![Chromium History Tab](images/chromium-history-tab.png)

Users can:
- Search across all history fields
- Filter by date ranges
- Sort by any column
- Export results to CSV format
- Copy individual entries or entire result sets

### Downloads Tab

The Downloads tab shows extracted download history with detailed information about each downloaded file:

- **Download URL**: Original source URL of the downloaded file
- **File Path**: Local file system path where file was saved
- **File Size**: Size of downloaded file
- **Download Date**: When the download completed
- **Username/Browser**: Context from file path

![Chromium Downloads Tab](images/chromium-downloads-tab.png)

### Logins Tab

The Logins tab displays extracted login credentials with sensitive information appropriately handled:

- **Origin URL**: Website where credentials were saved
- **Username**: Login username or email address
- **Password Status**: Indicates if password is encrypted or decrypted
- **Date Created**: When credentials were first saved
- **Username/Browser**: Context from file path

![Chromium Logins Tab](images/chromium-logins-tab.png)

**Security Note**: Passwords are stored encrypted and require additional decryption steps using extracted state keys.

### Cookies Tab

The Cookies tab provides access to extracted browser cookies with comprehensive details:

- **Host Key**: Domain or host the cookie belongs to
- **Cookie Name**: Name identifier of the cookie
- **Cookie Value**: Encrypted or plaintext cookie value
- **Expiration**: Cookie expiration date
- **Security Flags**: HttpOnly, Secure, SameSite attributes

![Chromium Cookies Tab](images/chromium-cookies-tab.png)

### State Keys Tab

The State Keys tab displays OS encryption keys used by Chromium to protect sensitive data:

- **Master Key GUID**: Windows DPAPI master key identifier
- **Encrypted Key**: Base64-encoded encrypted key material
- **Key Purpose**: Intended use (typically password encryption)
- **Username/Browser**: Context from file path

![Chromium State Keys Tab](images/chromium-state-keys-tab.png)

**Security Note**: These keys are essential for decrypting saved passwords and other encrypted browser data.

## Data Export and Analysis

### CSV Export Functionality

All Chromium data tables support CSV export for external analysis:

1. Use the table interface to filter and search desired records
2. Click the "Download CSV" button in the top-right of each tab
3. All currently visible/filtered records will be exported

### Copy Operations

Individual records or entire result sets can be copied to clipboard:

- **Single Row**: Double-click any table row to copy all fields
- **Multiple Rows**: Select rows and use Ctrl+C (or Cmd+C on Mac)
- **Filtered Results**: Copy button will copy all currently visible records

## Database Schema

Chromium data is stored in dedicated PostgreSQL tables under the `chromium` schema:

### chromium.history
- Stores browsing history records with URLs, titles, and visit metadata
- Links to originating file via `originating_object_id`
- Includes extracted username and browser context

### chromium.downloads
- Contains download history with file paths and source URLs
- Tracks download completion status and file metadata
- Preserves original download timestamps

### chromium.logins
- Stores login credential records with encrypted passwords
- Includes origin URLs and username values
- Requires state keys for password decryption

### chromium.cookies
- Contains browser cookies with domain and security attributes
- Stores both session and persistent cookies
- Includes expiration and security flag information

### chromium.state_keys
- Stores OS encryption keys for browser data protection
- Contains DPAPI master key GUIDs and encrypted key material
- Essential for decrypting saved passwords and sensitive data

## Security Considerations

### Password Decryption

Chromium passwords are encrypted using OS-level protection mechanisms:

- **Windows**: Uses DPAPI (Data Protection API) with user context
- **macOS**: Uses Keychain Services for encryption key management
- **Linux**: Uses various backends including libsecret or plain storage

Decryption requires:
1. Access to the user's OS encryption context
2. Corresponding state keys from `Local State` files
3. Appropriate decryption libraries and tools

### Data Sensitivity

Chromium analysis reveals highly sensitive information:

- **Browsing History**: Can expose visited websites and user behavior patterns
- **Saved Credentials**: Contains usernames and encrypted passwords for websites
- **Cookies**: May include authentication tokens and session identifiers
- **Downloads**: Shows downloaded files and their original sources

Always handle extracted Chromium data with appropriate security controls and access restrictions.