# Total-Sense

Total-Sense is a lightweight browser extension that checks the active tab against VirusTotal using the user's own API key. It does not use a hosted backend and is not affiliated with or endorsed by VirusTotal.

## Features

- Checks the current page URL against VirusTotal from the popup
- Requests a fresh analysis when VirusTotal has no current URL object or stale results
- Shows a verdict summary, detection counts, flagged engines, and analysis metadata
- Stores the API key locally in the extension's own storage area
- Ships as a simple unpacked extension with no build step required for development

## Privacy And Security

- Your API key is stored in local extension storage on your machine
- Requests go directly from the extension to `https://www.virustotal.com/api/v3`
- No application backend, analytics service, or external database is used
- Requesting a fresh analysis submits the current page URL to VirusTotal

## Browser Support

The current setup is aimed at Chromium-based browsers with Manifest V3 support, including Chrome, Edge, Brave, and Opera.

Firefox support is not currently verified.

## Install Locally

1. Clone or download this repository.
2. Open your browser's extensions page.
3. Enable Developer Mode.
4. Click `Load unpacked`.
5. Select this project folder.

## Setup

1. Open the extension options page from the popup.
2. Paste your VirusTotal API key.
3. Save the key.
4. Open the popup on any `http` or `https` page to view the current verdict.

## Package A Zip

You can create a distributable zip from PowerShell:

```powershell
.\package-extension.ps1
```

Or through npm:

```powershell
npm run build
```

The packaged file is written to `dist/total-sense-extension.zip`.

## Project Layout

- `popup.*`: popup UI for the active-tab check flow
- `options.*`: options page for API key storage and guidance
- `lib/`: extension and VirusTotal API helpers
- `assets/fonts/`: bundled Source Sans Pro assets
- `assets/icons/`: extension icons

## Notes

- Public VirusTotal API keys are rate limited.
- Unsupported tabs such as `chrome://` pages, extension pages, and other non-HTTP URLs are ignored.
- The extension uses `textContent` for remote data rendering, so VirusTotal response strings are not injected as HTML.

## Roadmap

- Add richer report drill-down links and history handling
- Expand support for additional observable types
- Add automated checks for packaging and regression coverage

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
