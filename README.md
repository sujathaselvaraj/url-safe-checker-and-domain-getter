# url-safe-checker-and-domain-getter

A simple utility to check if a URL is safe using Google Safe Browsing API and retrieve WHOIS domain information.

A Node.js utility to:

- ✅ Check multiple URLs against Google's Safe Browsing API
- 🌐 Fetch WHOIS info for any domain
- 🔧 Flexible options to control what kind of domain info is returned


## Installation

```bash
npm install url-safe-checker-and-domain-getter

## 🔐 Setup Google API Key

To use this npm, you'll need an API key:

1. Go to [Google Cloud Console](https://console.cloud.google.com/).
2. Create a project.
3. Enable **Safe Browsing API** from the library.
4. Create **API credentials** (API Key).
5. Use your key like:

```ts
checkUrlSafety(urlsToCheck, "YOUR_GOOGLE_API_KEY");

🚀 Usage
✅ Check URLs for safety
Pass an array of URLs to checkUrlSafety():

const { checkUrlSafety } = require('url-safe-checker-and-domain-getter');

(async () => {
  const urls = [
    'https://example.com',
    'http://malicious-site.com'
  ];

  const result = await checkUrlSafety(urls, 'YOUR_GOOGLE_API_KEY', {
    domainInfoRequired: true,   // Return WHOIS for all URLs
    unsafeURlDomainInfo: false, // Optional: Only unsafe URLs
    safeURlDomainInfo: false    // Optional: Only safe URLs
  });

  console.log(JSON.stringify(result, null, 2));
})();


🧠 Option Flags Explained

Option	            Type	  Description
domainInfoRequired	boolean	Return WHOIS info for all URLs (safe + unsafe)
unsafeURlDomainInfo	boolean	Return WHOIS info for unsafe URLs only
safeURlDomainInfo	boolean	Return WHOIS info for safe URLs only

If domainInfoRequired is true, it overrides the other two.

🌐 Get Domain Info Directly
To get WHOIS data only (without checking Safe Browsing):

const { getDomainInfo } = require('url-safe-checker-and-domain-getter');

(async () => {
  const urls = ['https://example.com', 'http://anotherdomain.com'];

  const whoisData = await Promise.all(urls.map(url =>
    getDomainInfo(url, 'CUSTOM_LABEL')
  ));

  console.log(whoisData);
})();

Important: The getDomainInfo function expects domain names (e.g., example.com) as input, not full URLs.

📝 Sample Output

{
  "unsafe": [
    {
      "url": "http://malicious-site.com",
      "threatType": "MALWARE"
    }
  ],
  "safe": [
    "https://example.com"
  ],
  "domainInfo": {
    "unsafe": [
      {
        "label": "UNSAFE",
        "domain": "malicious-site.com",
        "data": "WHOIS data..."
      }
    ],
    "safe": [
      {
        "label": "SAFE",
        "domain": "example.com",
        "data": "WHOIS data..."
      }
    ]
  }
}
