const whois = require('whois');
const axios = require('axios');

// Convert WHOIS lookup to a Promise
function getDomainInfo(url, label = '') {
  const domain = new URL(url).hostname;
  return new Promise((resolve, reject) => {
    whois.lookup(domain, (err, data) => {
      if (err) {
        resolve({
          label,
          domain,
          error: err.message,
        });
      } else {
        resolve({
          label,
          domain,
          data,
        });
      }
    });
  });
}

// function that returns structured results
async function checkUrlSafety(urls, apiKey, options = {}) {
  const {
    domainInfoRequired = true,
    unsafeURlDomainInfo = false,
    safeURlDomainInfo = false,
  } = options;

  const result = {
    unsafe: [],
    safe: [],
    domainInfo: {
      unsafe: [],
      safe: [],
    },
  };

  try {
    const response = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        client: {
          clientId: 'safe-browsing-api',
          clientVersion: '1.0.0',
        },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: urls.map((url) => ({ url })),
        },
      }
    );

    const matches = response.data.matches || [];
    const unsafeSet = new Set(matches.map(m => m.threat.url));

    result.unsafe = matches.map(match => ({
      url: match.threat.url,
      threatType: match.threatType,
    }));

    result.safe = urls.filter(url => !unsafeSet.has(url));

    // WHOIS info for unsafe URLs
    if (domainInfoRequired || unsafeURlDomainInfo) {
      const unsafeDomainPromises = result.unsafe.map(item =>
        getDomainInfo(item.url, 'UNSAFE')
      );
      result.domainInfo.unsafe = await Promise.all(unsafeDomainPromises);
    }

    // WHOIS info for safe URLs
    if (domainInfoRequired || safeURlDomainInfo) {
      const safeDomainPromises = result.safe.map(url =>
        getDomainInfo(url, 'SAFE')
      );
      result.domainInfo.safe = await Promise.all(safeDomainPromises);
    }

    return result;
  } catch (error) {
    throw new Error(error.response?.data?.error?.message || error.message);
  }
}

module.exports = {
  checkUrlSafety,
  getDomainInfo,
};
