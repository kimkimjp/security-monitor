'use strict';

let geoip;
try {
  geoip = require('geoip-lite');
} catch {
  geoip = null;
}

const PRIVATE_RANGES = [
  { prefix: '10.', mask: null },
  { prefix: '172.', mask: (ip) => { const b = parseInt(ip.split('.')[1], 10); return b >= 16 && b <= 31; } },
  { prefix: '192.168.', mask: null },
  { prefix: '127.', mask: null },
  { prefix: '169.254.', mask: null },
  { prefix: '::1', mask: null },
  { prefix: 'fc', mask: null },
  { prefix: 'fd', mask: null },
  { prefix: 'fe80', mask: null },
];

const LOCAL_RESULT = Object.freeze({
  country: 'Local',
  region: '',
  city: '',
  ll: [35.6762, 139.6503],
});

// Simple LRU-ish cache to avoid repeated lookups
const cache = new Map();
const CACHE_MAX = 10000;

function isPrivateIP(ip) {
  if (!ip) return true;
  for (const range of PRIVATE_RANGES) {
    if (ip.startsWith(range.prefix)) {
      return range.mask ? range.mask(ip) : true;
    }
  }
  return false;
}

function lookup(ip) {
  if (!ip || isPrivateIP(ip)) return LOCAL_RESULT;

  const cached = cache.get(ip);
  if (cached) return cached;

  if (!geoip) return LOCAL_RESULT;

  const geo = geoip.lookup(ip);
  const result = geo
    ? {
        country: geo.country || 'Unknown',
        region: geo.region || '',
        city: geo.city || '',
        ll: geo.ll || [0, 0],
      }
    : { country: 'Unknown', region: '', city: '', ll: [0, 0] };

  if (cache.size >= CACHE_MAX) {
    // Evict oldest quarter
    const keys = Array.from(cache.keys()).slice(0, CACHE_MAX / 4);
    for (const k of keys) cache.delete(k);
  }
  cache.set(ip, result);

  return result;
}

module.exports = { lookup, isPrivateIP };
