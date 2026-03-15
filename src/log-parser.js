'use strict';

const LOG_REGEX = /^(\S+) \S+ (\S+) \[([^\]]+)\] "([^"]*)" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"/;

const MONTH_MAP = {
  Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
  Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
};

/**
 * Parse Nginx combined-format timestamp string into a Date object.
 * Format: "15/Mar/2026:10:30:00 +0900"
 */
function parseTimestamp(raw) {
  const m = raw.match(/(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})/);
  if (!m) return null;

  const [, day, mon, year, hh, mm, ss, tz] = m;
  const month = MONTH_MAP[mon];
  if (month === undefined) return null;

  const tzSign = tz[0] === '+' ? -1 : 1;
  const tzHours = parseInt(tz.slice(1, 3), 10);
  const tzMins  = parseInt(tz.slice(3, 5), 10);
  const tzOffsetMs = tzSign * (tzHours * 60 + tzMins) * 60000;

  const utc = Date.UTC(
    parseInt(year, 10),
    month,
    parseInt(day, 10),
    parseInt(hh, 10),
    parseInt(mm, 10),
    parseInt(ss, 10),
  );

  return new Date(utc + tzOffsetMs);
}

/**
 * Parse a single Nginx combined-format log line.
 * Returns a structured object or null if the line does not match.
 */
function parseLine(line) {
  if (!line || typeof line !== 'string') return null;

  const match = line.match(LOG_REGEX);
  if (!match) return null;

  const [, ip, user, rawTimestamp, rawRequest, statusStr, bytesStr, referer, userAgent] = match;

  const timestamp = parseTimestamp(rawTimestamp);
  if (!timestamp) return null;

  const status = parseInt(statusStr, 10);
  const bytes  = bytesStr === '-' ? 0 : parseInt(bytesStr, 10);

  // Secondary parse of the request line: "METHOD /path HTTP/x.y"
  let method = '';
  let path = '';
  let httpVersion = '';

  const reqParts = rawRequest.match(/^(\S+)\s+(\S+)(?:\s+(\S+))?$/);
  if (reqParts) {
    method      = reqParts[1];
    path        = reqParts[2];
    httpVersion = reqParts[3] || '';
  } else {
    // Non-standard request (binary data, protocol probes, etc.)
    method = rawRequest;
  }

  return {
    ip,
    user: user === '-' ? null : user,
    timestamp,
    method,
    path,
    httpVersion,
    status,
    bytes,
    referer: referer === '-' ? null : referer,
    userAgent,
    rawRequest,
  };
}

module.exports = { parseLine, parseTimestamp };
