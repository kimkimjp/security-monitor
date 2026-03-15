'use strict';

const rules = require('./rules');
const geo   = require('./geo-lookup');

class DetectionEngine {
  constructor() {
    this.rules = rules;
    this._seq = 0;
  }

  /**
   * Run all rules against a parsed log entry.
   * @param {object} entry  - Parsed log entry from log-parser
   * @param {Map}    ipStats - IP statistics map from the store
   * @returns {Array} Array of alert objects
   */
  analyze(entry, ipStats) {
    const alerts = [];

    for (const rule of this.rules) {
      try {
        if (rule.test(entry, ipStats)) {
          this._seq += 1;
          const geoInfo = geo.lookup(entry.ip);

          alerts.push({
            id: `${Date.now()}-${this._seq}`,
            timestamp: entry.timestamp || new Date(),
            ruleId: rule.id,
            ruleName: rule.name,
            severity: rule.severity,
            category: rule.category,
            ip: entry.ip,
            detail: `${entry.method} ${entry.path} → ${entry.status} | UA: ${entry.userAgent || '(empty)'}`,
            country: geoInfo.country,
          });
        }
      } catch (err) {
        // Never let a single rule crash the engine
        if (process.env.NODE_ENV !== 'production') {
          console.error(`Rule ${rule.id} error:`, err.message);
        }
      }
    }

    return alerts;
  }
}

module.exports = DetectionEngine;
