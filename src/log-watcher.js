'use strict';

const fs           = require('fs');
const path         = require('path');
const { EventEmitter } = require('events');

const TAIL_LINES = 500;

class LogWatcher extends EventEmitter {
  constructor() {
    super();
    this._watcher   = null;
    this._filePath   = null;
    this._offset     = 0;
    this._lineBuffer = '';
    this._closed     = false;
  }

  /**
   * Start watching a log file for new lines.
   * Emits 'line' events for each complete line.
   */
  watch(filePath) {
    this._filePath = path.resolve(filePath);
    this._closed = false;

    // Read tail lines on startup
    this._readTail(() => {
      this._startWatching();
    });
  }

  /**
   * Read the last TAIL_LINES lines from the file to seed initial data.
   */
  _readTail(callback) {
    fs.stat(this._filePath, (err, stats) => {
      if (err) {
        console.warn(`[LogWatcher] Cannot stat ${this._filePath}:`, err.message);
        this._offset = 0;
        callback();
        return;
      }

      // Read entire file and take last N lines
      // For very large files, a reverse read would be more efficient,
      // but for typical log files this is adequate.
      const fileSize = stats.size;

      // Read at most last 2MB for tail
      const readStart = Math.max(0, fileSize - 2 * 1024 * 1024);
      const stream = fs.createReadStream(this._filePath, {
        start: readStart,
        encoding: 'utf8',
      });

      let data = '';
      stream.on('data', (chunk) => { data += chunk; });
      stream.on('error', (readErr) => {
        console.warn('[LogWatcher] Tail read error:', readErr.message);
        this._offset = fileSize;
        callback();
      });
      stream.on('end', () => {
        const lines = data.split('\n').filter((l) => l.length > 0);
        const tailLines = lines.slice(-TAIL_LINES);
        for (const line of tailLines) {
          this.emit('line', line);
        }

        // Set offset to end of file so we only read new data
        this._offset = fileSize;
        callback();
      });
    });
  }

  /**
   * Start fs.watch and read incremental data on changes.
   */
  _startWatching() {
    if (this._closed) return;

    try {
      this._watcher = fs.watch(this._filePath, (eventType) => {
        if (this._closed) return;

        if (eventType === 'rename') {
          // Log rotation detected: close current watcher and reopen
          this._handleRotation();
          return;
        }

        // 'change' event: read new data
        this._readIncremental();
      });

      this._watcher.on('error', (err) => {
        console.error('[LogWatcher] Watch error:', err.message);
        this.emit('error', err);
      });

      console.log(`[LogWatcher] Watching ${this._filePath}`);
    } catch (err) {
      console.error('[LogWatcher] Failed to start watching:', err.message);
      this.emit('error', err);
    }
  }

  /**
   * Read any new bytes appended since _offset.
   */
  _readIncremental() {
    fs.stat(this._filePath, (err, stats) => {
      if (err) {
        // File might be gone during rotation
        return;
      }

      if (stats.size < this._offset) {
        // File was truncated (rotation); reset
        this._offset = 0;
      }

      if (stats.size === this._offset) return; // nothing new

      const stream = fs.createReadStream(this._filePath, {
        start: this._offset,
        encoding: 'utf8',
      });

      let data = '';
      stream.on('data', (chunk) => { data += chunk; });
      stream.on('error', (readErr) => {
        console.warn('[LogWatcher] Incremental read error:', readErr.message);
      });
      stream.on('end', () => {
        this._offset = stats.size;
        this._processData(data);
      });
    });
  }

  /**
   * Buffer incoming data and emit complete lines.
   */
  _processData(data) {
    this._lineBuffer += data;
    const lines = this._lineBuffer.split('\n');

    // Last element is either empty (complete line) or incomplete
    this._lineBuffer = lines.pop() || '';

    for (const line of lines) {
      if (line.length > 0) {
        this.emit('line', line);
      }
    }
  }

  /**
   * Handle log rotation: wait briefly for new file, then reattach.
   */
  _handleRotation() {
    console.log('[LogWatcher] Rotation detected, reopening...');

    if (this._watcher) {
      this._watcher.close();
      this._watcher = null;
    }

    this._offset = 0;
    this._lineBuffer = '';

    // Wait a moment for the new file to appear
    const retryInterval = setInterval(() => {
      if (this._closed) {
        clearInterval(retryInterval);
        return;
      }

      fs.access(this._filePath, fs.constants.R_OK, (err) => {
        if (!err) {
          clearInterval(retryInterval);
          this._startWatching();
        }
      });
    }, 1000);

    // Give up after 30 seconds
    setTimeout(() => clearInterval(retryInterval), 30000);
  }

  /**
   * Stop watching.
   */
  close() {
    this._closed = true;
    if (this._watcher) {
      this._watcher.close();
      this._watcher = null;
    }
    this.removeAllListeners();
  }
}

module.exports = LogWatcher;
