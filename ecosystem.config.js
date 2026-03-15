module.exports = {
  apps: [{
    name: 'security-monitor',
    script: 'src/server.js',
    cwd: __dirname,
    env: {
      NODE_ENV: 'production',
      MONITOR_PORT: '4000',
      LOG_FILE: '/var/log/nginx/access.log',
      MONITOR_USER: process.env.MONITOR_USER || 'admin',
      MONITOR_PASS: process.env.MONITOR_PASS,
    },
    max_memory_restart: '300M',
    autorestart: true,
    watch: false,
  }],
};
