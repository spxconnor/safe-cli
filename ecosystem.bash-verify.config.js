// PM2 ecosystem file for bash_verify.
//
// `bash_verify` itself is a CLI tool, not a long-running daemon, so PM2
// isn't strictly needed. But the doctor + repair service can run as a
// timer-driven job in PM2 if you prefer PM2 over systemd.
//
// Run:
//   pm2 start /opt/bash-verifier/ecosystem.bash-verify.config.js
//   pm2 save
//   pm2 startup    # generate the systemd unit
//
module.exports = {
  apps: [
    {
      name: 'bash-verify-doctor',
      script: '/opt/bash-verifier/bin/bash_verify',
      args: '--doctor',
      cron_restart: '*/15 * * * *',
      autorestart: false,
      // PM2's exec_mode 'fork' is correct for one-shot CLI runs.
      exec_mode: 'fork',
      max_memory_restart: '512M',
      env: {
        PYTHONPATH: '/opt/bash-verifier',
      },
    },
  ],
};
