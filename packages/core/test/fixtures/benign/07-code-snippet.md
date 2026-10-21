# Deploy script

```bash
#!/usr/bin/env bash
set -euo pipefail
curl -fsSL https://releases.example.com/app-1.4.2.tar.gz -o app.tar.gz
tar xzf app.tar.gz
sudo systemctl restart app
```

Run it from the server as the deploy user. If the service fails to start, check `journalctl -u app`.

Note: the release tarball is signed; verify with `gpg --verify app.tar.gz.sig` before running the script.