Recorded hook-buildbox.xrpl.org outputs (2026-10-06, UTC 09:14-09:20), for the `buildbox-2026-10` recipe.

- Sources: Hooks Builder IDE templates (Xahau/xrpl-hooks-ide state/constants/templates.ts @ b992bcc):
  `starter.c` gist 1f8109c80f504e6326db2735df2f0ad6 rev d7d7feeb; `firewall.c` and `blacklist.c`
  gist 1cc30f39c8a0b9c55b88c312669ca45e rev 6e32f234.
- `*.remote.wasm`: the service's response (`output`, base64 + zlib) for the IDE request shape
  `{"output":"wasm","compress":true,"strip":true,"files":[{"type":"c","options":"-O2","name":<f>,"src":<src>}]}`,
  decoded. Recorded once; never regenerated from this package.
