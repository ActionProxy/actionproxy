# Local curl demo

Terminal 1 — run the gateway:

```bash
corepack pnpm dev:server
```

If `pnpm` is available on your PATH, `pnpm dev:server` works too.

Terminal 2 — run these scripts from the repo root:

```bash
bash examples/local-curl-demo/create-doc-search.sh
bash examples/local-curl-demo/create-email-approval.sh
bash examples/local-curl-demo/list-pending.sh
bash examples/local-curl-demo/approve-first-pending.sh
bash examples/local-curl-demo/create-denied-action.sh
curl -s http://127.0.0.1:8787/v1/audit | jq
```

The scripts default to `ACTIONPROXY_BASE_URL=http://127.0.0.1:8787`.

Optional Terminal 3 — start the local dashboard:

```bash
corepack pnpm dev:web
```

Then open `http://127.0.0.1:5173`.

The demo proves:

- read-only mock tools execute immediately in demo mode,
- sensitive tools require approval,
- denied tools are blocked,
- audit events are recorded.
