# Running KalmPass

What keeps the service safe to operate, and what to do when something goes
wrong.

## The server key

`SERVER_KEY` is a Cloudflare Worker secret. Every row in the database is sealed
with keys derived from it, and so is every backup. Cloudflare will not show it
again once set, so the copies you keep are the only way back if it is ever
deleted.

Keep at least two offline copies, in different places:

```
npm run key:sheet     # writes private/server-key-sheet.html to print
```

Print it, store the copies somewhere safe, and delete the file. Then check that
each copy is right by typing it back:

```
npm run key:check -- <the key from the paper>
```

The fingerprint it prints must match the **Server key** tile on the admin
dashboard and the `keyFingerprint` in every backup manifest.

The key cannot be rotated yet. The password pepper and the email index are
derived from it, so changing it would need every account to sign in again
under a migration that does not exist yet. Until it does, protect it instead.

If the Worker secret is lost, put a copy back with
`npx wrangler secret put SERVER_KEY` and confirm the fingerprint.

## Backups

Two layers:

1. **D1 point-in-time recovery**, built in, for the last 30 days. Best for
   undoing a recent mistake:
   ```
   npx wrangler d1 time-travel info kalmpass
   npx wrangler d1 time-travel restore kalmpass --timestamp=<unix time or RFC3339>
   ```
2. **Nightly exports to R2** (`kalmpass-backups`, kept 35 days), made by the
   cron at 04:17 UTC. They survive the database being deleted outright. Run one
   by hand from the admin dashboard with **Back up now**.

To restore an export into a fresh database:

```
npm run backup:restore -- 2026-09-17
npx wrangler d1 create kalmpass-restore
npx wrangler d1 execute kalmpass-restore --remote --file=schema.sql
npx wrangler d1 execute kalmpass-restore --remote --file=private/restore-2026-09-17.sql
```

Point `wrangler.jsonc` at the new database id, deploy, and check the health
endpoint. A restore was rehearsed on 17 September 2026 and brought back every
row the manifest listed.

## Monitoring

- **Uptime:** `.github/workflows/uptime.yml` checks the site and
  `/api/health` every 15 minutes, and fails if the last backup is more than
  50 hours old. GitHub emails failed scheduled runs to the account that last
  changed that file.
- **Health endpoint:** `https://kalmpass.net/api/health` reports the database,
  the server key and the email binding, and the age of the last backup.
- **Logs:** Workers observability is on. Look in the Cloudflare dashboard under
  Workers, kalmpass, Observability.
- **Admin dashboard:** `/admin/` shows the last backup, the key fingerprint,
  Stripe mode and price, and failed payments.

## Deploying

`npx wrangler deploy` from the repository. The GitHub Deploy workflow does the
same once the repository has `CLOUDFLARE_API_TOKEN` and
`CLOUDFLARE_ACCOUNT_ID` secrets; until then it skips that step.

After a deploy, `npm run smoke` and `npm run ext:test` check the live service
end to end with throwaway accounts.
