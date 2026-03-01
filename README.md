# cloudflare-simplelogin-api-worker

A Cloudflare Worker that replicates the [SimpleLogin](https://simplelogin.io) alias API, backed by a Cloudflare KV namespace instead of SimpleLogin's servers. It is designed to work with any client that already speaks the SimpleLogin API — including the **Bitwarden** password manager's built-in alias generator.

Aliases created here are stored in a shared KV namespace that the companion [cloudflare-email-forwarder-worker](https://github.com/dekle/cloudflare-email-forwarder-worker) reads from to decide whether to forward or reject incoming emails.

## Implemented endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/user_info` | Validate API key; return user info |
| `GET` | `/api/v5/alias/options` | Fetch suffix list (used by Bitwarden on open) |
| `POST` | `/api/v3/alias/custom/new` | Create a custom alias |
| `POST` | `/api/alias/random/new` | Create a random alias (word or UUID mode) |
| `GET` | `/api/v2/aliases` | List all aliases (paginated) |
| `GET` | `/api/aliases/:id` | Get a single alias |
| `DELETE` | `/api/aliases/:id` | Delete an alias |
| `POST` | `/api/aliases/:id/toggle` | Enable / disable an alias |
| `PATCH` | `/api/aliases/:id` | Update name, note, or pinned |
| `GET` | `/api/v2/mailboxes` | Return the single virtual mailbox |
| `GET` | `/api/v2/setting/domains` | Return the configured domain |
| `GET` | `/api/setting` | Return user settings |
| `POST` | `/api/sync` | Import all aliases from a real SimpleLogin account |

## Setup

### Prerequisites

- A Cloudflare account.
- A domain with **Cloudflare Email Routing** enabled (used by the forwarder worker).
- A **KV namespace** created in **Workers & Pages → KV** — note its ID.
- The companion [cloudflare-email-forwarder-worker](https://github.com/dekle/cloudflare-email-forwarder-worker) pointing at the **same KV namespace**.

### 1. Link the repo to a Cloudflare Worker

1. Go to **Workers & Pages → Create → Worker**.
2. After creation, go to **Settings → Build** and connect your GitHub repository.
3. Set the **build command**:
   ```
   envsubst < wrangler.toml.template > wrangler.toml
   ```

### 2. Set build environment variables

In **Settings → Build → Variables and secrets**:

| Variable | Value |
|---|---|
| `KV_NAMESPACE_ID` | The ID of your shared KV namespace |

### 3. Set runtime variables and secrets

In **Settings → Variables and Secrets**:

| Name | Type | Value |
|---|---|---|
| `DOMAIN` | Text | The domain used for alias addresses, e.g. `mail.example.com` |
| `USER_NAME` | Text | Display name returned by `/api/user_info` |
| `USER_EMAIL` | Text | Your real email address |
| `MAILBOX_ID` | Text | Any integer, e.g. `1` (defaults to `1` if omitted) |
| `API_KEY` | Secret | A strong random token — clients put this in the `Authentication` header |
| `SIGNING_SECRET` | Secret | A random string used to sign alias suffixes (generate below) |
| `SL_BASE_URL` | Text | *(Optional)* Self-hosted SimpleLogin URL for `/api/sync`; defaults to `https://app.simplelogin.io` |

#### Generating `API_KEY` and `SIGNING_SECRET`

Run either of these in PowerShell to generate a secure random value:

```powershell
# PowerShell
-join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) })
```

```powershell
# Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

```powershell
# OpenSSL (if installed)
openssl rand -hex 32
```

### 4. Configure SimpleLogin-compatible client

Follow the client documentation to setup SimpleLogin, but make the following changesL

1. Set the self-hosted server URL to your Cloudflare Worker's API URL: `https://cloudflare-simplelogin-api-worker.yourname.workers.dev`.
2. Use the API Key generated and stored in the Worker secrets (this should be different to your SimpleLogin API Key for security purposes).

### 5. Deploy

Push to `main` — the build runs automatically. Alternatively, trigger a manual deploy from the **Deployments** page.

## Syncing from a real SimpleLogin account

If you have existing aliases on SimpleLogin, import them all into KV with a single request:

```http
POST /api/sync
Authentication: <your API_KEY>
Content-Type: application/json

{
  "sl_api_key": "<your real SimpleLogin API key>",
  "sl_base_url": "https://app.simplelogin.io"
}
```

Response:
```json
{
  "added": 42,
  "updated": 0,
  "total_sl": 42,
  "total_kv_after": 42
}
```

Existing KV aliases are matched by email address and have their metadata refreshed. New aliases are assigned a local ID.

## KV schema

| Key | Value |
|---|---|
| `alias@domain.com` | JSON `AliasRecord` (see `src/index.ts`) |
| `__next_id__` | Next numeric alias ID (integer as string) |

The KV namespace is shared with the email-forwarder worker. The forwarder parses the JSON value and gates on the `enabled` field, so disabling an alias here immediately stops forwarding.

## Environment reference

| Name | Type | Required | Description |
|---|---|---|---|
| `KV_NAMESPACE_ID` | Build env var | Yes | ID of the shared `EMAIL_FORWARD_KV` KV namespace |
| `API_KEY` | Secret | Yes | Token clients send in the `Authentication` header |
| `SIGNING_SECRET` | Secret | Yes | Used to HMAC-sign alias suffixes |
| `DOMAIN` | Text | Yes | Domain for alias addresses |
| `USER_NAME` | Text | Yes | Display name for `/api/user_info` |
| `USER_EMAIL` | Text | Yes | Real email for `/api/user_info` and mailbox |
| `MAILBOX_ID` | Text | No | Virtual mailbox ID, defaults to `1` |
| `SL_BASE_URL` | Text | No | SimpleLogin base URL for sync, defaults to `https://app.simplelogin.io` |
