# Moodle Example

Demonstrates the full LTI 1.3 Advantage feature set against a local Moodle instance:

| Feature | What the example does |
|---|---|
| **Dynamic Registration** | Moodle auto-configures the tool — no manual URL entry |
| **Resource Link Launch** | Displays user identity and course context after a validated OIDC launch |
| **NRPS** | Fetches the full course roster and displays it in a table |
| **AGS** | Submits a score of 75/100 to the Moodle gradebook on every launch |
| **Deep Linking** | Content picker lets instructors add a plain or graded resource to a course |

## Prerequisites

- Go 1.21+
- Docker with Compose

## Quick start

### 1. Start Moodle

```bash
cd examples/moodle
docker compose up -d
```

Moodle takes a few minutes to initialise. Wait until `http://localhost:8085` loads the login page.

Default credentials: **admin / bitnami123**

### 2. Start the tool

Two URLs are involved:

- **`TOOL_BASE_URL`** — what the **browser** uses to reach the tool (login, launch, redirect).
- **`TOOL_INTERNAL_URL`** — what **Moodle's server** uses to fetch the JWKS (server-to-server).

When Moodle runs in Docker, the browser accesses the tool via `localhost:8080`, but
Moodle's PHP process must use `host.docker.internal:8080` to reach the host machine.

```bash
TOOL_BASE_URL=http://localhost:8080 \
TOOL_INTERNAL_URL=http://host.docker.internal:8080 \
go run ./examples/moodle
```

The tool always listens on `:8080`; these variables only control the URLs
advertised to Moodle during dynamic registration.

### 3. Register the tool in Moodle

1. Log into Moodle as admin (`http://localhost:8085`)
2. Go to **Site administration → Plugins → Activity modules → External tool → Manage tools**
3. Paste the dynamic registration URL and click **Add**:
   ```
   http://host.docker.internal:8080/lti/registration
   ```
4. Moodle opens an iframe, the tool negotiates the registration, and the page
   closes automatically. The tool now appears with **Active** status.

> **Note:** The tool generates a new RSA key pair on every startup and stores
> everything in memory. After a restart you must re-register the tool in Moodle
> (delete the old entry first, then repeat step 3).

### 4. Add the tool to a course

To test a **Resource Link launch**:

1. Open any Moodle course → **Turn editing on**
2. Go to More → LTI External Tools → Turn on "Show in activity chooser"
3. Go the your course → **Add an activity or resource**
4. Select **Go LTI Demo** from the preconfigured tools list and save
5. Click the activity — the OIDC flow runs and you land on the launch dashboard

To test **Deep Linking** (adds the tool as a content item):

1. In a course → Turn editing on → Add a block or use a text editor
2. Click the link-selector button → choose **Go LTI Demo — Add Content**
3. Pick **Basic Resource** or **Graded Activity** and click **Add to Course**
4. The item appears in the course. Click it to trigger a resource-link launch.

For the **Graded Activity** option, a gradebook line item is created automatically.
Each subsequent launch submits a score of 75/100 — visible in the Moodle gradebook.

## Endpoints

| Path | Purpose |
|---|---|
| `GET/POST /oidc/login` | OIDC login initiation |
| `POST /lti/launch` | JWT validation + launch handler |
| `GET /.well-known/jwks.json` | Tool's public JWKS |
| `GET /lti/registration` | Dynamic Registration |
| `POST /lti/deeplink/submit` | Builds and returns the Deep Linking response JWT |

## Troubleshooting

### `fix_jwks_alg(): Argument #1 ($jwks) must be of type array, null given`

This error means Moodle's PHP cURL could not fetch the tool's JWKS URL. Moodle
ships with a list of blocked hosts that cURL is not allowed to contact. On a
local development setup the block list includes `localhost` and related entries,
which prevents Moodle from fetching `host.docker.internal`.

To unblock it:

1. Log into Moodle as admin
2. Go to **Site administration → Security → HTTP security**
   (`/admin/settings.php?section=httpsecurity`)
3. Find the **cURL blocked hosts list** and remove `localhost` and any other
   entries that match your tool's host (e.g. `host.docker.internal`)
4. Find the **cURL allowed ports list** and add `8080` (or whatever port your tool listens on)
5. Save changes and retry

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `TOOL_BASE_URL` | `http://localhost:8080` | Browser-facing base URL (login, launch, redirect URIs). |
| `TOOL_INTERNAL_URL` | *(same as `TOOL_BASE_URL`)* | Base URL used by the platform's server to fetch JWKS. Set to `http://host.docker.internal:8080` when Moodle runs in Docker. |
