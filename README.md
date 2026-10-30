# NIGHTSCAN — Vercel deployment package

NIGHTSCAN is packaged as one Flask application and one HTML dashboard. When deployed to Vercel, Vercel runs the Python backend automatically. Visitors only open the public URL, choose their preferred LLM provider/model, paste their own LLM API key, and run discovery. They do **not** install Python or run a server.

This build performs AI-assisted discovery of public API products, official documentation, public base endpoints, categories and integration information from public search-index results. It does not extract, test, validate, or publish third-party credentials. Search-index results are not a crawl of every internet page.

## Project files

- `index.html` — NIGHTSCAN Home, Scanner and API Library UI.
- `server.py` — Flask backend; Vercel detects the top-level `app` object and runs it as a Python Function.
- `requirements.txt` — Python dependencies.
- `vercel.json` — Vercel framework, Python function duration, bundled HTML and response security headers.
- `.python-version` — Python runtime selection.
- `.env.example` — environment-variable template.

## Deploy it (one-time owner setup)

### 1. Create the persistent database

The community API Library and user accounts must be shared by every visitor. Vercel Functions do not provide a persistent local filesystem, so this project requires a hosted PostgreSQL database (for example, a Neon or Supabase PostgreSQL project).

Create a database and copy its PostgreSQL connection string. Use the provider's pooled connection string if offered and ensure it includes SSL (commonly `?sslmode=require`).

The application automatically creates its tables and seeds a few starter API directory entries on first startup.

### 2. Put the project on GitHub

1. Extract this ZIP.
2. Create a new, private or public GitHub repository.
3. Upload the **contents** of the `NIGHTSCAN-Vercel` folder to the repository root. `server.py`, `index.html`, `requirements.txt` and `vercel.json` must be at the root, not nested one folder deeper.
4. Do not upload a real `.env` file or any private keys.

### 3. Import the repository into Vercel

1. Open <https://vercel.com/new> and import the GitHub repository.
2. Keep the project root at the repository root.
3. Vercel should detect Flask from `requirements.txt` and deploy the root-level `server.py` as a Python Function. No separate always-on server or manual Python process is required.
4. Add the environment variables below in **Project → Settings → Environment Variables**.

### 4. Required Vercel environment variables

| Variable | Value |
|---|---|
| `NIGHTSCAN_SECRET_KEY` | A long random secret used to sign secure sessions. Generate one with `python -c "import secrets; print(secrets.token_urlsafe(48))"`. |
| `DATABASE_URL` | Your hosted PostgreSQL connection string. Required for persistent global library data, accounts and rate limits. |

Set them for Production and Preview as needed, then redeploy. Never put a visitor's LLM API key in Vercel environment variables; visitors enter their own key in the Scanner. Their key is sent over HTTPS to the backend for the request and is not stored in the database or application logs.

### 5. Optional search and Google sign-in configuration

| Variable | Purpose |
|---|---|
| `TAVILY_API_KEY` | Optional search provider key. If omitted, NIGHTSCAN uses its DuckDuckGo HTML search fallback. Adding Tavily can make public search more reliable. |
| `GOOGLE_CLIENT_ID` | Enables Google sign-in/up. |
| `GOOGLE_CLIENT_SECRET` | Enables Google sign-in/up. |
| `GOOGLE_REDIRECT_URI` | Set to `https://YOUR-PROJECT.vercel.app/auth/google/callback` and add that exact URL to the Google OAuth client's authorized redirect URIs. |

Google sign-in is disabled in the UI until the Google client credentials are configured. Email/password signup remains available.

### 6. Open the site

After deployment, open the Vercel URL, for example `https://nightscan.vercel.app`.

- Home, Scanner and API Library are served from the same deployment.
- The Scanner calls the Python backend automatically through same-origin `/api/...` routes.
- Visitors choose a provider and model, paste their own LLM API key, and click **Start Discovery**. The optional discovery-topic field can be left blank for a broad public API discovery sweep.
- Users sign in before contributing an API entry to the global library.

## Local development (optional)

Python 3.13 is recommended.

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
python server.py
```

Open <http://127.0.0.1:8000>. For local SQLite development, no `DATABASE_URL` is required. Local SQLite is only for local testing; it is not a substitute for PostgreSQL on Vercel.

## API routes

- `GET /api/health` — health and database status.
- `GET /api/bootstrap` — session, CSRF token, account and library counts.
- `GET /api/llm/providers` — supported LLM providers.
- `POST /api/llm/models` — retrieve models using the visitor's supplied provider key.
- `POST /api/discover` — query public web search results and use the selected LLM to extract public API metadata.
- `GET /api/library` — read the shared community API directory.
- `POST /api/library` — contribute a public API metadata entry (requires sign-in and CSRF token).
- `POST /api/auth/signup`, `POST /api/auth/login`, `POST /api/auth/logout` — email/password account endpoints.
- `/auth/google` — optional Google OAuth flow.

## Important deployment notes

- The global API Library only becomes global when all visitors use the same deployed application and its shared PostgreSQL database.
- Do not deploy without `DATABASE_URL` and `NIGHTSCAN_SECRET_KEY`; the application intentionally fails fast on Vercel instead of silently placing community data on ephemeral disk.
- The visitor's LLM key is received by the Python backend in a request body, passed to the selected provider, and not written to database rows. Use HTTPS only (Vercel provides HTTPS on its deployment domains).
- The included email/password flow hashes passwords with scrypt and uses signed, HTTP-only, secure-on-Vercel session cookies plus CSRF checks. It is a functional baseline, not a security audit: it does not yet include email verification, password-reset email, account lockout review, or abuse monitoring. Add those before treating accounts as high-assurance production authentication.
- The public API search queries an index provider and analyzes a limited set of returned results. It cannot guarantee discovery of every API or page on the internet.
- This package has been syntax-checked, but it has not been deployed to your Vercel account or connected to your database/provider credentials. You must complete the one-time owner setup above.
