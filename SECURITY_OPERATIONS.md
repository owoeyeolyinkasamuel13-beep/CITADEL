# Security operations notes

## Login throttling

Set `APP_ENV=development` explicitly for local development. It uses a SQLite
sliding-window store at
`.login_rate_limit.sqlite3` (or the path in `LOGIN_RATE_LIMIT_DB_PATH`). It is
shared by multiple workers on the same host, stores only SHA-256 digests of
personnel IDs and source addresses, and expires attempt rows after ten
minutes. The limit is five attempts per personnel ID and sixty attempts per
source address in that window. A successful non-MFA login clears that
personnel ID's bucket. Throttling is temporary and does not change account
status or lock accounts.

This is a development implementation, not a distributed production limiter.
It is not suitable across multiple hosts or on a network filesystem. Until a
shared limiter (for example, a managed Redis service or an API gateway with
shared counters) is configured and integrated, set `APP_ENV=production`:
login then fails closed with HTTP 503 instead of silently using a per-host
limiter. Do not trust arbitrary forwarded-address headers; configure proxy
trust only for the deployment's known reverse proxies.

## MFA

Accounts with `mfa_enabled=True` cannot receive an access token from the
password-only login endpoint. Login returns HTTP 403 until a real second-factor
verification flow is implemented. No MFA mechanism is inferred or simulated.

## MySQL driver and character set

PyMySQL is pinned to 1.2.3, which includes the upstream 1.2.1 SQL injection
fix, and the SQLAlchemy connection explicitly requests `utf8mb4`. No CITADEL
MySQL schema or record changes are used for login throttling.

## JWT dependencies

`python-jose==3.5.0` remains pinned because the upstream release page lists
3.5.0 as the latest release, while published advisories have no patched
version. Current application use rejects empty or undersized signing keys and
passes an explicit HS256 allowlist, mitigating the specific conditions
described by those advisories. This is not a claim that the dependency
advisories are resolved; track upstream fixes or replace the library after a
compatibility review.
