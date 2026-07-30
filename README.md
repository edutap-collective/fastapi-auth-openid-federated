# fastapi-auth-openid-federated

Federated OpenID Connect Relying Party for FastAPI — trust via OpenID Federation 1.0.
Part of the `fastapi_auth` package family.

```python
from fastapi_auth import openid
```

## Install (development)

```bash
uv venv && source .venv/bin/activate
make install          # uv pip install -U -e ".[dev]"
make test-local
```

## Quickstart

Initialize settings from environment (`OIDC_*` prefix) and mount the relying party on your FastAPI app:

```python
from fastapi import FastAPI, Depends
from fastapi_auth.openid import OidcSettings, OidcRP

# Settings auto-loaded from environment (OIDC_ENTITY_ID, OIDC_BASE_URL, OIDC_FED_JWKS, etc.)
settings = OidcSettings()

# Create the relying party
rp = OidcRP(settings)

# Attach to FastAPI
app = FastAPI()
rp.mount(app)

# Protect a route with `Depends(rp.current_user())`
@app.get("/protected")
async def protected_route(identity = Depends(rp.current_user())):
    return {"sub": identity.sub, "email": identity.email}

# Optional: get authenticated user or None
@app.get("/maybe-protected")
async def maybe_protected(identity = Depends(rp.optional_user())):
    if identity is None:
        return {"message": "Anonymous"}
    return {"sub": identity.sub}
```

See `docs/` for tutorials, how-to guides, and detailed API reference.

## Docker

No system dependencies (JOSE via `joserfc`, not XML → no `xmlsec1`):

```bash
docker build -t fastapi-auth-openid-federated .
docker run --rm \
  -e OIDC_ENTITY_ID="..." \
  -e OIDC_BASE_URL="https://example.com" \
  -e OIDC_FED_JWKS='{"keys":[...]}' \
  -p 8000:8000 \
  fastapi-auth-openid-federated
```

For integration tests with Redis / PostgreSQL:

```bash
make test-integration  # via docker-compose + pytest
```

See `docs/` for setup, building, and debugging.

## Documentation

Full Diataxis-structured docs (Tutorial, How-to, Reference, Explanation) in `docs/`:

```bash
uv pip install -U -e ".[docs]"
uv run sphinx-build -W -b html docs docs/_build
```

Then open `docs/_build/index.html` in your browser.

## CI

GitHub Actions pipeline:

- **Lint & Type**: `ruff check` + `ty` across Python 3.12, 3.13, 3.14
- **Tests**: unit tests + integration tests (redis/postgres compose)
- **Docker**: multi-stage image build (no xmlsec1 system dependency)
- **Docs**: Sphinx build with `-W` (error on warnings)

See `.github/workflows/` for the full CI configuration.

## License

Dual-licensed: **Apache-2.0 OR EUPL-1.2** — the recipient may choose either.
See `LICENSE-APACHE` and `LICENSE-EUPL`.
