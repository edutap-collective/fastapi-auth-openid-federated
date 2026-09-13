# syntax=docker/dockerfile:1
FROM python:3.13-slim AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
# uv for fast, reproducible installs
COPY --from=ghcr.io/astral-sh/uv:0.12 /uv /usr/local/bin/uv
COPY pyproject.toml README.md ./
COPY src ./src
# No system dependency: JOSE (joserfc), not XML — no xmlsec1 needed.
RUN uv pip install --system --no-cache ".[redis,postgres]"
RUN rm -f /usr/local/bin/uv

FROM python:3.13-slim AS runtime
ENV PYTHONUNBUFFERED=1
COPY --from=build /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=build /usr/local/bin /usr/local/bin
WORKDIR /app
# Smoke check baked in: the package imports cleanly.
RUN python -c "from fastapi_auth import openid; print('import ok', openid.__version__)"
CMD ["python", "-c", "from fastapi_auth import openid; print('fastapi-auth-openid-federated', openid.__version__)"]
