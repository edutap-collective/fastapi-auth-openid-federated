# How-to: Mit der Docker-Umgebung arbeiten

Diese Anleitung zeigt Ihnen, wie Sie das mitgelieferte `Dockerfile` und `compose.yml` für Build, lokalen Betrieb und Integrationstests nutzen.

## Image bauen

Das `Dockerfile` im Repository-Root baut ein mehrstufiges, schlankes Image auf `python:3.13-slim`:

```shell
docker build -t fastapi-auth-openid-federated .
```

```{note}
Das Paket validiert Trust Chains und Tokens ausschließlich über `joserfc` (reines JOSE/JWT), nicht über XML-Signaturen.
Im Gegensatz zum `saml`-Schwesterpaket braucht das Image deshalb **keine** Systemabhängigkeit wie `xmlsec1` — nur die Python-Pakete selbst.
```

Das Image installiert das Paket samt `redis`- und `postgres`-Extra über `uv`, entfernt `uv` anschließend wieder aus dem finalen Layer und prüft beim Build per Smoke-Check, dass sich das Paket importieren lässt:

```shell
docker run --rm fastapi-auth-openid-federated
```

Die Ausgabe bestätigt Paketname und Version.
Dieses Image ist als **Basis** für Ihre eigene Anwendung gedacht: Ergänzen Sie Ihren `app.py`-Code und einen eigenen `CMD`/`ENTRYPOINT`, der einen ASGI-Server wie `uvicorn` startet, in einem eigenen Dockerfile, das von diesem Image erbt oder dessen Build-Stufen wiederverwendet.

## Integrationstests gegen echte Abhängigkeiten fahren

`compose.yml` stellt Redis und Postgres bereit, gegen die die Store-Implementierungen in `tests/session/test_stores_integration.py` real getestet werden (kein Mock):

```shell
docker compose up -d --wait
```

Danach laufen die als `integration` markierten Tests gegen die laufenden Dienste:

```shell
IT_REDIS_URL=redis://localhost:6379/0 \
IT_DB_URL=postgresql+asyncpg://postgres:pw@localhost:5432/fa \
uv run pytest -m integration -v
```

## Alles über make erledigen

`make test-integration` fasst genau diese Schritte zusammen — Dienste starten, Tests ausführen, Dienste wieder abbauen, auch bei fehlgeschlagenen Tests:

```shell
make test-integration
```

## Aufräumen

Bauen Sie die Compose-Dienste manuell auf, räumen Sie danach auch manuell auf.
`-v` entfernt zusätzlich die von Postgres/Redis angelegten Volumes:

```shell
docker compose down -v
```

```{seealso}
Welche Store-Implementierung `OidcSettings.store` auswählt und welches Extra sie jeweils benötigt: {doc}`/howto/stores`.
```
