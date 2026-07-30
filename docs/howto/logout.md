# How-to: Logout einrichten (lokal und am OP)

Diese Anleitung zeigt Ihnen, wie Sie den lokalen Logout einrichten und optional zusätzlich ein Single Logout am OpenID Provider anstoßen.

## Lokalen Logout auslösen

`/openid/logout` beendet die lokale Session immer, unabhängig davon, ob ein OP-Logout konfiguriert ist:

```text
GET /openid/logout?next=/bye
```

Ohne `next`-Parameter leitet die RP stattdessen auf `OidcSettings.post_logout_default` weiter (Standard `/`):

```python
settings = openid.OidcSettings(
    entity_id="https://rp.example",
    base_url="https://rp.example",
    fed_jwks=fed_jwks,
    session_secret=session_secret,
    post_logout_default="/goodbye",
)
```

Das genügt für einen rein lokalen Logout: Die Session wird gelöscht, das Cookie entfernt, die Person landet auf dem konfigurierten Ziel.

## Single Logout am OP zusätzlich anstoßen

Um beim OP ebenfalls abzumelden, aktivieren Sie `enable_op_logout` und registrieren mindestens eine `post_logout_redirect_uri`:

```python
settings = openid.OidcSettings(
    entity_id="https://rp.example",
    base_url="https://rp.example",
    fed_jwks=fed_jwks,
    session_secret=session_secret,
    trust_anchors=trust_anchors,
    enable_op_logout=True,
    post_logout_redirect_uris=["https://rp.example/openid/post-logout"],
)
```

Mit dieser Konfiguration löst die RP beim Logout zusätzlich eine frische Trust-Chain-Auflösung für den OP der aktuellen Identität auf, um dessen `end_session_endpoint` zu ermitteln, und leitet dorthin weiter — mit `client_id` und dem ersten Eintrag aus `post_logout_redirect_uris` als Query-Parametern.
`post_logout_redirect_uris` fließt außerdem automatisch in die eigene, veröffentlichte Entity Configuration ein.

```{important}
Der OP-Logout ist ausdrücklich **best effort**.
Jeder Fehler dabei — nicht erreichbarer OP, gebrochene Trust Chain, fehlender `end_session_endpoint` — fällt auf einen rein lokalen Logout zurück, statt einen Fehler zu werfen.
Der lokale Schutz Ihrer eigenen Anwendung darf nie von der Erreichbarkeit eines externen OP abhängen; Details dazu in {doc}`/explanation/security-model`.
```

Ohne registrierte `post_logout_redirect_uris` oder ohne `iss` in der geladenen Identität bleibt der Logout in jedem Fall lokal, auch bei aktiviertem `enable_op_logout`.
