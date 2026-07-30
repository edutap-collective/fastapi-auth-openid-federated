# How-to: Federation Keys erzeugen, rotieren und veröffentlichen

Diese Anleitung zeigt Ihnen, wie Sie das Schlüsselmaterial in `OidcSettings.fed_jwks` erzeugen, persistent verwalten und rotieren, und wie Sie überprüfen, was Ihre RP davon veröffentlicht.

## Einen neuen Schlüssel erzeugen

`fed_jwks` erwartet ein JWKS-Dict mit **privatem** Schlüsselmaterial.
Erzeugen Sie einen RSA- oder EC-Schlüssel mit `joserfc`:

```python
from joserfc.jwk import KeySet, RSAKey

signing_key = RSAKey.generate_key(key_size=2048, parameters={"kid": "rp-fed-2026-01"}, private=True)
fed_jwks = KeySet([signing_key]).as_dict(private=True)
```

Wenn Sie stattdessen einen EC-Schlüssel bevorzugen, verwenden Sie `ECKey.generate_key(crv="P-256", parameters={"kid": "rp-fed-2026-01"}, private=True)` — die RP erkennt den Schlüsseltyp automatisch und signiert die Entity Configuration mit dem passenden Algorithmus (`RS256` für RSA, `ES256`/`ES384`/`ES512` je nach Kurve für EC).

## Den Schlüssel dauerhaft speichern

Ein bei jedem Prozessstart neu erzeugter Schlüssel ändert bei jedem Neustart die `entity_id`-Bindung nach außen: Wer Ihre RP zuvor über ihre alte Entity Configuration validiert hat, sieht danach einen anderen Schlüssel.
Erzeugen Sie den Schlüssel deshalb einmalig und serialisieren Sie ihn zu JSON:

```python
import json

print(json.dumps(fed_jwks))
```

Speichern Sie die Ausgabe als Wert der Umgebungsvariable `OIDC_FED_JWKS`, zum Beispiel in Ihrem Secret-Store oder einer `.env`-Datei außerhalb der Versionskontrolle:

```shell
export OIDC_FED_JWKS="$(cat fed-jwks.json)"
```

`OidcSettings` liest diese Variable dank `pydantic-settings` automatisch ein (Präfix `OIDC_`, siehe {doc}`/reference/settings`).
Behandeln Sie den Inhalt wie jedes andere Secret: nicht ins Repository committen.

## Schlüssel rotieren

`OidcRP` verwendet aus `fed_jwks` ausschließlich den **ersten** Eintrag mit privatem Schlüsselmaterial und veröffentlicht auch nur dessen öffentliches Gegenstück in der eigenen Entity Configuration.
Eine Rotation ist deshalb kein gleitender Übergang mit zwei parallel gültigen Schlüsseln, sondern ein atomarer Austausch:

1. Erzeugen Sie einen neuen Schlüssel wie oben beschrieben, mit einer neuen `kid`.
2. Ersetzen Sie den Wert von `fed_jwks` (bzw. `OIDC_FED_JWKS`) vollständig durch den neuen Schlüssel.
3. Deployen Sie die RP neu.

```{important}
Stimmen Sie den Zeitpunkt der Rotation mit dem Betreiber Ihres Trust Anchors bzw. unmittelbaren Superiors ab (siehe {doc}`/howto/trust-anchors`).
Sobald die neue Entity Configuration veröffentlicht ist, muss auch die dortige Subordinate Statement über Ihre RP das neue öffentliche JWKS führen, sonst schlägt die Trust-Chain-Validierung fehl.
```

## Die veröffentlichte Entity Configuration prüfen

Nach jedem Schlüsselwechsel lohnt ein Blick auf das tatsächlich veröffentlichte Dokument:

```shell
curl -s https://rp.example/openid/.well-known/openid-federation
```

Die Antwort ist ein kompaktes JWT (`application/entity-statement+jwt`).
Um den `kid` im Header ohne Signaturprüfung nachzuvollziehen, dekodieren Sie das erste Segment; für eine vollständige, signaturgeprüfte Ansicht fügen Sie das Token in einen JWT-Inspektor ein, dem Sie das öffentliche Gegenstück Ihres Schlüssels übergeben.

```{note}
Die Gültigkeitsdauer der veröffentlichten Entity Configuration ist derzeit fest auf 3600 Sekunden gesetzt und nicht über `OidcSettings` konfigurierbar.
```
