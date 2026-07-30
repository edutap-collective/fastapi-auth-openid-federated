# Tutorial: Föderations-Login mit einer minimalen FastAPI-App

In diesem Tutorial bauen wir Schritt für Schritt eine minimale FastAPI-App, die als OpenID-Connect-Relying-Party (RP) in einer **OpenID Federation 1.0** auftritt.
Am Ende haben Sie eine App, die ihre eigene Entity Configuration veröffentlicht, eine Route hinter einem Login schützt und einen Föderations-Login anstößt.
Sie brauchen dafür nur Python 3.12+ und `uv` — kein externer Dienst muss vorher laufen.

## Schritt 1: Projekt anlegen

Legen Sie ein neues Verzeichnis mit einer virtuellen Umgebung an und installieren Sie das Paket sowie einen ASGI-Server für den lokalen Testlauf.

```shell
mkdir federation-login-tutorial && cd federation-login-tutorial
uv venv && source .venv/bin/activate
uv pip install fastapi-auth-openid-federated uvicorn
```

Legen Sie eine Datei `app.py` an.
Alle folgenden Schritte ergänzen diese eine Datei.

## Schritt 2: Föderationsschlüssel erzeugen

Jede Entität in einer OpenID Federation signiert ihre eigene Entity Configuration mit einem eigenen Schlüsselpaar, den **Federation Keys**.
`OidcSettings.fed_jwks` erwartet ein JWKS-Dict mit dem privaten Schlüsselmaterial dieser RP.
Wir erzeugen dafür mit `joserfc` — einer Abhängigkeit, die das Paket ohnehin mitbringt — einen frischen RSA-Schlüssel:

```python
from joserfc.jwk import KeySet, RSAKey

signing_key = RSAKey.generate_key(key_size=2048, parameters={"kid": "rp-fed-1"}, private=True)
fed_jwks = KeySet([signing_key]).as_dict(private=True)
```

```{note}
Für dieses Tutorial genügt ein bei jedem Start neu erzeugter Schlüssel.
Wie Sie Federation Keys für einen echten Betrieb dauerhaft verwalten und rotieren, zeigt {doc}`/howto/fed-keys`.
```

## Schritt 3: OidcSettings konfigurieren

`OidcSettings` beschreibt, wer diese RP ist (`entity_id`, `base_url`) und mit welchem Schlüssel sie signiert (`fed_jwks`).
Ergänzen Sie in `app.py`:

```python
from fastapi_auth import openid

settings = openid.OidcSettings(
    entity_id="https://rp.example",
    base_url="http://localhost:8000",
    fed_jwks=fed_jwks,
    authority_hints=["https://ta.example"],
    trust_anchors={},
    session_secret="change-me-to-a-random-32-byte-value",
    cookie_secure=False,
)
```

`entity_id` ist der Identifier, unter dem diese RP in der Föderation bekannt ist.
`authority_hints` nennt die unmittelbaren Superiors dieser RP — die Entitäten, die für sie eine Subordinate Statement ausstellen.
`trust_anchors` bleibt hier bewusst leer; wir tragen in Schritt 6 nach, wozu er dient.
`cookie_secure=False` ist nur nötig, weil dieser lokale Testlauf über `http://` statt `https://` läuft.

## Schritt 4: OidcRP bauen und mounten

`OidcRP` verdrahtet Federation-Keys, Session-Store und den Router zu dieser einen konfigurierten RP.
`OidcRP.mount()` hängt ihn in die FastAPI-App ein:

```python
from fastapi import FastAPI

app = FastAPI()
rp = openid.OidcRP(settings)
rp.mount(app)
```

Starten Sie die App:

```shell
uvicorn app:app --reload
```

## Schritt 5: Die veröffentlichte Entity Configuration ansehen

`rp.mount()` hat vier Routen unter `/openid` eingehängt, darunter `/openid/.well-known/openid-federation`.
Rufen Sie sie in einem zweiten Terminal auf:

```shell
curl -i http://localhost:8000/openid/.well-known/openid-federation
```

Sie sollten `200 OK` mit `content-type: application/entity-statement+jwt` sehen, gefolgt von einem signierten JWT.
Das ist die selbstsignierte Entity Configuration dieser RP — jede an der Föderation beteiligte Entität veröffentlicht eine solche unter diesem Pfad.
Sie enthält unter anderem das öffentliche Gegenstück Ihres in Schritt 2 erzeugten Schlüssels.

## Schritt 6: Eine geschützte Route hinzufügen

`OidcRP.current_user()` liefert eine FastAPI-Dependency, die die `FederatedIdentity` aus der Session lädt oder mit `401` abbricht, wenn keine Session besteht.
Ergänzen Sie:

```python
from fastapi import Depends


@app.get("/me")
async def me(identity: openid.FederatedIdentity = Depends(rp.current_user())) -> dict[str, object]:
    return {"sub": identity.sub, "display_name": identity.display_name}
```

Rufen Sie die Route ohne eingeloggt zu sein auf:

```shell
curl -i http://localhost:8000/me
```

Sie sollten `401 Unauthorized` mit `{"detail":"Not authenticated"}` sehen.
Genau dieses Verhalten macht `/me` zu einer geschützten Route: Ohne gültige Session kommt niemand hindurch.

## Schritt 7: Den Login anstoßen

Um `/me` tatsächlich zu erreichen, muss sich jemand über einen OpenID Provider (OP) anmelden, dem diese RP vertraut.
Der Login startet über `/openid/login`, mit dem gewünschten OP als `op`-Query-Parameter:

```text
GET /openid/login?op=<entity_id_des_op>&next=/me
```

Die RP löst dabei die Trust Chain des angegebenen OP auf — sie folgt dessen `authority_hints` nach oben, bis sie einen der in `OidcSettings.trust_anchors` konfigurierten Anchor erreicht — und validiert sie kryptographisch (siehe {doc}`/explanation/trust-chain`).
Erst wenn diese Validierung erfolgreich ist, kennt die RP den `authorization_endpoint` des OP und leitet mit `303` dorthin weiter.

```{important}
Weil `trust_anchors` in diesem Tutorial leer geblieben ist, kann diese Auflösung noch bei keinem OP erfolgreich enden — das ist beabsichtigt: Ohne einen konfigurierten Anchor gibt es kein implizites Vertrauen zu irgendeiner Föderation.
Um den Login gegen einen echten OP zu Ende zu führen, tragen Sie einen Trust Anchor Ihrer Föderation ein.
Wie das geht, zeigt {doc}`/howto/trust-anchors`.
```

## Zusammenfassung

Sie haben jetzt eine FastAPI-App, die

- ihre eigene, signierte Entity Configuration unter `/openid/.well-known/openid-federation` veröffentlicht,
- eine Route mit `Depends(rp.current_user())` gegen unauthentifizierten Zugriff schützt, und
- einen Föderations-Login über `/openid/login?op=...` anstößt.

Von hier aus zeigen die How-to-Anleitungen die einzelnen Bausteine für einen echten Betrieb: {doc}`/howto/trust-anchors` für Vertrauen zu einer echten Föderation, {doc}`/howto/fed-keys` für dauerhaftes Schlüsselmanagement, {doc}`/howto/stores` für ein produktionstaugliches Session-Backend, {doc}`/howto/wayf` für die OP-Auswahl mehrerer Provider, {doc}`/howto/logout` für Logout und {doc}`/howto/docker` für den Betrieb im Container.
