# fastapi-auth-openid-federated

`fastapi-auth-openid-federated` ist ein FastAPI-Baustein für einen föderierten OpenID-Connect-Relying-Party (RP).
Statt einzelne OpenID Provider (OP) manuell zu registrieren, vertraut die RP einer **OpenID Federation 1.0**: eine kryptographisch validierte Trust Chain zu einem konfigurierten Trust Anchor entscheidet, welchem OP vertraut wird.
Importiert wird das Paket über:

```python
from fastapi_auth import openid
```

## Aufbau dieser Dokumentation

Die Dokumentation folgt dem [Diataxis](https://diataxis.fr/)-Rahmenwerk und gliedert sich in vier Bereiche.

Reference
: Faktische Nachschlage-Seiten zu Konfiguration (`OidcSettings`), Identitätsmodell (`FederatedIdentity`) und der öffentlichen API.

Explanation
: Hintergrundwissen zum Trust-Chain-Modell und zum Sicherheitsmodell der RP.

Tutorial
: Ein durchgehender Föderations-Login-Durchlauf mit einer minimalen FastAPI-App, zum Nachvollziehen.

How-to
: Aufgabenorientierte Anleitungen für einzelne Konfigurationsfragen: Trust Anchors, Federation Keys, Session-Backend, OP-Discovery, Logout, Docker.

```{toctree}
:maxdepth: 2
:caption: Inhalt

tutorial/federation-login
howto/trust-anchors
howto/fed-keys
howto/stores
howto/wayf
howto/logout
howto/docker
reference/settings
reference/identity
reference/public-api
explanation/trust-chain
explanation/security-model
```
