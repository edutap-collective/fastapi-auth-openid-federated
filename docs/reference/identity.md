# FederatedIdentity und Claim-Registry

`FederatedIdentity` (`fastapi_auth.openid.identity.model.FederatedIdentity`) ist die kuratierte, typisierte Sicht auf die Claims, die ein OpenID Provider für eine authentifizierte Person freigibt.
Sie ist ein `pydantic.BaseModel`.

## Felder

| Feld | Typ | Default | Bedeutung |
|---|---|---|---|
| `sub` | `str \| None` | `None` | Stabiler Subject-Identifier beim OP. |
| `iss` | `str \| None` | `None` | Entity-Identifier des ausstellenden OP. |
| `eppn` | `str \| None` | `None` | eduPerson Principal Name. |
| `affiliation` | `list[str]` | `[]` | eduPerson-Affiliation (z. B. `member`, `staff`). |
| `scoped_affiliation` | `list[str]` | `[]` | eduPerson-Affiliation mit Scope (z. B. `staff@lmu.de`). |
| `entitlement` | `list[str]` | `[]` | eduPerson-Entitlements (Autorisierungs-URIs). |
| `assurance` | `list[str]` | `[]` | eduPerson-Assurance-Profile (Identitätssicherungsniveau). |
| `mail` | `list[str]` | `[]` | E-Mail-Adressen. |
| `email_verified` | `bool \| None` | `None` | Ob die primäre E-Mail-Adresse vom OP als verifiziert markiert wurde. |
| `display_name` | `str \| None` | `None` | Anzeigename. |
| `given_name` | `str \| None` | `None` | Vorname. |
| `surname` | `str \| None` | `None` | Nachname. |
| `preferred_username` | `str \| None` | `None` | Bevorzugter Benutzername. |
| `preferred_language` | `str \| None` | `None` | Bevorzugtes Locale. |
| `picture` | `str \| None` | `None` | URL eines Profilbilds. |
| `home_organization` | `str \| None` | `None` | SCHAC Home Organization. |
| `acr` | `str \| None` | `None` | Authentication Context Class Reference. |
| `amr` | `list[str]` | `[]` | Authentication Method References. |
| `auth_time` | `int \| None` | `None` | Zeitpunkt der Authentifizierung beim OP (Unix-Epoch). |
| `claims` | `dict[str, object]` | `{}` | Escape Hatch: sämtliche empfangenen Claims (ID-Token und ggf. Userinfo), unverändert. |

```{note}
Feldnamen, die es auch im `saml`-Schwesterpaket gibt, sind absichtlich identisch benannt, damit Code, der beide Pakete konsumiert, `FederatedIdentity` einheitlich behandeln kann.
```

## Claim-Registry

`fastapi_auth.openid.identity.registry.REGISTRY` ordnet bekannte OIDC-Claim-Namen den `FederatedIdentity`-Feldern zu.
Sie deckt Standard-OpenID-Connect-Claims sowie eduPerson-/SCHAC-Claims über OIDC ab, wie sie REFEDS "OIDCre" definiert.
`multivalued` gibt an, ob das Zielfeld eine Liste ist; ein skalarer Claim-Wert wird in diesem Fall in eine einelementige Liste umgewandelt.

| `FederatedIdentity`-Feld | OIDC-Claim | Mehrwertig |
|---|---|---|
| `sub` | `sub` | Nein |
| `iss` | `iss` | Nein |
| `mail` | `email` | Ja |
| `email_verified` | `email_verified` | Nein |
| `display_name` | `name` | Nein |
| `given_name` | `given_name` | Nein |
| `surname` | `family_name` | Nein |
| `preferred_username` | `preferred_username` | Nein |
| `preferred_language` | `locale` | Nein |
| `picture` | `picture` | Nein |
| `acr` | `acr` | Nein |
| `amr` | `amr` | Ja |
| `auth_time` | `auth_time` | Nein |
| `eppn` | `eduperson_principal_name` | Nein |
| `scoped_affiliation` | `eduperson_scoped_affiliation` | Ja |
| `affiliation` | `eduperson_affiliation` | Ja |
| `entitlement` | `eduperson_entitlement` | Ja |
| `assurance` | `eduperson_assurance` | Ja |
| `home_organization` | `schac_home_organization` | Nein |

`registry.resolve(claim: str) -> ClaimDef | None`
: Löst eine Claim-Definition anhand des OIDC-Claim-Namens auf; gibt `None` zurück, wenn der Claim nicht in der Registry geführt wird.

## map_claims

```python
def map_claims(claims: Mapping[str, object]) -> FederatedIdentity
```

`fastapi_auth.openid.identity.mapper.map_claims` baut aus einem flachen Claims-Dict (ID-Token, optional zusammengeführt mit Userinfo) eine `FederatedIdentity`.
Für jeden Claim mit einem in der Registry bekannten Namen wird der Wert in das zugehörige Feld geschrieben; unbekannte Claims werden für die typisierten Felder ignoriert.
`None`-Werte werden übersprungen.
Das vollständige Eingabe-Dict landet unverändert im `claims`-Feld.
`map_claims` ist eine reine Funktion ohne OIDC-, JOSE- oder Netzwerk-Abhängigkeiten.

## select_identifier

```python
def select_identifier(
    identity: FederatedIdentity,
    primary: str,
    fallback: Sequence[str] = (),
) -> str | None
```

`fastapi_auth.openid.identity.identifier.select_identifier` liefert den ersten nicht-leeren Wert der übergebenen Feldnamen in Präferenz-Reihenfolge (`primary`, dann `fallback`).
Jeder Name muss ein Feld von `FederatedIdentity` sein, zum Beispiel `"sub"` oder `"eppn"`.
Bei einem listenwertigen Feld wird das erste Element verwendet.
`OidcRP.identifier()` ruft diese Funktion mit `primary="sub"` und `fallback=["eppn", "preferred_username"]` auf.
