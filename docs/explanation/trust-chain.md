# Über das Trust-Chain-Modell

Ein klassischer OpenID-Connect-RP vertraut einem OP, weil ein Administrator dessen Metadaten (Issuer, Endpunkte, JWKS) manuell hinterlegt hat.
Das genügt nicht, sobald sehr viele OPs beteiligt sind, die sich unabhängig voneinander ändern — etwa in einer Hochschulföderation mit hunderten Identity-Providern.
`fastapi-auth-openid-federated` löst dieses Problem über **OpenID Federation 1.0**: Vertrauen wird nicht statisch konfiguriert, sondern bei jedem Login kryptographisch aus einer Kette signierter Entity Statements abgeleitet.

## Entity Statements als Bausteine

Jede an der Föderation beteiligte Entität — RP, OP, Intermediate, Trust Anchor — veröffentlicht eine signierte **Entity Configuration** unter `<entity_id>/.well-known/openid-federation`.
Eine Entity Configuration ist ein selbstsigniertes JWT (`iss == sub`) mit `typ: entity-statement+jwt`.
Sie enthält unter anderem das öffentliche JWKS der Entität, ihre `authority_hints` (die unmittelbaren Superiors) und optional protokollspezifische Metadaten (`metadata.openid_relying_party`, `metadata.openid_provider`, ...).

Eine übergeordnete Entität kann zusätzlich ein **Subordinate Statement** über eine untergeordnete Entität ausstellen (`iss != sub`).
Es wird über den `federation_fetch_endpoint` der übergeordneten Entität abgerufen und bindet den öffentlichen Schlüssel des Untergeordneten kryptographisch an dessen Superior.
Aneinandergereiht ergeben Entity Configuration und Subordinate Statements eine **Trust Chain**: eine Sequenz signierter Statements vom Blatt (Leaf, z. B. dem OP) bis zu einem Trust Anchor.

## Auflösung: Navigation ohne Vertrauen

`federation.trust_chain.resolve_trust_chain()` folgt den `authority_hints` einer Entität rekursiv nach oben, bis eine der Superior-Entitäten mit einem in `OidcSettings.trust_anchors` konfigurierten Anchor übereinstimmt.
Dabei wird für jede besuchte Entität zunächst deren eigene Entity Configuration geholt (um ihren `federation_fetch_endpoint` zu finden), anschließend das Subordinate Statement über die darunterliegende Entität von genau diesem Endpunkt.
Diese Auflösungsphase liest Claims ausschließlich über `jose.peek_claims()` — ein bewusst unverifiziertes Auspacken des JWT-Payloads, das nur der Navigationsentscheidung dient ("welchen Endpunkt als Nächstes abfragen?").
Kein Statement wird in dieser Phase als vertrauenswürdig behandelt.
Ein Loop-Schutz (`visited`) und eine maximale Tiefe (`max_depth`, Default `10`) verhindern endlose oder zyklische Pfade.
Findet sich kein Pfad zu einem konfigurierten Anchor, wirft die Auflösung einen `TrustChainError` — die RP versucht nicht, "irgendeinem" Anchor zu vertrauen, den sie unterwegs findet.

## Validierung: erst hier entsteht Vertrauen

Die eigentliche kryptographische Prüfung übernimmt `federation.trust_chain.validate_trust_chain()`, getrennt von der Auflösung.
Für jedes Statement wird zunächst Struktur (`typ`, Pflicht-Claims) und Frische (`iat`/`exp`, mit `clock_skew`-Toleranz) geprüft.
Anschließend wird die Signaturkette verifiziert: Statement `j` wird mit einem Schlüssel aus dem JWKS des nächsthöheren Statements `j+1` geprüft — außer dem obersten Statement, dessen Aussteller ein Trust Anchor sein muss und das ausschließlich mit dem für diesen Anchor **out-of-band konfigurierten** JWKS aus `OidcSettings.trust_anchors` verifiziert wird.
Ergänzend wird die Issuer/Subject-Verkettung geprüft (`chain[j].iss == chain[j+1].sub`) und dass das Leaf-Statement selbstsigniert ist.

```{important}
Der oberste Schlüssel der Kette kommt niemals aus einem über das Netz abgerufenen Statement, sondern ausschließlich aus der lokalen `trust_anchors`-Konfiguration.
Ohne einen passenden Eintrag dort endet keine Trust Chain erfolgreich — es gibt kein implizites Vertrauen zu einer Föderation, der man nicht explizit einen Anchor zugeordnet hat.
```

Diese Trennung von Auflösung (Navigation, ungeprüft) und Validierung (Kryptographie, geprüft) ist bewusst so gebaut: Ein Angreifer, der Netzwerkantworten manipuliert, kann die Auflösung höchstens in die Irre führen, aber keine Signaturprüfung umgehen, weil jedes Statement unabhängig gegen den Schlüssel seines Ausstellers verifiziert wird.

## Metadata Policy: wer darf was einschränken

Trust Chains transportieren nicht nur Vertrauen, sondern auch **Metadata Policies**: Regeln, mit denen ein Superior die Metadaten seiner Untergeordneten einschränken kann (etwa welche `id_token_signing_alg_values` erlaubt sind).
`federation.metadata_policy.merge_policies()` führt die Policies aller Subordinate Statements einer Kette zusammen, in der Reihenfolge Trust Anchor zuerst, unmittelbarer Superior des Leaf zuletzt.
Jeder Operator (`value`, `add`, `default`, `one_of`, `subset_of`, `superset_of`, `essential`) darf beim Zusammenführen nur enger werden, nie lockerer — ein Widerspruch (etwa zwei unterschiedliche `value`-Vorgaben) macht die gesamte Kette ungültig.
`resolve_metadata()` wendet die gemergte Policy anschließend in fester Reihenfolge auf die Leaf-Metadaten an und liefert die tatsächlich wirksamen Metadaten für einen Entity-Typ (z. B. `openid_provider`) zurück.
Das bedeutet: Eine übergeordnete Organisation (etwa ein föderationsweiter Trust Anchor) kann technische Mindeststandards erzwingen, die kein untergeordneter OP unterlaufen kann, ohne dass seine Metadaten als "broken" verworfen werden.

## Zusammenspiel im Login

`login.begin_login()` und `OidcRP.op_logout_url()` rufen `resolve_and_validate()` auf: Auflösung, Validierung und Policy-Anwendung in einem Schritt, für den gewählten OP.
Erst das Ergebnis — ein `ResolvedEntity` mit policy-aufgelösten `openid_provider`-Metadaten, darunter `authorization_endpoint`, `token_endpoint` und das protokoll-JWKS des OP — bildet die Grundlage für den eigentlichen OIDC-Ablauf.
Wie diese Metadaten anschließend im Sicherheitsmodell des Logins verwendet werden, beschreibt {doc}`/explanation/security-model`.
