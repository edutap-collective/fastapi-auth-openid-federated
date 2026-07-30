# Über das Sicherheitsmodell

Diese Seite ordnet die einzelnen Sicherheitsmechanismen der RP in ein Gesamtbild ein.
Sie beschreibt, welche Angriffe jeder Mechanismus adressiert und warum er so und nicht anders gebaut ist.
Für die zugrundeliegende Vertrauensherleitung siehe {doc}`/explanation/trust-chain`.

## Algorithmus-Pinning statt "alg" vom Angreifer

Jede Signaturprüfung im Paket — Trust-Chain-Statements (`federation.jose.DEFAULT_SIGNING_ALGORITHMS`) ebenso wie das ID-Token (`OidcSettings.id_token_signing_alg_values`) — übergibt die erlaubten Algorithmen explizit an `joserfc`, statt dem `alg`-Header im Token zu vertrauen.
`joserfc.jwt.decode()` prüft von sich aus weder `exp` noch `iat`; das Paket validiert diese Claims deshalb an jeder Stelle separat und explizit, mit einer über `clock_skew` konfigurierbaren Toleranz.
`"none"` ist an keiner Stelle ein zulässiger Algorithmus — für das JWT-Session-Backend erzwingt ein Pydantic-Validator das zusätzlich zur Laufzeit (`OidcSettings._check_jwt_alg_not_none`).
Diese Explizitheit ist die Antwort auf die bekannte JWT-Schwachstellenklasse "Algorithm Confusion": Ein Angreifer, der den `alg`-Header eines Tokens auf `none` oder auf einen symmetrischen Algorithmus mit einem ihm bekannten Schlüssel (etwa dem öffentlichen RSA-Schlüssel als HMAC-Secret) umschreibt, kann damit keine gültige Signatur erzeugen, weil die erlaubte Algorithmenliste serverseitig fixiert ist.

## PKCE, state und nonce

Jeder Login-Vorgang (`oidc.login.begin_login()`) erzeugt drei unabhängige, zufällige Werte mit `secrets.token_urlsafe()`: ein `state`, eine `nonce` und einen PKCE-`code_verifier` (S256-Challenge).
Alle drei werden serverseitig im `LoginStateStore` unter dem `state` abgelegt, mit einer über `login_state_ttl` begrenzten Gültigkeit.
Der Callback-Endpunkt entnimmt (`state_store.pop()`) den gespeicherten Zustand exakt einmal — ein wiederholter Callback mit demselben `state` findet keinen Eintrag mehr und schlägt fehl.
`state` bindet Authorization Request und Callback aneinander und schützt vor Cross-Site-Request-Forgery auf den Login-Vorgang.
`nonce` wird als Claim im ID-Token erwartet (`oidc.id_token.validate_id_token()` vergleicht sie mit dem gespeicherten Wert) und verhindert die Wiedereinspielung eines fremden, gültigen ID-Tokens in eine andere Session.
Der PKCE-`code_verifier` wird erst beim Token-Austausch offengelegt; ohne ihn ist ein abgefangener Authorization Code beim Token-Endpunkt des OP wertlos.

## Signiertes Request Object mit aud = OP

Statt Authorization-Request-Parameter offen als Query-String zu senden, baut `oidc.request_object.build_request_object()` ein signiertes JWT (`typ: oauth-authz-req+jwt`, OpenID Federation §12.1.1.1) und signiert es mit dem föderationseigenen Schlüssel der RP.
Sein `aud` ist ausschließlich die Entity-ID des adressierten OP, sein `iss`/`client_id` die Entity-ID der RP, und es trägt bewusst **keinen** `sub`-Claim.
Der fehlende `sub`-Claim ist kein Versehen: Ein Request Object mit `sub` ließe sich sonst als `private_key_jwt`-Client-Assertion missbrauchen, weil beide Tokentypen mit demselben Schlüssel signiert sind.
Die enge `aud`-Bindung stellt sicher, dass ein für OP A signiertes Request Object nicht bei OP B eingereicht werden kann.

## ID-Token-Validierung gegen die Trust-Chain-JWKS

`oidc.login.complete_login()` verifiziert das vom OP zurückgegebene ID-Token mit dem `op_jwks`, das aus der bereits validierten Trust Chain stammt (`login_state.op_metadata`) — nicht mit einem erneut, unauthentifiziert von einer OIDC-Discovery-URL abgerufenen JWKS.
`oidc.id_token.validate_id_token()` prüft zusätzlich `iss` gegen den erwarteten Issuer, dass `client_id` in `aud` enthalten ist (bei mehreren Audiences zusätzlich `azp == client_id`), `nonce` gegen den gespeicherten Wert sowie `iat`/`exp` mit Clock-Skew.
Damit hängt die Vertrauenswürdigkeit des ID-Tokens durchgängig an derselben kryptographisch verifizierten Kette wie die Metadaten des OP — es gibt keinen zweiten, schwächer abgesicherten Pfad, über den ein Angreifer OP-Schlüssel unterschieben könnte.

## Session-Cookie-Härtung

Das `CookieBackend` setzt das Session-Cookie mit `httponly=True`, `samesite="lax"` und — sofern `OidcSettings.cookie_secure` nicht bewusst deaktiviert wurde — `secure=True`.
`httponly` verhindert den Zugriff durch clientseitiges JavaScript und damit Session-Diebstahl über XSS.
`samesite="lax"` unterbindet das automatische Mitsenden des Cookies bei plattformübergreifenden POST-Requests und mindert CSRF-Risiken.
Der Cookie-Inhalt ist nicht die Session selbst, sondern eine mit `itsdangerous.URLSafeTimedSerializer` signierte Session-ID; die eigentliche `FederatedIdentity` liegt serverseitig im konfigurierten `Store`.
Eine manipulierte oder abgelaufene Signatur (`BadSignature`, `SignatureExpired`) wird beim Lesen abgefangen und wie "keine Session" behandelt, statt einen Fehler zu werfen.

## Open-Redirect-Schutz

Login (`next`) und Logout (`next`) akzeptieren ein clientseitig beeinflussbares Redirect-Ziel.
`redirect.is_safe_redirect()` lässt nur zwei Formen zu: einen einzelnen, mit genau einem `/` beginnenden lokalen Pfad (explizit **nicht** `//` oder `/\`, die im Browser als protokollrelative, also cross-origin URLs interpretiert werden) oder eine absolute `http`/`https`-URL, deren Host in `OidcSettings.allowed_redirect_hosts` allowlisted ist.
Werte mit ASCII-Steuerzeichen werden als Verteidigung in der Tiefe pauschal verworfen, um Header- beziehungsweise Response-Splitting-Tricks abzufangen, die vorgelagerte Parser übersehen könnten.
Jeder andere Wert fällt zurück auf `/`.
Ohne diese Prüfung könnte ein Angreifer einen Login-Link mit `next=https://evil.example` verteilen und Nutzende nach erfolgreicher Authentifizierung auf eine fremde Seite umleiten.

## WAYF-Autoescape

Im `discovery_mode="embedded"` rendert die RP selbst eine "Where Are You From"-Auswahlseite (`discovery.embedded.render_wayf()`) mit den in `OidcSettings.op_list` konfigurierten OP-Einträgen.
Anzeigename und Entity-ID eines OP sind grundsätzlich Daten aus Föderationsmetadaten, also aus RP-Sicht nicht vertrauenswürdige Eingaben.
`OidcRP` initialisiert die Jinja2-Umgebung deshalb mit `autoescape=select_autoescape()`, ausdrücklich nicht abschaltbar über die Konfiguration.
Ohne Autoescape könnte ein bösartig benannter OP-Eintrag (etwa ein `display_name` mit eingebettetem `<script>`) zu Cross-Site-Scripting auf der WAYF-Seite führen.

## Best-effort Logout

`/logout` löscht immer zuerst die lokale Session (`backend.revoke()`).
Ist `enable_op_logout` aktiviert, versucht `OidcRP.op_logout_url()` zusätzlich, den `end_session_endpoint` des OP über eine frische Trust-Chain-Auflösung zu ermitteln und dorthin weiterzuleiten.
Jeder Fehler in diesem zusätzlichen Schritt — nicht erreichbarer OP, gebrochene Trust Chain, fehlender `end_session_endpoint` — wird abgefangen und führt zu einem lokalen Logout statt zu einem Fehler.
Diese Entscheidung ist bewusst: Der lokale Schutz der eigenen Anwendung (keine gültige Session mehr) darf niemals von der Erreichbarkeit oder dem Wohlverhalten eines externen OP abhängen.
Ein vollständiges Single Logout über alle beteiligten Systeme hinweg ist damit ausdrücklich ein "best effort", keine Garantie.
