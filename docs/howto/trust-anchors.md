# How-to: Trust Anchors und authority_hints konfigurieren

Diese Anleitung zeigt Ihnen, wie Sie Ihre RP mit den Trust Anchors einer echten Föderation verbinden, sodass Trust-Chain-Auflösung beim Login tatsächlich erfolgreich enden kann (siehe {doc}`/explanation/trust-chain` für den Hintergrund).

## Trust Anchor aus der Föderation beziehen

`OidcSettings.trust_anchors` bildet Entity-Identifier auf das **öffentliche** JWKS des jeweiligen Trust Anchors ab:

```python
trust_anchors = {
    "https://ta.example": {
        "keys": [
            {
                "kty": "RSA",
                "kid": "ta-2026-01",
                "n": "<base64url-modulus-vom-Foederationsbetreiber>",
                "e": "AQAB",
            }
        ]
    }
}
```

Beziehen Sie diesen Eintrag **out-of-band** von Ihrer Föderation, nicht durch automatisches Nachladen zur Laufzeit.
Der Betreiber des Trust Anchors veröffentlicht dessen `entity_id` und öffentliches JWKS über einen von ihm dokumentierten, vertrauenswürdigen Kanal — zum Beispiel eine signierte Konfigurationsdatei oder ein internes Registrierungsverfahren.
Tragen Sie genau diese beiden Werte in `trust_anchors` ein.

```{important}
Der oberste Schlüssel jeder Trust Chain wird ausschließlich gegen die hier konfigurierten Anchor-JWKS geprüft, niemals gegen ein über das Netz abgerufenes Statement.
Ein Eintrag, der nicht aus dem dokumentierten Out-of-Band-Kanal Ihrer Föderation stammt, öffnet die Tür zu einer falschen Föderation.
```

Wenn Sie mehreren Föderationen gleichzeitig vertrauen wollen, tragen Sie mehrere Anchors ein:

```python
trust_anchors = {
    "https://ta.example": ta_example_jwks,
    "https://ta-partner.example": ta_partner_jwks,
}
```

Eine Trust Chain gilt bereits als vertrauenswürdig, sobald sie an **einem** der konfigurierten Anchors endet.

## authority_hints der eigenen RP setzen

`OidcSettings.authority_hints` ist die Kehrseite: die Liste der unmittelbaren Superiors **dieser RP** in der Föderation.
Diese Werte erscheinen in der eigenen, unter `/openid/.well-known/openid-federation` veröffentlichten Entity Configuration und sind es, denen ein Superior folgt, um für Ihre RP eine Subordinate Statement auszustellen:

```python
settings = openid.OidcSettings(
    entity_id="https://rp.example",
    base_url="https://rp.example",
    fed_jwks=fed_jwks,
    authority_hints=["https://ta.example"],
    trust_anchors=trust_anchors,
    session_secret=session_secret,
)
```

Wenden Sie sich an den Betreiber Ihres unmittelbaren Superiors, damit er Ihre `entity_id` und Ihr öffentliches Federation-JWKS in seine Subordinate-Statement-Ausgabe aufnimmt.
Ohne diesen Schritt kann keine externe Partei Ihre RP bis zu einem Trust Anchor zurückverfolgen, selbst wenn Ihre eigene Konfiguration korrekt ist.

## Prüfen, ob die Konfiguration greift

Rufen Sie nach dem Deployment die eigene Entity Configuration ab und vergewissern Sie sich, dass `authority_hints` die erwarteten Werte enthält:

```shell
curl -s https://rp.example/openid/.well-known/openid-federation
```

Den vollständigen Login-Redirect, der diese Konfiguration tatsächlich auflöst, zeigt {doc}`/tutorial/federation-login`.
