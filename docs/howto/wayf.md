# How-to: OP-Discovery konfigurieren (passthrough vs. embedded WAYF)

Diese Anleitung zeigt Ihnen, wie Sie festlegen, welchen OpenID Provider `/openid/login` verwendet: fest vorgegeben, vom aufrufenden Client übergeben, oder über eine selbst gerenderte Auswahlseite.
Beide Varianten steuert `OidcSettings.discovery_mode`.

## Passthrough: OP kommt vom aufrufenden Client

Im Standardmodus `discovery_mode="passthrough"` übergibt der aufrufende Client den OP direkt als `op`-Query-Parameter:

```text
GET /openid/login?op=https://op.example&next=/app
```

Wenn Sie nur einen einzigen OP anbinden, sparen Sie sich den Query-Parameter, indem Sie `fixed_op_entity_id` setzen.
Er greift, sobald `/openid/login` ohne `op` aufgerufen wird:

```python
settings = openid.OidcSettings(
    entity_id="https://rp.example",
    base_url="https://rp.example",
    fed_jwks=fed_jwks,
    trust_anchors=trust_anchors,
    discovery_mode="passthrough",
    fixed_op_entity_id="https://op.example",
)
```

Ruft ein Client `/openid/login` ohne `op` auf und ist weder `op` noch `fixed_op_entity_id` gesetzt, antwortet die RP mit `400 Bad Request`.

## Embedded: eigene WAYF-Seite

Binden Sie mehrere OPs an und wollen der Person die Auswahl überlassen, setzen Sie `discovery_mode="embedded"` und listen die OPs in `op_list`:

```python
settings = openid.OidcSettings(
    entity_id="https://rp.example",
    base_url="https://rp.example",
    fed_jwks=fed_jwks,
    trust_anchors=trust_anchors,
    discovery_mode="embedded",
    op_list=[
        {"entity_id": "https://op-a.example", "display_name": "Hochschule A"},
        {"entity_id": "https://op-b.example", "display_name": "Hochschule B"},
    ],
)
```

Ruft ein Client `/openid/login` ohne `op` auf, rendert die RP selbst eine "Where Are You From"-Seite (WAYF) mit einem Link je Eintrag aus `op_list`.
Jeder Link führt zurück auf `/openid/login`, diesmal mit gesetztem `op`.
Fehlt `display_name` in einem Eintrag, zeigt die WAYF-Seite stattdessen den `entity_id`-Wert an.

```{note}
Anzeigename und Entity-ID eines OP sind Daten aus Föderationsmetadaten und damit aus RP-Sicht nicht vertrauenswürdige Eingaben.
Die WAYF-Seite rendert deshalb grundsätzlich mit aktiviertem Autoescape — Details dazu in {doc}`/explanation/security-model`.
```

## Beide Modi kombinieren

`op` in der URL hat in beiden Modi Vorrang: Auch im `"embedded"`-Modus überspringt ein mitgegebener `op`-Parameter die WAYF-Seite und startet den Login direkt gegen diesen OP.
Nutzen Sie das etwa für Deep-Links, die eine bestimmte Hochschule bereits kennen, während die allgemeine Login-Schaltfläche weiterhin auf die WAYF-Seite führt.
