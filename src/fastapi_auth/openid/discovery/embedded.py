"""Embedded Where-Are-You-From (WAYF) renderer: a self-hosted OP picker page.

Renders a minimal HTML list of OpenID Providers. Each entry links back to the
RP's own login endpoint with the chosen OP's entity id attached.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote

from jinja2 import Environment

TEMPLATE_NAME = "wayf.html"


@dataclass(frozen=True)
class OpChoice:
    """One selectable OpenID Provider in the WAYF picker."""

    entity_id: str
    display_name: str


def render_wayf(ops: list[OpChoice], login_path: str, next_url: str, jinja_env: Environment) -> str:
    """Render the embedded WAYF page listing ``ops`` as links to ``login_path``.

    Each link is ``{login_path}?op=<url-encoded entity_id>&next=<url-encoded next_url>``.
    OP display names and entity ids originate from federation metadata and are
    therefore untrusted; the template MUST render with autoescape enabled (the
    caller is responsible for constructing ``jinja_env`` that way).
    """
    encoded_next = quote(next_url, safe="")
    entries = [
        {
            "display_name": op.display_name,
            "href": f"{login_path}?op={quote(op.entity_id, safe='')}&next={encoded_next}",
        }
        for op in ops
    ]
    template = jinja_env.get_template(TEMPLATE_NAME)
    return template.render(ops=entries)
