from __future__ import annotations

from typing import Annotated

import typer  # Maybe change for type-slim

from rich import print as rich_print
from rich import print_json

from dominfo.client import IANA_DEFAULT_SERVER
from dominfo.client import DominfoClient


def main(
    domain: str,
    iana_server: str = IANA_DEFAULT_SERVER,
    as_json: Annotated[
        bool, typer.Option("--json", "-j", help="Output as JSON")
    ] = False,
) -> None:
    client = DominfoClient(server=iana_server)
    whois_info = client.get_whois_info(domain)

    if as_json:
        print_json(data=whois_info, default=str)
    else:
        rich_print(whois_info)


if __name__ == "__main__":
    typer.run(main)
