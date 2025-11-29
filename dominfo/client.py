from __future__ import annotations

import contextlib
import re
import socket

from datetime import datetime


IANA_DEFAULT_SERVER = "whois.iana.org"


class DominfoClient:
    def __init__(self, server: str = IANA_DEFAULT_SERVER):
        self.server = server

    def _whois_query(self, server: str, query: str) -> str:
        try:
            with socket.create_connection((server, 43)) as sock:
                sock.sendall(f"{query}\r\n".encode())

                response_parts = []
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response_parts.append(data)

                return b"".join(response_parts).decode("utf-8", errors="ignore")

        except OSError as e:
            raise ConnectionError(f"Failed to connect to {server}: {e}") from e

    def _get_whois_server_from_iana(self, iana_response: str) -> str:
        whois_server_match = re.search(
            r"whois: \s*([^\s]+)", iana_response, re.IGNORECASE
        )
        if whois_server_match:
            return whois_server_match.group(1)

        raise ValueError("WHOIS server not found in IANA response")

    def _get_whois_raw(self, domain: str) -> str:
        iana_response = self._whois_query(self.server, domain)
        whois_server = self._get_whois_server_from_iana(iana_response)
        whois_raw = self._whois_query(whois_server, domain)

        return whois_raw

    def _parse_whois_raw(
        self, whois_raw: str
    ) -> dict[str, str | list[str] | datetime | None]:
        re_patterns = {
            "domain_name": r"Domain\s*Name: \s*([^\s]+)",
            "registry_domain_id": r"Registry\s*Domain\s*ID: \s*([^\s]+)",
            "registrar_whois_server": r"Registrar\s*WHOIS\s*Server: \s*([^\s]+)",
            "registrar_url": r"Registrar\s* URL: \s*([^\s]+)",
            "updated_date": r"Updated\s* Date: \s*([^\s]+)",
            "creation_date": r"Creation\s* Date: \s*([^\s]+)",
            "registry_expiry_date": r"Registry\s* Expiry\s* Date: \s*([^\s]+)",
            "registrar": r"Registrar: \s*([^\s]+)",
            "registrar_iana_id": r"Registrar\s* IANA\s* ID: \s*([^\s]+)",
            "name_server": r"Name\s* Server: \s*([^\s]+)",
            "dnssec": r"DNSSEC: \s*([^\s]+)",
        }

        parsed_data: dict[str, str | list[str] | datetime | None] = {}
        for key, pattern in re_patterns.items():
            matches = re.findall(pattern, whois_raw, re.IGNORECASE)
            if not matches:
                parsed_data[key] = None
                continue

            parsed_data[key] = matches if len(matches) > 1 else matches[0]

        return parsed_data

    def _clean_whois_data(
        self, whois_data: dict[str, str | datetime | list[str] | None]
    ) -> dict[str, str | list[str] | datetime | None]:
        date_fields = ["updated_date", "creation_date", "registry_expiry_date"]
        for field in date_fields:
            if not whois_data.get(field):
                continue

            date_str = whois_data[field]
            if isinstance(date_str, str):
                with contextlib.suppress(ValueError):
                    whois_data[field] = datetime.fromisoformat(
                        date_str.replace("Z", "+00:00")  # Not needed in Python 3.11+
                    )

        return whois_data

    def get_whois_info(
        self, domain: str
    ) -> dict[str, str | list[str] | datetime | None]:
        whois_raw = self._get_whois_raw(domain)
        whois_parsed = self._parse_whois_raw(whois_raw)
        return self._clean_whois_data(whois_parsed)
