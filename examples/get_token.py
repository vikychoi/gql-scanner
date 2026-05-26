#!/usr/bin/env -S uv run
# /// script
# dependencies = ["requests"]
# ///
"""Example credential-refresh script for gql-scanner.

Referenced from a role's ``refresh`` config; gql-scanner runs it (by default via
``uv run``, which honors the PEP 723 block above so ``requests`` is guaranteed in
an isolated env) whenever that role's session looks expired.

gql-scanner passes context via environment variables:
  GQLSCAN_ROLE       the role name being refreshed
  GQLSCAN_URL        the target GraphQL URL
  GQLSCAN_OLD_TOKEN  the (expired) credential header value, if any

Print EITHER a bare token (applied via the role's inject header/template) ...
    print(access_token)
... OR a JSON object to set headers/cookies directly:
    print(json.dumps({"headers": {"Authorization": f"Bearer {access_token}"}}))
"""

from __future__ import annotations

import json
import os

import requests

URL = os.environ.get("GQLSCAN_URL", "http://localhost:5013/graphql")
ROLE = os.environ.get("GQLSCAN_ROLE", "user")


def main() -> None:
    # Adapt to your auth flow (OAuth refresh token, login mutation, etc.).
    resp = requests.post(
        URL,
        json={
            "query": (
                "mutation($u:String!,$p:String!)"
                "{ login(username:$u,password:$p){ accessToken } }"
            ),
            "variables": {"u": ROLE, "p": os.environ.get("GQLSCAN_PASSWORD", "changeme")},
        },
        timeout=15,
    )
    token = resp.json()["data"]["login"]["accessToken"]
    # Emit a JSON object so the Authorization header is set verbatim.
    print(json.dumps({"headers": {"Authorization": f"Bearer {token}"}}))


if __name__ == "__main__":
    main()
