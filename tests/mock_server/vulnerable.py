"""Mock GraphQL server with every weakness toggled ON."""

from __future__ import annotations

from .app import VULNERABLE, build_sdl, make_handler

PROFILE = VULNERABLE
SDL = build_sdl(VULNERABLE)


def handler():  # type: ignore[no-untyped-def]
    return make_handler(VULNERABLE)
