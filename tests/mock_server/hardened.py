"""Mock GraphQL server with every control correctly applied."""

from __future__ import annotations

from .app import HARDENED, build_sdl, make_handler

PROFILE = HARDENED
SDL = build_sdl(HARDENED)


def handler():  # type: ignore[no-untyped-def]
    return make_handler(HARDENED)
