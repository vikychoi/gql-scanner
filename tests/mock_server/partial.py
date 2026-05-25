"""A realistic partial target: defended, but leaks its schema (introspection on)."""

from __future__ import annotations

from .app import PARTIAL, build_sdl, make_handler

PROFILE = PARTIAL
SDL = build_sdl(PARTIAL)


def handler():  # type: ignore[no-untyped-def]
    return make_handler(PARTIAL)
