"""Check abstract base class and the per-run context handed to every check."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..accessmatrix import AccessMatrix
from ..config import Role, Settings
from ..exchange import Exchange
from ..findings import Finding
from ..reporter import Reporter
from ..schema.model import SchemaModel
from ..schema.reconstruct import ReconstructResult
from ..session import SessionManager
from ..transport import Transport


@dataclass(frozen=True)
class CheckContext:
    """Everything a check needs. Checks are pure over this; only ``transport`` does I/O."""

    settings: Settings
    transport: Transport
    schema: SchemaModel | None
    matrix: AccessMatrix
    introspection_enabled: bool
    reconstruction: ReconstructResult | None = None
    reporter: Reporter | None = None
    session: SessionManager | None = None
    # Shared, mutable scratch space so checks that derive from the same expensive
    # probing (e.g. the injection families) compute it once. Frozen dataclass keeps
    # the binding fixed; the dict contents are intentionally mutable.
    cache: dict[str, object] = field(default_factory=dict)

    @property
    def url(self) -> str:
        return self.settings.url

    @property
    def roles(self) -> list[Role]:
        return self.settings.roles

    def primary_role(self) -> Role:
        """The role to use for behavior probes that test a control, not authz.

        Injection/DoS probes want to reach resolvers, so they use the first
        authenticated role (alphabetical) if one exists, else unauthenticated.
        """
        authed = [r for r in self.settings.roles if not r.is_unauth]
        return authed[0] if authed else self.settings.roles[0]

    def primary_creds(self) -> tuple[dict[str, str] | None, dict[str, str] | None]:
        role = self.primary_role()
        # Prefer the session's current (possibly-refreshed) credentials.
        if self.session is not None:
            creds = self.session.creds(role.name)
            return (creds.merged_headers(), creds.merged_cookies())
        return (role.headers or None, role.cookies or None)

    def send(
        self,
        role_name: str,
        document: str,
        *,
        variables: dict[str, Any] | None = None,
        operation_name: str | None = None,
    ) -> Exchange:
        """Send a GraphQL op as ``role_name``, refresh-aware when a session exists.

        Routes through the :class:`SessionManager` (so an expired token is refreshed
        and the request replayed) when one is wired in; otherwise falls back to a
        direct transport send with the role's static credentials — the path unit
        tests take when they build a context without a session.
        """
        if self.session is not None:
            return self.session.graphql(
                self.transport,
                role_name,
                document,
                variables=variables,
                operation_name=operation_name,
            )
        role = next((r for r in self.settings.roles if r.name == role_name), None)
        return self.transport.graphql(
            self.url,
            document,
            headers=(role.headers or None) if role else None,
            cookies=(role.cookies or None) if role else None,
            variables=variables,
            operation_name=operation_name,
        )


# Scan categories — a run can enable the access-control scan, the vulnerability scan,
# or both. Each check declares which one it belongs to.
CATEGORY_ACCESS_CONTROL = "access-control"
CATEGORY_VULNERABILITY = "vulnerability"


class Check(ABC):
    """A single, idempotent, read-only-by-default control from the OWASP sheet."""

    id: str
    title: str
    requires_schema: bool = False
    is_mutation_probe: bool = False  # gated by --allow-mutations when True
    category: str = CATEGORY_VULNERABILITY  # access-control checks override this

    @abstractmethod
    def run(self, ctx: CheckContext) -> list[Finding]:
        """Run the check and return zero or more findings."""
        raise NotImplementedError
