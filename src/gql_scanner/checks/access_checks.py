"""Access-control checks (OWASP §"Authorization"), driven by the access matrix.

Ground-truth role→permission expectations are not declared, so these checks use
the deterministic baseline the matrix gives us — chiefly the ``unauthenticated``
role — to flag missing or inconsistent authorization:

* GQL-NODE-FIELD-ACCESS — informational: a global ``node``/``nodes`` field plus a
  direct-by-ID access probe.
* GQL-BOLA-IDOR — object-by-ID fetches reachable without authorization.
* GQL-BFLA — privileged *mutations* reachable without authentication.
* GQL-UNAUTH-ACCESS — any operation that resolves data for the anonymous role.
* GQL-EDGE-NODE-AUTHZ — connection ``edges.node`` path authorizes differently
  from the operation's scalar path.

All probes use minimal selections and benign placeholder IDs; none mutate data
unless ``--allow-mutations`` is set (mutations are SKIPPED otherwise).
"""

from __future__ import annotations

from ..config import UNAUTH_ROLE
from ..findings import Finding, Severity
from ..heuristics import Access, classify_access
from ..schema.model import Operation
from .base import Check, CheckContext

# Benign placeholder identifier used for object-by-ID access probes.
_PROBE_ID = "1"


class UnauthAccess(Check):
    id = "GQL-UNAUTH-ACCESS"
    title = "Operation reachable without authentication"
    requires_schema = True

    def run(self, ctx: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        for op in ctx.matrix.sorted_operations:
            cell = ctx.matrix.get(op, UNAUTH_ROLE)
            if cell.access is Access.ALLOWED and cell.exchange is not None:
                sev = Severity.HIGH if op.is_mutation else Severity.MEDIUM
                findings.append(
                    Finding(
                        check_id=self.id,
                        issue_name=f"{op.operation_type} '{op.name}' allowed unauthenticated",
                        description=(
                            f"The {op.operation_type} '{op.name}' resolves data for the "
                            "unauthenticated role, exposing it to anonymous clients."
                        ),
                        severity=sev,
                        raw_request=cell.exchange.raw_request,
                        raw_response=cell.exchange.raw_response,
                        remediation="Enforce authn/authz per field (Authorization).",
                        evidence=f"{op.operation_type}:{op.name}",
                    )
                )
        return findings


class BrokenFunctionLevelAuthz(Check):
    id = "GQL-BFLA"
    title = "Broken function-level authorization"
    requires_schema = True

    def run(self, ctx: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        findings += self._unauth_mutations(ctx)
        findings += self._privilege_inversion(ctx)
        return findings

    def _unauth_mutations(self, ctx: CheckContext) -> list[Finding]:
        out: list[Finding] = []
        for op in ctx.matrix.sorted_operations:
            if not op.is_mutation:
                continue
            cell = ctx.matrix.get(op, UNAUTH_ROLE)
            if cell.access is Access.ALLOWED and cell.exchange is not None:
                out.append(
                    Finding(
                        check_id=self.id,
                        issue_name=f"privileged mutation '{op.name}' has no function-level authz",
                        description=(
                            f"The state-changing mutation '{op.name}' executes for the "
                            "unauthenticated role — function-level authorization is missing."
                        ),
                        severity=Severity.HIGH,
                        raw_request=cell.exchange.raw_request,
                        raw_response=cell.exchange.raw_response,
                        remediation="Restrict mutations to authorized roles (Authorization).",
                        evidence=f"mutation:{op.name}",
                        confidence=0.85,
                        signals="unauth-mutation(0.85): mutation resolved with no credentials",
                    )
                )
        return out

    def _privilege_inversion(self, ctx: CheckContext) -> list[Finding]:
        """A lower-privilege role is ALLOWED where a higher-privilege role is DENIED.

        Only fires when ``privilege`` levels are declared (otherwise all roles tie
        at 0 and no inversion is possible) — declared ground truth → high confidence.
        """
        priv = {r.name: r.privilege for r in ctx.roles}
        if len(set(priv.values())) < 2:
            return []
        out: list[Finding] = []
        for op in ctx.matrix.sorted_operations:
            allowed_lo: tuple[str, int] | None = None
            denied_hi: tuple[str, int] | None = None
            evidence_cell = None
            for role in sorted(priv):
                cell = ctx.matrix.get(op, role)
                if cell.access is Access.ALLOWED:
                    if allowed_lo is None or priv[role] < allowed_lo[1]:
                        allowed_lo = (role, priv[role])
                        evidence_cell = cell
                elif cell.access is Access.DENIED:
                    if denied_hi is None or priv[role] > denied_hi[1]:
                        denied_hi = (role, priv[role])
            if (
                allowed_lo is not None
                and denied_hi is not None
                and allowed_lo[1] < denied_hi[1]
                and evidence_cell is not None
                and evidence_cell.exchange is not None
            ):
                out.append(
                    Finding(
                        check_id=self.id,
                        issue_name=f"privilege inversion on {op.operation_type} '{op.name}'",
                        description=(
                            f"'{op.name}' is allowed for lower-privilege role "
                            f"'{allowed_lo[0]}' (priv {allowed_lo[1]}) but denied for "
                            f"higher-privilege role '{denied_hi[0]}' (priv {denied_hi[1]}) — "
                            "function-level authorization is inconsistent."
                        ),
                        severity=Severity.HIGH,
                        raw_request=evidence_cell.exchange.raw_request,
                        raw_response=evidence_cell.exchange.raw_response,
                        remediation="Make access monotonic in privilege (Authorization).",
                        evidence=f"{op.operation_type}:{op.name}",
                        confidence=0.8,
                        signals=(
                            f"privilege-inversion(0.80): {allowed_lo[0]} allowed, "
                            f"{denied_hi[0]} denied"
                        ),
                    )
                )
        return out


class BrokenObjectLevelAuthz(Check):
    id = "GQL-BOLA-IDOR"
    title = "Broken object-level authorization (IDOR)"
    requires_schema = True

    def run(self, ctx: CheckContext) -> list[Finding]:
        if ctx.schema is None:
            return []
        if any(r.owns for r in ctx.roles):
            return self._ownership_differential(ctx)
        return self._unauth_heuristic(ctx)

    def _ownership_differential(self, ctx: CheckContext) -> list[Finding]:
        """Ground-truth BOLA: can role A read an object role B declared it owns?"""
        assert ctx.schema is not None
        out: list[Finding] = []
        by_field: dict[str, Operation] = {
            op.name: op for op in ctx.schema.queries if op.id_argument() is not None
        }
        for owner in sorted(ctx.roles, key=lambda r: r.name):
            for field_name in sorted(owner.owns):
                op = by_field.get(field_name)
                if op is None:
                    continue
                for obj_id in owner.owns[field_name]:
                    for attacker in sorted(ctx.roles, key=lambda r: r.name):
                        if attacker.name == owner.name:
                            continue
                        ex = ctx.transport.graphql(
                            ctx.url,
                            op.document_with_id(obj_id),
                            headers=attacker.headers or None,
                            cookies=attacker.cookies or None,
                        )
                        if classify_access(ex) is Access.ALLOWED:
                            out.append(
                                Finding(
                                    check_id=self.id,
                                    issue_name=(
                                        f"BOLA: '{attacker.name}' reads {field_name}#{obj_id}"
                                    ),
                                    description=(
                                        f"Role '{attacker.name}' successfully fetched "
                                        f"{field_name} id {obj_id}, which role '{owner.name}' "
                                        "owns — per-object authorization is missing."
                                    ),
                                    severity=Severity.HIGH,
                                    raw_request=ex.raw_request,
                                    raw_response=ex.raw_response,
                                    remediation="Authorize per-object access by owner (Authz).",
                                    evidence=f"{field_name}#{obj_id}->{attacker.name}",
                                    confidence=0.9,
                                    signals=(
                                        f"cross-role-access(0.90): {attacker.name} read "
                                        f"{owner.name}'s object"
                                    ),
                                )
                            )
        return out

    def _unauth_heuristic(self, ctx: CheckContext) -> list[Finding]:
        """Fallback (no ownership declared): object-by-ID reachable unauthenticated."""
        assert ctx.schema is not None
        out: list[Finding] = []
        unauth = next((r for r in ctx.roles if r.name == UNAUTH_ROLE), None)
        for op in ctx.schema.queries:
            if op.id_argument() is None:
                continue
            ex = ctx.transport.graphql(
                ctx.url,
                op.document_with_id(_PROBE_ID),
                headers=(unauth.headers or None) if unauth else None,
                cookies=(unauth.cookies or None) if unauth else None,
            )
            if classify_access(ex) is Access.ALLOWED:
                out.append(
                    Finding(
                        check_id=self.id,
                        issue_name=f"object-by-ID '{op.name}' returns data without ownership check",
                        description=(
                            f"'{op.name}' returns an object by ID to the unauthenticated role; "
                            "objects appear fetchable by ID with no ownership check. Declare role "
                            "'owns' in --roles for a precise cross-role test."
                        ),
                        severity=Severity.MEDIUM,
                        raw_request=ex.raw_request,
                        raw_response=ex.raw_response,
                        remediation="Authorize per-object access by owner (Authorization).",
                        evidence=f"query:{op.name}",
                        confidence=0.5,
                        signals="unauth-object-by-id(0.50): heuristic, no ownership ground truth",
                    )
                )
        return out


class NodeFieldAccess(Check):
    id = "GQL-NODE-FIELD-ACCESS"
    title = "Global node/nodes field present"
    requires_schema = True

    def run(self, ctx: CheckContext) -> list[Finding]:
        if ctx.schema is None or not ctx.schema.has_node_field:
            return []
        node_op = next((o for o in ctx.schema.queries if o.name in ("node", "nodes")), None)
        if node_op is None:
            return []
        ex = ctx.transport.graphql(ctx.url, node_op.document_with_id(_PROBE_ID))
        reachable = classify_access(ex) is Access.ALLOWED
        desc = f"A global '{node_op.name}' field is present" + (
            " and resolves objects directly by opaque ID." if reachable else "."
        )
        return [
            Finding(
                check_id=self.id,
                issue_name=f"global '{node_op.name}' field present",
                description=desc + " Review that per-object authorization is enforced here.",
                severity=Severity.LOW if reachable else Severity.INFO,
                raw_request=ex.raw_request,
                raw_response=ex.raw_response,
                remediation="Ensure node(id:) enforces per-object authorization (Authorization).",
                evidence=f"query:{node_op.name}",
            )
        ]


class EdgeNodeAuthz(Check):
    id = "GQL-EDGE-NODE-AUTHZ"
    title = "Edge/node authorization inconsistency"
    requires_schema = True

    def run(self, ctx: CheckContext) -> list[Finding]:
        if ctx.schema is None:
            return []
        findings: list[Finding] = []
        for op in ctx.schema.queries:
            edges_doc = op.edges_node_document()
            if edges_doc is None:
                continue
            scalar_cell = ctx.matrix.get(op, UNAUTH_ROLE)
            edges_ex = ctx.transport.graphql(ctx.url, edges_doc)
            edges_access = classify_access(edges_ex)
            scalar_access = scalar_cell.access
            if {scalar_access, edges_access} == {Access.ALLOWED, Access.DENIED}:
                findings.append(
                    Finding(
                        check_id=self.id,
                        issue_name=f"'{op.name}' authorizes edges/node path differently",
                        description=(
                            f"For '{op.name}', the scalar path is {scalar_access.value} but the "
                            f"edges.node path is {edges_access.value}; authorization is applied "
                            "inconsistently across access paths."
                        ),
                        severity=Severity.MEDIUM,
                        raw_request=edges_ex.raw_request,
                        raw_response=edges_ex.raw_response,
                        remediation="Authorize data, not the access path (Authorization).",
                        evidence=f"query:{op.name}",
                    )
                )
        return findings
