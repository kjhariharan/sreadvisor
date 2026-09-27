"""SLI suggestions: deterministic, table-driven, sourced from whichever telemetry tier can already measure them.

Three sources, matching the three tiers Stage 2 already computed for the service:

* tier 1 (OneAgent default) drives entry-point latency and error-rate SLIs, and dependency call latency for
  datastores and outbound services — signals that exist for every monitored service with no configuration;
* tier 2 (application-level library metrics) drives SLIs a tier-1 signal cannot express, most concretely consumer
  lag for a messaging dependency (Kafka's own client metric, never a OneAgent default) and connection-pool or
  cache saturation;
* tier 3 (business-aware custom metrics) is a lookup table keyed by the business category Stage 1 inferred, with a
  generic fallback built from the service's own key operations when the category is not in the table.

No new judgment is made here: which entry points and dependencies exist, and what each tier already measures, were
decided in Stage 1 and Stage 2. This module only maps that structure onto a suggestion.
"""

from __future__ import annotations

from sreadvisor.nfr.tiers import TelemetryTiers
from sreadvisor.report.schema import SliSuggestion
from sreadvisor.schema.dataset import BusinessContext, RepoAnalysis

# category -> [(name, description, kind)]. Matches the categories the business_context_inferrer agent can choose
# (see agents/definitions.py BUSINESS_INSTRUCTION); a category with no entry falls back to _generic_business_slis.
BUSINESS_SLI_TABLE: dict[str, list[tuple[str, str, str]]] = {
    "shopping_cart": [
        ("Cart abandonment rate", "Share of carts created that are never followed by a completed checkout.", "business"),
        ("Checkout completion latency", "Time from checkout start to order confirmation.", "latency"),
    ],
    "order_management": [
        ("Order state transition timing", "Time an order spends in each state (placed, processing, shipped, delivered).", "latency"),
        ("Failed fulfillment rate", "Share of orders that fail to fulfill (cancelled, backordered, or errored).", "error_rate"),
    ],
    "payments": [
        ("Payment authorization success rate", "Share of payment authorization attempts that succeed.", "business"),
        ("Payment authorization latency", "Time from an authorization request to the provider's response.", "latency"),
    ],
    "notification": [
        ("Delivery success rate by channel", "Share of notifications confirmed delivered, broken down by channel (email, SMS, push).", "business"),
        ("Send latency by channel", "Time from a send request to delivery confirmation, per channel.", "latency"),
    ],
    "inventory": [
        ("Stock reservation failure rate", "Share of stock reservation attempts that fail (out of stock, conflict).", "error_rate"),
        ("Stock sync latency", "Time for a stock change to propagate to the systems that read it.", "latency"),
    ],
    "catalog": [
        ("Catalog search latency", "Time to return results for a catalog search or listing request.", "latency"),
        ("Catalog item availability", "Share of catalog items that resolve successfully when looked up.", "business"),
    ],
    "user_identity": [
        ("Authentication success rate", "Share of authentication attempts that succeed.", "business"),
        ("Registration completion rate", "Share of started registrations that complete.", "business"),
    ],
    "booking_scheduling": [
        ("Booking confirmation rate", "Share of booking attempts that end in a confirmed reservation.", "business"),
        ("Slot availability check latency", "Time to answer whether a requested slot is available.", "latency"),
    ],
    "customer_records": [
        ("Record lookup latency", "Time to retrieve a customer or record by id.", "latency"),
        ("Record update success rate", "Share of record update requests that succeed without conflict or validation error.", "error_rate"),
    ],
    "reporting_analytics": [
        ("Report generation latency", "Time from a report request to the finished report.", "latency"),
        ("Report data freshness", "Age of the data a generated report is based on.", "business"),
    ],
    "messaging_integration": [
        ("Message delivery success rate", "Share of integration messages that reach their destination without error.", "error_rate"),
        ("End-to-end integration latency", "Time from message send to confirmed processing at the destination.", "latency"),
    ],
}


def _generic_business_slis(business: BusinessContext) -> list[tuple[str, str, str]]:
    """Fallback for category "other" or an unlisted category: one pair of SLIs per key operation, generic but concrete."""
    out = []
    for op in business.key_operations[:3]:
        out.append((f"{op} success rate", f"Share of \"{op}\" attempts that complete without error.", "business"))
        out.append((f"{op} latency", f"Time to complete \"{op}\".", "latency"))
    return out


def business_slis(business: BusinessContext | None) -> list[tuple[str, str, str]]:
    if business is None:
        return []
    return BUSINESS_SLI_TABLE.get(business.category) or _generic_business_slis(business)


# --------------------------------------------------------------------------------------- tier lookups


def _tier1_signal(tiers: TelemetryTiers, signal_id: str):
    return next((s for s in tiers.tier1_oneagent_default.signals if s.signal.id == signal_id), None)


def _tier2_metric(tiers: TelemetryTiers, *, name_contains: str | None = None, name_prefix: str | None = None):
    """The first tier-2 metric actually present in the service (never one that is merely available if added)."""
    for m in tiers.metric_index:
        if m.tier != 2 or not m.present_in_service:
            continue
        if name_contains and name_contains not in m.name:
            continue
        if name_prefix and not m.name.startswith(name_prefix):
            continue
        return m
    return None


def _entry_point_subject(ep) -> str:
    if ep.http_method or ep.route:
        return f"{ep.http_method or ''} {ep.route or ep.symbol}".strip()
    return ep.symbol


# ---------------------------------------------------------------------------------------- entry points (tier 1)


def entry_point_slis(repos: list[RepoAnalysis], tiers: TelemetryTiers) -> list[SliSuggestion]:
    out: list[SliSuggestion] = []
    latency = _tier1_signal(tiers, "oa.service.response_time")
    failure = _tier1_signal(tiers, "oa.service.failure_rate")
    throughput = _tier1_signal(tiers, "oa.service.request_count")
    for repo in repos:
        for ep in repo.entry_points:
            subject = _entry_point_subject(ep)
            if latency:
                out.append(SliSuggestion(
                    id="", name=f"Latency: {subject}", kind="latency", subject=subject, tier=1, tier_label="OneAgent default",
                    measurement_source=f"OneAgent: {latency.signal.metric_key or latency.signal.name}", metric_key=latency.signal.metric_key,
                    signal_type=latency.signal.signal_type,
                    description=f"Response time of the {ep.kind} entry point {subject}, captured automatically once the service is monitored.",
                    rationale="Every externally reachable entry point should have a latency SLI; OneAgent measures this for any monitored service with no configuration."))
            if failure:
                out.append(SliSuggestion(
                    id="", name=f"Error rate: {subject}", kind="error_rate", subject=subject, tier=1, tier_label="OneAgent default",
                    measurement_source=f"OneAgent: {failure.signal.metric_key or failure.signal.name}", metric_key=failure.signal.metric_key,
                    signal_type=failure.signal.signal_type,
                    description=f"Share of requests to {subject} that fail.",
                    rationale="Latency without an error-rate SLI hides requests that fail fast; both are needed for a usable SLO."))
            if throughput and ep is repo.entry_points[0]:  # one service-level throughput SLI per repo is enough, not one per route
                out.append(SliSuggestion(
                    id="", name=f"Request throughput: {repo.repo}", kind="throughput", subject=repo.repo, tier=1, tier_label="OneAgent default",
                    measurement_source=f"OneAgent: {throughput.signal.metric_key or throughput.signal.name}", metric_key=throughput.signal.metric_key,
                    signal_type=throughput.signal.signal_type,
                    description="Overall request volume for the service, for capacity and anomaly-detection context.",
                    rationale="A throughput baseline lets a latency or error-rate change be read in the context of load."))
    return out


# ------------------------------------------------------------------------------------- dependencies (tier 1 / 2)

_MESSAGING_METRIC_PRIORITY = ("records-lag-max", "records-per-request-avg", "commit-latency-avg")


def dependency_slis(repos: list[RepoAnalysis], tiers: TelemetryTiers) -> list[SliSuggestion]:
    out: list[SliSuggestion] = []
    seen: set[tuple[str, str]] = set()
    db_latency = _tier1_signal(tiers, "oa.db.call_time")
    cache_calls = _tier1_signal(tiers, "oa.cache.remote_calls")
    service_latency = _tier1_signal(tiers, "oa.service.response_time")
    for repo in repos:
        for flow in repo.transaction_flows:
            for dep in flow.dependencies:
                key = (dep.kind, dep.name)
                if key in seen:
                    continue
                seen.add(key)
                if dep.kind == "datastore" and db_latency:
                    out.append(SliSuggestion(
                        id="", name=f"Query latency: {dep.name}", kind="latency", subject=dep.name, tier=1, tier_label="OneAgent default",
                        measurement_source=f"OneAgent: {db_latency.signal.metric_key or db_latency.signal.name}", metric_key=db_latency.signal.metric_key,
                        signal_type=db_latency.signal.signal_type,
                        description=f"Response time of calls from this service to {dep.name}, as seen by the caller.",
                        rationale="A hard-failure datastore dependency needs its own latency SLI so a slowdown is visible before it saturates the caller."))
                    pool = _tier2_metric(tiers, name_prefix="hikaricp.connections") or _tier2_metric(tiers, name_contains="pool")
                    if pool:
                        out.append(_saturation_from_metric(dep.name, pool, "connection pool"))
                elif dep.kind == "cache":
                    hits = _tier2_metric(tiers, name_prefix="cache.")
                    if hits:
                        out.append(SliSuggestion(
                            id="", name=f"Cache hit ratio: {dep.name}", kind="business", subject=dep.name, tier=2,
                            tier_label="application level, library emitted",
                            measurement_source=f"{hits.source}: {hits.name} (hits derived from lookups by result)", metric_key=None,
                            signal_type="counter",
                            description=f"Share of lookups against {dep.name} served from cache rather than the source of truth.",
                            rationale="Cache effectiveness is invisible to OneAgent (an in-process cache has no external call to trace); the library's own counters are the only source."))
                    elif cache_calls:
                        out.append(SliSuggestion(
                            id="", name=f"Cache call latency: {dep.name}", kind="latency", subject=dep.name, tier=1, tier_label="OneAgent default",
                            measurement_source=f"OneAgent: {cache_calls.signal.metric_key or cache_calls.signal.name}", metric_key=cache_calls.signal.metric_key,
                            signal_type=cache_calls.signal.signal_type, description=f"Response time of calls to the distributed cache {dep.name}.",
                            rationale="A distributed cache is a network dependency; OneAgent traces it like any other outbound call."))
                elif dep.kind == "messaging":
                    lag = None
                    for name in _MESSAGING_METRIC_PRIORITY:
                        lag = _tier2_metric(tiers, name_contains=name)
                        if lag:
                            break
                    if lag:
                        out.append(SliSuggestion(
                            id="", name=f"Consumer lag: {dep.name}", kind="saturation", subject=dep.name, tier=2,
                            tier_label="application level, library emitted", measurement_source=f"{lag.source}: {lag.name}", metric_key=None,
                            signal_type="gauge",
                            description=f"How far behind the latest message this service's consumer of {dep.name} is running.",
                            rationale="Consumer lag is the primary health signal for a messaging consumer and is emitted by the client library, never by OneAgent."))
                    elif service_latency:
                        out.append(SliSuggestion(
                            id="", name=f"Processing latency: {dep.name}", kind="latency", subject=dep.name, tier=1, tier_label="OneAgent default",
                            measurement_source=f"OneAgent: {service_latency.signal.metric_key}", metric_key=service_latency.signal.metric_key,
                            signal_type="metric", description=f"Time to process messages from {dep.name}.",
                            rationale="No consumer-lag metric was detected for this messaging dependency; service response time is the fallback until one is added."))
                elif dep.kind in ("http_service", "external_api") and service_latency:
                    out.append(SliSuggestion(
                        id="", name=f"Outbound call latency: {dep.name}", kind="latency", subject=dep.name, tier=1, tier_label="OneAgent default",
                        measurement_source=f"OneAgent: {service_latency.signal.metric_key}", metric_key=service_latency.signal.metric_key,
                        signal_type="metric", description=f"Response time of calls from this service to {dep.name}.",
                        rationale="Outbound calls to another service are traced automatically; this becomes the SLI for that dependency."))
    return out


def _saturation_from_metric(subject: str, m, label: str) -> SliSuggestion:
    return SliSuggestion(
        id="", name=f"{label.capitalize()} saturation: {subject}", kind="saturation", subject=subject, tier=2,
        tier_label="application level, library emitted", measurement_source=f"{m.source}: {m.name}", metric_key=None, signal_type="gauge",
        description=f"How close the {label} used to reach {subject} is to its configured limit.",
        rationale=f"Pool saturation is invisible to OneAgent; the {label} library exposes it directly, and it is the earliest warning of a capacity problem.")


# ------------------------------------------------------------------------------------------------- assemble


def suggest_slis(repos: list[RepoAnalysis], business: BusinessContext | None, tiers: TelemetryTiers) -> list[SliSuggestion]:
    suggestions = entry_point_slis(repos, tiers) + dependency_slis(repos, tiers)
    for name, description, kind in business_slis(business):
        suggestions.append(SliSuggestion(
            id="", name=name, kind=kind, subject=business.capability, tier=3, tier_label="business-aware custom instrumentation",
            measurement_source="custom instrumentation: not yet implemented", metric_key=None, signal_type=None, description=description,
            rationale=f"Derived from the service's inferred business purpose ({business.category}); neither OneAgent defaults nor the "
                     "application's existing library metrics can express this without new instrumentation."))
    seen_names: set[str] = set()
    deduped = []
    for s in suggestions:
        if s.name in seen_names:
            continue
        seen_names.add(s.name)
        deduped.append(s)
    for i, s in enumerate(deduped, 1):
        s.id = f"SLI-{i:03d}"
    return deduped
