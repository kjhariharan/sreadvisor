"""Application-level telemetry instrumentation: libraries the app itself uses to emit metrics.

Deliberately separate from the Dynatrace OneAgent default catalogue: these metrics come from
library instrumentation in the application and must not be assumed to overlap with OneAgent's.
"""

from __future__ import annotations

import re
from pathlib import Path

from sreadvisor.code.configfiles import ConfigEntry
from sreadvisor.graph.code_graph import SOURCE_SUFFIXES
from sreadvisor.nfr.loader import load_app_catalogue
from sreadvisor.nfr.tiers import documented_metrics
from sreadvisor.schema.dataset import Dependency, TechStackFingerprint, TelemetryAnalysis, TelemetryLibrary
from sreadvisor.util.files import evidence, iter_files, read_text, rel

# kind -> (display name, regex over "group:name" of a runtime dependency, config-key regex)
LIBRARIES: list[tuple[str, str, re.Pattern[str], re.Pattern[str]]] = [
    ("micrometer", "Micrometer", re.compile(r"io\.micrometer:micrometer-(core|registry-[\w\-]+)|:spring-boot-starter-actuator$"),
     re.compile(r"^management\.(metrics|endpoints|endpoint|prometheus|observations|datadog|newrelic|influx|statsd|jmx)\b|"
                r"^spring\.(metrics|jmx)\b", re.I)),
    ("opentelemetry", "OpenTelemetry", re.compile(r"io\.opentelemetry|opentelemetry-|:@opentelemetry/|:opentelemetry\.|OpenTelemetry"),
     re.compile(r"^(management\.(otlp|opentelemetry|tracing)|otel|OTEL_)", re.I)),
    ("prometheus_client", "Prometheus client", re.compile(r"io\.prometheus:|:prom-client$|:prometheus[-_]client$|prometheus-net"),
     re.compile(r"prometheus", re.I)),
    ("dropwizard", "Dropwizard Metrics", re.compile(r"io\.dropwizard\.metrics|com\.codahale\.metrics"),
     re.compile(r"dropwizard|metrics\.", re.I)),
    ("kafka_client", "Apache Kafka client", re.compile(r"org\.apache\.kafka:kafka-clients|:spring-kafka$|confluent-kafka|:kafkajs$|Confluent\.Kafka"),
     re.compile(r"kafka\..*(metrics|consumer|producer|listener)|spring\.kafka", re.I)),
    ("application_insights", "Azure Application Insights", re.compile(r"applicationinsights", re.I), re.compile(r"applicationinsights", re.I)),
    ("datadog_client", "Datadog client (dd-trace / dogstatsd)", re.compile(r"datadog|dd-trace|dogstatsd", re.I), re.compile(r"datadog|dd\.", re.I)),
    ("statsd", "StatsD client", re.compile(r"statsd", re.I), re.compile(r"statsd", re.I)),
]

CUSTOM_METRIC = [
    re.compile(r"""(?:Counter|Timer|Gauge|DistributionSummary|LongTaskTimer)\.builder\(\s*["']([^"']+)["']"""),
    re.compile(r"""\b(?:registry|meterRegistry|metrics)\.(?:counter|timer|gauge|summary)\(\s*["']([^"']+)["']"""),
    re.compile(r"""@Timed\(\s*(?:value\s*=\s*)?["']([^"']+)["']"""),
    re.compile(r"""@Counted\(\s*(?:value\s*=\s*)?["']([^"']+)["']"""),
    re.compile(r"""\.create(?:Counter|Histogram|UpDownCounter|ObservableGauge|Gauge)\(\s*["']([^"']+)["']"""),
    re.compile(r"""\b(?:Counter|Gauge|Histogram|Summary)\(\s*['"]([a-zA-Z_:][\w:]*)['"]"""),
    re.compile(r"""new\s+(?:client\.)?(?:Counter|Gauge|Histogram|Summary)\(\{\s*name\s*:\s*['"]([^'"]+)['"]"""),
    re.compile(r"""Metrics\.Create(?:Counter|Gauge|Histogram|Summary)\(\s*"([^"]+)\""""),
]
CUSTOM_KIND = re.compile(r"(Counter|Timer|Gauge|DistributionSummary|Histogram|Summary|counter|timer|gauge|summary)")


def _coord(d: Dependency) -> str:
    return f"{d.group or ''}:{d.name}"


def scan_telemetry(root: Path, entries: list[ConfigEntry], fp: TechStackFingerprint) -> TelemetryAnalysis:
    runtime_deps = [d for d in fp.dependencies if "test" not in d.categories]
    present_categories = {c for d in runtime_deps for c in d.categories}
    libs: list[TelemetryLibrary] = []

    for kind, display, dep_rx, key_rx in LIBRARIES:
        matches = [d for d in runtime_deps if dep_rx.search(_coord(d))]
        if not matches:
            continue
        # Kafka clients are only telemetry-relevant as a client library; keep, but describe it as such.
        lib = TelemetryLibrary(library=display, kind=kind, version=next((d.version for d in matches if d.version), None),
                               evidence=[d.evidence for d in matches[:4]])
        for e in entries:
            if key_rx.search(e.key):
                lib.configuration.append({"key": e.key, "value": e.value[:120],
                                          "evidence": evidence(e.file, e.line, f"{e.key}={e.value[:80]}").model_dump()})
        # Documented metrics come from the application instrumentation catalogue (single source of truth, tier 2).
        names, source = documented_metrics(load_app_catalogue(), kind, [_coord(d).lower() for d in runtime_deps], present_categories)
        if names:
            lib.documented_metrics = names
            lib.documented_metrics_source = source
        libs.append(lib)

    if libs:
        by_kind = {l.kind: l for l in libs}
        for f in iter_files(root, suffixes=SOURCE_SUFFIXES, include_tests=False):
            rp = rel(f, root)
            for i, line in enumerate(read_text(f).splitlines(), 1):
                for rx in CUSTOM_METRIC:
                    m = rx.search(line)
                    if m:
                        # attribute to the most specific library present
                        target = (by_kind.get("micrometer") if re.search(r"builder\(|registry|@Timed|@Counted", line) else None) \
                            or by_kind.get("opentelemetry") or by_kind.get("prometheus_client") or by_kind.get("dropwizard") \
                            or next(iter(by_kind.values()))
                        km = CUSTOM_KIND.search(line)
                        target.custom_metrics.append({"name": m.group(1), "type": km.group(1).lower() if km else "unknown",
                                                      "evidence": evidence(rp, i, line).model_dump()})
                        break
    return TelemetryAnalysis(libraries=libs)
