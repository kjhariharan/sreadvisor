"""Deterministic retrieval of reliability-pattern *candidates*.

The LLM is never asked to read the whole repository. This catalogue finds lines that may
implement a resilience mechanism (annotations, library calls, config keys) across the
supported stacks; the reliability agent then judges each candidate in context, which is
where its judgment is actually needed (is this really a retry? what does it protect?).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sreadvisor.code.configfiles import is_infra_file, is_noise_config
from sreadvisor.graph.code_graph import SOURCE_SUFFIXES, CodeGraph
from sreadvisor.util.files import iter_files, rel

HINTS: list[tuple[str, re.Pattern[str]]] = [
    ("retry", re.compile(r"@Retryable|@Retry\b|@RetryableTopic|RetryTemplate|Retry\.of|retryWhen|\.retry\(|resilience4j\.retry|"
                         r"spring\.retry|@retry\b|tenacity|WaitAndRetry|RetryPolicy|axios-retry|p-retry|max-?attempts|maxAttempts|backoff", re.I)),
    ("circuit_breaker", re.compile(r"@CircuitBreaker|CircuitBreaker\.of|CircuitBreakerRegistry|@HystrixCommand|HystrixCommand|"
                                   r"resilience4j\.circuitbreaker|CircuitBreakerPolicy|opossum|CircuitBreakerFactory|failureRateThreshold|"
                                   r"circuit[-_ ]?breaker|CircuitBreakerFactory", re.I)),
    ("timeout", re.compile(r"@TimeLimiter|@Timeout\b|setConnectTimeout|setReadTimeout|connect-?timeout|read-?timeout|response-?timeout|"
                           r"socket-?timeout|connectionTimeout|\.timeout\(|request-timeout|default-timeout|query\.timeout|"
                           r"connection-timeout|idle-timeout|max-lifetime|TimeoutPolicy|HttpClient.*Timeout|timeout-per-shutdown-phase", re.I)),
    ("fallback", re.compile(r"fallbackMethod|@Fallback\b|onErrorReturn|onErrorResume|\.recover\(|FallbackPolicy|fallback", re.I)),
    ("bulkhead", re.compile(r"@Bulkhead|ThreadPoolBulkhead|BulkheadPolicy|\bSemaphore\b", re.I)),
    ("rate_limiter", re.compile(r"@RateLimiter|RateLimiter\.of|bucket4j|Bucket4j|rate-?limit|ratelimit|AspNetCoreRateLimit|Throttl", re.I)),
    ("cache", re.compile(r"@Cacheable|@CacheEvict|@CachePut|@CacheResult|@EnableCaching|Caffeine|CacheManager|lru_cache|"
                         r"functools\.cache|IMemoryCache|IDistributedCache|MemoryCache|cache-manager|node-cache|spring\.cache\.|"
                         r"jcache|ehcache", re.I)),
    ("async_offload", re.compile(r"@Async\b|@EnableAsync|ThreadPoolTaskExecutor|ExecutorService|CompletableFuture\.supplyAsync")),
    ("idempotency", re.compile(r"idempoten|Idempotency-Key|@Idempotent", re.I)),
    ("health_check", re.compile(r"HealthIndicator|health\.probes|endpoint\.health|IHealthCheck|MapHealthChecks|/health|/livez|/readyz|"
                                r"livenessProbe|readinessProbe|liveness|readiness", re.I)),
    ("graceful_shutdown", re.compile(r"server\.shutdown\s*=\s*graceful|timeout-per-shutdown-phase|IHostApplicationLifetime|@PreDestroy|"
                                     r"SIGTERM|terminationGracePeriod", re.I)),
    ("transaction", re.compile(r"@Transactional|TransactionTemplate|BEGIN TRANSACTION|transaction\.atomic|@transaction", re.I)),
]
CONFIG_SUFFIXES = (".properties", ".yml", ".yaml", ".xml", ".json", ".toml", ".conf", ".config")
MAX_PER_FILE = 25


@dataclass
class Candidate:
    file: str
    line: int
    text: str
    hint: str
    context: str


def find_candidates(graph: CodeGraph, *, max_total: int = 400) -> list[Candidate]:
    root, reader = graph.root, graph.reader
    out: list[Candidate] = []
    for f in iter_files(root, suffixes=SOURCE_SUFFIXES + CONFIG_SUFFIXES, include_tests=not graph.exclude_tests):
        rp = rel(f, root)
        if f.name.lower() in ("package-lock.json", "pom.xml") or f.name.endswith(".csproj"):
            continue  # dependency manifests are handled by the fingerprint step
        lines = reader.lines(rp)
        # Infrastructure files (Kubernetes probes, CI) are analysed by the infra module, not as application code.
        if is_noise_config(rp) or (f.suffix.lower() in (".yml", ".yaml") and is_infra_file(rp, "\n".join(lines))):
            continue
        found = 0
        for i, text in enumerate(lines, 1):
            stripped = text.strip()
            if not stripped or stripped.startswith(("//", "*", "/*", "#")) and not stripped.startswith("#["):
                continue
            for hint, rx in HINTS:
                if rx.search(text):
                    ctx = reader.read(rp, max(1, i - 1), min(len(lines), i + 2), max_lines=4)
                    out.append(Candidate(rp, i, stripped[:200], hint, ctx))
                    found += 1
                    break
            if found >= MAX_PER_FILE or len(out) >= max_total:
                break
        if len(out) >= max_total:
            break
    return out
