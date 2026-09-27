"""Application-level capacity settings: connection pools, thread pools, server limits, rate limiters.

Read from config files and (for settings that live in code) source lines. Framework defaults are
recorded separately, labelled ``framework_default``, so they are never mistaken for explicit config.
"""

from __future__ import annotations

import re
from pathlib import Path

from sreadvisor.code.configfiles import ConfigEntry
from sreadvisor.graph.code_graph import SOURCE_SUFFIXES
from sreadvisor.schema.dataset import CapacitySetting, TechStackFingerprint
from sreadvisor.util.files import evidence, iter_files, read_text, rel

# (category, regex over the dotted config key)
CONFIG_KEYS: list[tuple[str, re.Pattern[str]]] = [
    ("db_pool", re.compile(r"(^|\.)hikari\.(maximum-?pool-?size|minimum-?idle|connection-?timeout|idle-?timeout|max-?lifetime|"
                           r"leak-?detection-?threshold|pool-?name)$", re.I)),
    ("db_pool", re.compile(r"datasource\.(tomcat|dbcp2?|c3p0)\.(max-?active|max-?total|max-?idle|min-?idle|initial-?size|max-?wait)", re.I)),
    ("db_pool", re.compile(r"(quarkus\.datasource.*jdbc\.(max-size|min-size|initial-size|acquisition-timeout|idle-removal-interval))", re.I)),
    ("db_pool", re.compile(r"(spring\.r2dbc\.pool\.(max-size|initial-size|max-idle-time))|hibernate\.c3p0\.(max_size|min_size)|"
                           r"(^|\.)max_?pool_?size$|maximum pool size|max pool size", re.I)),
    ("cache_pool", re.compile(r"(redis|lettuce|jedis).*pool\.(max-active|max-idle|min-idle|max-wait)", re.I)),
    ("server_limits", re.compile(r"server\.(tomcat|jetty|undertow|netty)\.(threads\.\w+|max-connections|accept-count|"
                                 r"connection-timeout|max-http-form-post-size|processor-cache|io-threads|worker-threads)", re.I)),
    ("server_limits", re.compile(r"(^|\.)server\.(max-http-(request-)?header-size|connection-timeout)$", re.I)),
    ("thread_pool", re.compile(r"spring\.task\.(execution|scheduling)\.pool\.\w+|spring\.task\.execution\.pool\.queue-capacity|"
                               r"quarkus\.(thread-pool|vertx)\.[\w\-.]+|quarkus\.http\.(io-threads|limits\.[\w\-.]+)|"
                               r"spring\.mvc\.async\.request-timeout|spring\.threads\.virtual\.enabled", re.I)),
    ("rate_limiter", re.compile(r"(ratelimiter|rate-?limit|bucket4j|replenish-?rate|burst-?capacity|limit-?for-?period|"
                                r"limit-?refresh-?period)", re.I)),
    ("bulkhead", re.compile(r"(bulkhead)\.[\w\-.]*(max-?concurrent-?calls|max-?thread-?pool-?size|core-?thread-?pool-?size|"
                            r"queue-?capacity|max-?wait-?duration)", re.I)),
]

# (category, regex over a source line, description)
CODE_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("thread_pool", re.compile(r"Executors\.new(Fixed|Cached|Scheduled|WorkStealing|SingleThread\w*|VirtualThread\w*)\w*\("), "Executors factory"),
    ("thread_pool", re.compile(r"new\s+ThreadPoolExecutor\("), "ThreadPoolExecutor"),
    ("thread_pool", re.compile(r"\.set(Core|Max)PoolSize\(|\.setQueueCapacity\(|ThreadPoolTaskExecutor|@EnableAsync"), "Spring task executor"),
    ("thread_pool", re.compile(r"ThreadPoolExecutor\(\s*max_workers|ProcessPoolExecutor\(|workers\s*=\s*\d+|--workers[ =]\d+|UV_THREADPOOL_SIZE"), "Python/Node worker pool"),
    ("thread_pool", re.compile(r"ThreadPool\.SetM(in|ax)Threads|MaxConcurrentConnections|MaxConcurrentUpgradedConnections"), ".NET thread/connection limits"),
    ("db_pool", re.compile(r"setMaximumPoolSize\(|setMinimumIdle\(|pool_size\s*=|max_overflow\s*=|MaxPoolSize|Max Pool Size|"
                           r"Maximum Pool Size|new\s+(pg\.)?Pool\(\{[^}]*\bmax\s*:"), "connection pool setting in code"),
    ("rate_limiter", re.compile(r"RateLimiter\.(create|of)\(|@RateLimiter\b|new\s+Bucket4j|Bucket\.builder\(|AddRateLimiter|"
                                r"UseRateLimiter|slowapi|Limiter\("), "rate limiter in code"),
    ("bulkhead", re.compile(r"new\s+Semaphore\(\s*\d+|@Bulkhead\b|Bulkhead\.of\("), "bulkhead / concurrency limit in code"),
]

# Framework defaults (documented values), only emitted when the setting is not explicit.
_DEFAULTS = [
    ("db_pool", "spring.datasource.hikari.maximum-pool-size", "10", "HikariCP default", ("starter-data-jpa", "starter-jdbc", "hikari")),
    ("server_limits", "server.tomcat.threads.max", "200", "embedded Tomcat default", ("starter-web", "starter-webmvc")),
    ("server_limits", "server.tomcat.max-connections", "8192", "embedded Tomcat default", ("starter-web", "starter-webmvc")),
    ("server_limits", "server.tomcat.accept-count", "100", "embedded Tomcat default", ("starter-web", "starter-webmvc")),
]


def scan_capacity(root: Path, entries: list[ConfigEntry], fp: TechStackFingerprint) -> list[CapacitySetting]:
    out: list[CapacitySetting] = []
    seen_keys: set[str] = set()
    for e in entries:
        for category, rx in CONFIG_KEYS:
            if rx.search(e.key):
                out.append(CapacitySetting(layer="application", category=category, key=e.key, value=e.value,
                                           evidence=evidence(e.file, e.line, e.raw or f"{e.key}={e.value}")))
                seen_keys.add(e.key)
                break

    for f in iter_files(root, suffixes=SOURCE_SUFFIXES, include_tests=False):
        rp = rel(f, root)
        for i, line in enumerate(read_text(f).splitlines(), 1):
            s = line.strip()
            if s.startswith(("//", "*", "/*", "#")):
                continue
            for category, rx, desc in CODE_PATTERNS:
                if rx.search(line):
                    out.append(CapacitySetting(layer="application", category=category, key=desc, value=s[:160],
                                               evidence=evidence(rp, i, s)))
                    break

    is_spring = any(fw.name == "Spring Boot" for fw in fp.frameworks)
    if is_spring:
        for category, key, value, subject, needles in _DEFAULTS:
            if key in seen_keys:
                continue
            trigger = next((d for d in fp.dependencies if "test" not in d.categories
                            and any(n in d.name for n in needles)), None)
            if trigger:
                out.append(CapacitySetting(layer="application", category=category, key=key, value=value,
                                           origin="framework_default", subject=subject, evidence=trigger.evidence))
    out.sort(key=lambda c: (c.origin != "explicit", c.category, c.evidence.file if c.evidence else "", c.evidence.line if c.evidence and c.evidence.line else 0))
    return out
