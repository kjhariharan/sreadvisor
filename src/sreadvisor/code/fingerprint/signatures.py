"""Known-signature tables: dependency coordinates -> framework and category.

Coordinates are matched as ``group:name`` (lower-case; ``group`` is empty for npm/pypi).
Extend these tables when a new stack or library needs recognising; no parser changes needed.
"""

from __future__ import annotations

import re

# (framework name, regex over "group:name"). Order matters: first hit per name wins.
FRAMEWORK_RULES: list[tuple[str, str]] = [
    ("Spring Boot", r"^org\.springframework\.boot:"),
    ("Spring Framework", r"^org\.springframework(\.\w+)*:spring-(core|context|web|webmvc|webflux)$"),
    ("Quarkus", r"^io\.quarkus(\.\w+)*:"),
    ("Micronaut", r"^io\.micronaut(\.\w+)*:"),
    ("Jakarta EE", r"^jakarta\.platform:"),
    ("Express", r"^:express$"),
    ("NestJS", r"^:@nestjs/core$"),
    ("Next.js", r"^:next$"),
    ("React", r"^:react$"),
    ("Angular", r"^:@angular/core$"),
    ("Django", r"^:django$"),
    ("Flask", r"^:flask$"),
    ("FastAPI", r"^:fastapi$"),
    ("Gin", r"^:github\.com/gin-gonic/gin$"),
    ("Echo", r"^:github\.com/labstack/echo(/v\d+)?$"),
    ("Fiber", r"^:github\.com/gofiber/fiber(/v\d+)?$"),
    ("Chi", r"^:github\.com/go-chi/chi(/v\d+)?$"),
    ("Axum", r"^:axum$"),
    ("Actix Web", r"^:actix-web$"),
    ("Rocket", r"^:rocket$"),
    ("Tonic", r"^:tonic$"),
    ("ASP.NET Core", r"^:microsoft\.aspnetcore(\.\w+)*$"),
    ("Entity Framework Core", r"^:microsoft\.entityframeworkcore(\.\w+)*$"),
]

# (category, regex over "group:name"). A dependency may fall into several categories.
CATEGORY_RULES: list[tuple[str, str]] = [
    ("datastore", r"(mysql|mariadb|postgres|psycopg|h2database|:h2$|hsqldb|oracle|ojdbc|mssql|sqlserver|sqlite|mongo|cassandra|"
                  r"couchbase|dynamodb|elasticsearch|opensearch|neo4j|jdbc|hibernate|jpa|jooq|mybatis|sqlalchemy|"
                  r"npgsql|entityframeworkcore|typeorm|sequelize|prisma|mongoose|pg$|mysql2|knex|liquibase-core|"
                  r"pgx|lib/pq|go-sql-driver|gorm\.io|sqlx|diesel|tokio-postgres|rusqlite)"),
    ("cache", r"(caffeine|ehcache|cache-api|jcache|starter-cache|redis|lettuce|jedis|memcached|hazelcast|infinispan|ioredis)"),
    ("messaging", r"(kafka|rabbit|amqp|activemq|artemis|jms|pulsar|sqs|sns|servicebus|eventhub|nats|celery|kombu|masstransit|bullmq|sarama|lapin)"),
    ("http_client", r"(okhttp|httpclient|httpcomponents|feign|webflux|reactor-netty|retrofit|axios|node-fetch|got$|:requests$|httpx|aiohttp|"
                    r"microsoft\.extensions\.http|refit|resttemplate|spring-web$|jersey-client|rest-client|reqwest)"),
    ("resilience", r"(resilience4j|hystrix|failsafe|spring-retry|spring-cloud-circuitbreaker|polly|tenacity|backoff|opossum|cockatiel|"
                   r"fault-tolerance|bucket4j|ratelimit|gobreaker|retry-go|failsafe-go)"),
    ("telemetry", r"(micrometer|opentelemetry|prometheus|dropwizard|metrics-core|actuator|applicationinsights|prom-client|"
                  r"opencensus|datadog|newrelic|statsd|zipkin|brave|jaeger|otel)"),
    ("security", r"(spring-security|oauth2|keycloak|jjwt|jose|passport|identity|authentication|jwt|shiro)"),
    ("secrets", r"(vault|keyvault|secretsmanager|secret-manager|jasypt|hvac|azure\.security)"),
    ("schema_migration", r"(flyway|liquibase|alembic|entityframeworkcore\.design|knex|sequelize-cli|umzug)"),
    ("audit", r"(envers|spring-data-envers|audit|javers)"),
    ("web", r"(spring-boot-starter-web|starter-webflux|spring-webmvc|jersey|resteasy|quarkus-rest|quarkus-resteasy|"
            r"thymeleaf|vertx-web|:express$|fastify|koa|:flask$|fastapi|django|aspnetcore|micronaut-http-server)"),
    ("test", r"(junit|mockito|testcontainers|assertj|hamcrest|spring-boot-starter-test|spring-boot-test|jest|mocha|pytest|"
             r"xunit|nunit|moq|wiremock|rest-assured|quarkus-junit)"),
]

_FW = [(n, re.compile(p)) for n, p in FRAMEWORK_RULES]
_CAT = [(c, re.compile(p)) for c, p in CATEGORY_RULES]


def frameworks_for(coordinate: str) -> list[str]:
    key = coordinate.lower()
    return [n for n, rx in _FW if rx.search(key)]


def categories_for(coordinate: str) -> list[str]:
    key = coordinate.lower()
    return [c for c, rx in _CAT if rx.search(key)]
