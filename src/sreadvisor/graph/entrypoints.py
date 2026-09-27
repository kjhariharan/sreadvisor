"""Deterministic entry-point detection: annotation / decorator / attribute catalogue per stack.

Graphify tells us *where* every method is; this catalogue tells us which methods are
externally triggered (REST, messaging, scheduled, ...). The LLM only reasons over what
this retrieves, so cost scales with the number of entry points, not lines of code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Order matters: first matching rule wins for a given annotation line.


@dataclass(frozen=True)
class Rule:
    kind: str
    regex: re.Pattern[str]
    suffixes: tuple[str, ...]
    http_group: int | None = None  # regex group holding the HTTP verb, if any
    fixed_method: str | None = None


def _r(kind: str, pattern: str, suffixes: tuple[str, ...], http_group: int | None = None, fixed: str | None = None) -> Rule:
    return Rule(kind, re.compile(pattern), suffixes, http_group, fixed)


JVM = (".java", ".kt", ".groovy", ".scala")
DOTNET = (".cs",)
PY = (".py",)

RULES: list[Rule] = [
    _r("rest", r"^@(Get|Post|Put|Delete|Patch)Mapping\b", JVM, http_group=1),
    _r("rest", r"^@RequestMapping\b", JVM),
    _r("rest", r"^@(GET|POST|PUT|DELETE|PATCH|HEAD)\b", JVM, http_group=1),
    _r("graphql", r"^@(Query|Mutation|Subscription|Schema|Batch)Mapping\b", JVM),
    _r("messaging", r"^@(KafkaListener|RabbitListener|JmsListener|SqsListener|PulsarListener|StreamListener|Incoming|"
                    r"SendToUser|MessageMapping|KafkaHandler|ServiceBusListener)\b", JVM),
    _r("scheduled", r"^@(Scheduled|Schedules)\b", JVM),
    _r("event", r"^@(EventListener|TransactionalEventListener|Observes)\b", JVM),
    _r("rest", r"^\[Http(Get|Post|Put|Delete|Patch)\b", DOTNET, http_group=1),
    _r("rest", r"^\[HttpTrigger\b", DOTNET),
    _r("messaging", r"^\[(ServiceBusTrigger|QueueTrigger|EventHubTrigger|KafkaTrigger|EventGridTrigger)\b", DOTNET),
    _r("scheduled", r"^\[TimerTrigger\b", DOTNET),
    _r("rest", r"^@\w+\.(get|post|put|delete|patch)\(", PY, http_group=1),
    _r("rest", r"^@\w+\.(route|api_route|websocket)\(", PY),
    _r("scheduled", r"^@\w+\.(periodic_task|scheduled_job|cron)\b", PY),
    _r("messaging", r"^@(?:\w+\.)?(task|shared_task|consumer|subscriber)\b", PY),
]

CLASS_ROUTE_RULES = [
    re.compile(r"^@RequestMapping\b"),
    re.compile(r"^@Path\b"),
    re.compile(r"^\[Route\b"),
    re.compile(r"^@\w+\.prefix\b"),
]
METHOD_ROUTE_EXTRA = re.compile(r"^(@Path|\[Route)\b")  # JAX-RS @Path / ASP.NET [Route] on the method itself
_STRING = re.compile(r'"([^"]*)"|\'([^\']*)\'')
_REQ_METHOD = re.compile(r"RequestMethod\.(GET|POST|PUT|DELETE|PATCH)|method\s*=\s*\{?\s*(?:RequestMethod\.)?(GET|POST|PUT|DELETE|PATCH)")

# Express / Fastify / Koa style route registration (call expressions, not annotations).
JS_ROUTE = re.compile(r"\b(?:app|router|server|fastify|api)\.(get|post|put|delete|patch)\(\s*[`'\"]([^`'\"]+)")

# Superclass / interface names that make every public method an entry point.
GRPC_BASES = re.compile(r"(ImplBase|Servicer)$")
HOSTED_BASES = re.compile(r"^(BackgroundService|IHostedService)$")


def first_string(text: str) -> str | None:
    m = _STRING.search(text)
    return (m.group(1) if m.group(1) is not None else m.group(2)) if m else None


def request_method(text: str) -> str | None:
    m = _REQ_METHOD.search(text)
    return (m.group(1) or m.group(2)) if m else None


def join_route(prefix: str | None, route: str | None) -> str | None:
    if not prefix and not route:
        return None
    joined = "/" + "/".join(p.strip("/") for p in (prefix or "", route or "") if p and p.strip("/"))
    return joined if joined != "/" or prefix or route else "/"
