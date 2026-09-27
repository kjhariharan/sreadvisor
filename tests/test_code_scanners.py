from pathlib import Path

from sreadvisor.code.capacity import scan_capacity
from sreadvisor.code.configfiles import read_config_entries
from sreadvisor.code.encryption import scan_encryption_audit
from sreadvisor.code.fingerprint import fingerprint_repo
from sreadvisor.code.secrets import scan_secrets
from sreadvisor.code.telemetry import scan_telemetry
from sreadvisor.graph.code_graph import CodeGraph


def w(tmp: Path, name: str, text: str) -> None:
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def scan(tmp):
    fp = fingerprint_repo(tmp)
    return fp, read_config_entries(tmp)


def test_secrets_hardcoded_placeholder_default_and_sources(tmp_path):
    w(tmp_path, "src/main/resources/application.properties", """
spring.datasource.url=jdbc:postgresql://db/app?user=app&password=plainpw123
spring.datasource.password=${DB_PASS:devdefault}
api.client-secret=literal-secret-value
mail.password=${MAIL_PASSWORD}
spring.datasource.hikari.maximum-pool-size=25
spring.cloud.vault.uri=https://vault:8200
""")
    w(tmp_path, "src/main/java/App.java", 'class App { String k = System.getenv("STRIPE_API_KEY"); String bad = "AKIAABCDEFGHIJKLMNOP"; }\n')
    fp, entries = scan(tmp_path)
    res = scan_secrets(tmp_path, entries, fp)
    kinds = {(h.kind, h.key) for h in res.hardcoded}
    assert ("credentials_in_connection_string", "spring.datasource.url") in kinds
    assert ("default_value_in_placeholder", "spring.datasource.password") in kinds
    assert ("hardcoded_credential", "api.client-secret") in kinds
    assert not any(k[1] == "mail.password" for k in kinds)
    assert any(h.key == "AWS access key id" for h in res.hardcoded)
    blob = res.model_dump_json()
    assert "plainpw123" not in blob and "literal-secret-value" not in blob and "devdefault" not in blob
    mechs = {(s.mechanism, s.name) for s in res.sourced_from}
    assert ("environment_variable", "DB_PASS") in mechs and ("environment_variable", "MAIL_PASSWORD") in mechs
    assert ("environment_variable", "STRIPE_API_KEY") in mechs
    assert any(m == "vault" for m, _ in mechs)


def test_capacity_config_and_code(tmp_path):
    w(tmp_path, "src/main/resources/application.yml", """
spring:
  datasource:
    hikari:
      maximum-pool-size: 30
  task:
    execution:
      pool: {core-size: 8, max-size: 16}
server:
  tomcat:
    threads: {max: 400}
resilience4j:
  ratelimiter:
    instances:
      api: {limitForPeriod: 50, limitRefreshPeriod: 1s}
""")
    w(tmp_path, "src/main/java/Pool.java", "class Pool { Object e = Executors.newFixedThreadPool(16); }\n")
    fp, entries = scan(tmp_path)
    cap = scan_capacity(tmp_path, entries, fp)
    keys = {c.key: c for c in cap}
    assert keys["spring.datasource.hikari.maximum-pool-size"].value == "30" and keys["spring.datasource.hikari.maximum-pool-size"].evidence.line == 5
    assert keys["server.tomcat.threads.max"].category == "server_limits"
    assert any(c.category == "rate_limiter" for c in cap)
    assert any(c.category == "thread_pool" and c.evidence.file.endswith("Pool.java") for c in cap)
    assert all(c.origin == "explicit" for c in cap)  # no framework detected -> no defaults invented


def test_framework_default_only_when_not_explicit(tmp_path):
    w(tmp_path, "pom.xml", """<project><parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>3.3.0</version></parent>
<dependencies><dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-data-jpa</artifactId></dependency></dependencies></project>""")
    fp, entries = scan(tmp_path)
    assert any(c.origin == "framework_default" and c.value == "10" for c in scan_capacity(tmp_path, entries, fp))
    w(tmp_path, "src/main/resources/application.properties", "spring.datasource.hikari.maximum-pool-size=5\n")
    fp, entries = scan(tmp_path)
    cap = scan_capacity(tmp_path, entries, fp)
    assert not any(c.origin == "framework_default" and c.category == "db_pool" for c in cap)


def test_encryption_audit_retention(tmp_path):
    w(tmp_path, "src/main/resources/application.properties", """
server.ssl.enabled=true
server.ssl.key-store-password=topsecret
spring.datasource.url=jdbc:mysql://db/app?useSSL=false
spring.data.redis.ssl.enabled=false
logging.logback.rollingpolicy.max-history=30
partner.url=http://partner.example.com/api
callback.url=http://localhost:8080/cb
""")
    w(tmp_path, "src/main/java/Sec.java", "class Sec { void x() { new NoopHostnameVerifier(); logger.info(\"AUDIT login\"); } @Audited class E {} }\n")
    fp, entries = scan(tmp_path)
    facts = scan_encryption_audit(tmp_path, entries, fp).facts
    by = {(f.setting, f.status) for f in facts}
    assert ("server.ssl.enabled", "enabled") in by
    assert ("spring.datasource.url", "disabled") in by
    assert ("spring.data.redis.ssl.enabled", "disabled") in by
    assert any(f.domain == "retention" and f.setting.endswith("max-history") for f in facts)
    plain = [f for f in facts if f.status == "plaintext"]
    assert [f.value for f in plain] == ["http://partner.example.com/api"]  # localhost is not reported
    assert any(f.domain == "audit" and f.layer == "code" for f in facts)
    assert any(f.setting == "validation bypass in code" for f in facts)
    assert all("topsecret" not in f.model_dump_json() for f in facts)


def test_telemetry_libraries_and_custom_metrics(tmp_path):
    w(tmp_path, "pom.xml", """<project><dependencies>
<dependency><groupId>io.micrometer</groupId><artifactId>micrometer-registry-prometheus</artifactId></dependency>
<dependency><groupId>org.apache.kafka</groupId><artifactId>kafka-clients</artifactId><version>3.7.0</version></dependency>
</dependencies></project>""")
    w(tmp_path, "src/main/resources/application.properties", "management.metrics.tags.app=orders\nmanagement.endpoints.web.exposure.include=prometheus\n")
    w(tmp_path, "src/main/java/M.java", 'class M { void f(MeterRegistry registry) { Counter.builder("orders.created").register(registry); } }\n')
    fp, entries = scan(tmp_path)
    t = scan_telemetry(tmp_path, entries, fp)
    kinds = {l.kind: l for l in t.libraries}
    assert {"micrometer", "kafka_client"} <= set(kinds)
    assert len(kinds["micrometer"].configuration) == 2
    assert kinds["micrometer"].custom_metrics[0]["name"] == "orders.created"
    assert "records-lag-max" in kinds["kafka_client"].documented_metrics
    assert "OneAgent" in t.note


# ----------------------------------------------------------------- entry points (other stacks)


def build(tmp: Path) -> CodeGraph:
    g = CodeGraph(tmp, tmp / ".state")
    g.build()
    return g


def test_entry_points_jaxrs_quarkus(tmp_path):
    w(tmp_path, "src/main/java/OrderResource.java", """
package shop;
@Path("/orders")
public class OrderResource {
    @GET
    @Path("/{id}")
    public String get(String id) { return id; }

    @POST
    public String create(String body) { return body; }

    @Incoming("orders-in")
    public void consume(String m) { }

    @Scheduled(every = "10s")
    void tick() { }
}
""")
    eps = {e.symbol: e for e in build(tmp_path).entry_points()}
    assert (eps["OrderResource.get()"].http_method, eps["OrderResource.get()"].route) == ("GET", "/orders/{id}")
    assert (eps["OrderResource.create()"].http_method, eps["OrderResource.create()"].route) == ("POST", "/orders")
    assert eps["OrderResource.consume()"].kind == "messaging"
    assert eps["OrderResource.tick()"].kind == "scheduled"


def test_entry_points_python_fastapi(tmp_path):
    w(tmp_path, "app/main.py", '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/orders")
async def create_order(o):
    return save(o)

def save(o):
    return o
''')
    g = build(tmp_path)
    eps = {e.symbol: e for e in g.entry_points()}
    assert eps["health()"].route == "/health" and eps["health()"].http_method == "GET"
    assert eps["create_order()"].http_method == "POST"
    chain = g.call_chain(eps["create_order()"].id)
    assert [s["symbol"] for s in chain] == ["create_order()", "save()"]


def test_entry_points_dotnet_and_tests_excluded(tmp_path):
    w(tmp_path, "src/OrdersController.cs", """
[ApiController]
[Route("api/orders")]
public class OrdersController {
    [HttpGet("{id}")]
    public string Get(int id) { return ""; }
}""")
    w(tmp_path, "src/test/java/FooTests.java", "class FooTests { @GetMapping(\"/x\") void t() {} }\n")
    eps = build(tmp_path).entry_points()
    assert [(e.http_method, e.route) for e in eps] == [("GET", "/api/orders/{id}")]


def test_graph_cache_reuses_unchanged_files(tmp_path):
    w(tmp_path, "a.py", "def a():\n    return 1\n")
    w(tmp_path, "b.py", "def b():\n    return 2\n")
    g1 = CodeGraph(tmp_path, tmp_path / ".state")
    s1 = g1.build()
    s2 = CodeGraph(tmp_path, tmp_path / ".state").build()
    assert s1["cache_entries_added"] == 2 and s2["cache_entries_added"] == 0
    w(tmp_path, "b.py", "def b():\n    return 3\n")
    s3 = CodeGraph(tmp_path, tmp_path / ".state").build()
    assert s3["cache_entries_added"] == 1  # only the changed file is re-parsed


def test_source_reader_redacts_secrets_before_they_reach_an_llm_prompt(tmp_path):
    """read_code/get_call_chain (SourceReader.read) and search_code must never surface a raw credential: both feed
    straight into an LLM prompt in code/llm_steps.py."""
    w(tmp_path, "Config.java", 'class Config {\n  String pwd = "hunter2pass";\n'
                               '  // jdbc:postgresql://db/app?user=app&password=realsecret123\n}\n')
    g = CodeGraph(tmp_path, tmp_path / ".state")
    g.build()
    text = g.reader.read("Config.java", 1, 4)
    assert "hunter2pass" not in text and "realsecret123" not in text
    assert "<redacted-secret>" in text
    assert "pwd" in text and "class Config" in text  # surrounding code is still useful context

    hits = g.search_code("pwd")
    assert hits and "hunter2pass" not in hits[0]["text"] and "<redacted-secret>" in hits[0]["text"]
