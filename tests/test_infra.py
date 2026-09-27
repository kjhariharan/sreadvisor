"""Infra parsers on realistic fixtures: Kubernetes, Istio, Linkerd, Terraform, Helm, CI/CD systems."""

from pathlib import Path

from sreadvisor.infra.analyze import analyze_infra


def w(tmp: Path, name: str, text: str) -> None:
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


K8S = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: orders, namespace: shop}
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate: {maxSurge: 1, maxUnavailable: 0}
  template:
    metadata:
      labels: {app: orders}
      annotations: {sidecar.istio.io/inject: "true"}
    spec:
      terminationGracePeriodSeconds: 45
      containers:
        - name: app
          image: shop/orders:1.4
          resources:
            requests: {cpu: 250m, memory: 512Mi}
            limits: {cpu: "1", memory: 1Gi}
          livenessProbe: {httpGet: {path: /health/live, port: 8080}, periodSeconds: 10, failureThreshold: 3}
          readinessProbe: {httpGet: {path: /health/ready, port: 8080}}
          env:
            - name: DB_PASSWORD
              valueFrom: {secretKeyRef: {name: orders-db, key: password}}
            - name: API_TOKEN
              value: "abc123def456"
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata: {name: orders}
spec:
  scaleTargetRef: {kind: Deployment, name: orders}
  minReplicas: 3
  maxReplicas: 12
  metrics:
    - type: Resource
      resource: {name: cpu, target: {type: Utilization, averageUtilization: 70}}
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata: {name: orders}
spec:
  minAvailable: 2
  selector: {matchLabels: {app: orders}}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: orders}
spec:
  tls: [{hosts: [orders.example.com]}]
  rules: [{host: orders.example.com}]
"""

ISTIO = """
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata: {name: payments}
spec:
  hosts: [payments.shop.svc.cluster.local]
  http:
    - retries: {attempts: 3, perTryTimeout: 2s, retryOn: 5xx}
      timeout: 5s
      route: [{destination: {host: payments}}]
---
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata: {name: payments}
spec:
  host: payments.shop.svc.cluster.local
  trafficPolicy:
    outlierDetection: {consecutive5xxErrors: 5, interval: 10s, baseEjectionTime: 30s}
    connectionPool: {tcp: {maxConnections: 100}}
---
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata: {name: default, namespace: shop}
spec:
  mtls: {mode: STRICT}
"""


def test_kubernetes_facts(tmp_path):
    w(tmp_path, "k8s/orders.yaml", K8S)
    ia = analyze_infra([tmp_path])
    wl = ia.workloads[0]
    assert (wl.name, wl.replicas, wl.strategy, wl.max_surge, wl.max_unavailable) == ("orders", "3", "RollingUpdate", "1", "0")
    assert wl.termination_grace_period_seconds == 45 and wl.mesh_injection.startswith("istio")
    c = wl.containers[0]
    assert c.limits == {"cpu": "1", "memory": "1Gi"} and c.liveness.target == "/health/live:8080" and c.readiness.type == "http"
    assert c.env_from_secrets == ["DB_PASSWORD <- secret/orders-db:password"]
    hpa = ia.autoscalers[0]
    assert (hpa.min_replicas, hpa.max_replicas, hpa.target) == ("3", "12", "orders") and "cpu" in hpa.metrics[0]
    assert ia.disruption_budgets[0].min_available == "2"
    assert any(f.domain == "in_transit" and f.status == "enabled" for f in ia.encryption_audit.facts)
    assert any(h.key and "API_TOKEN" in h.key for h in ia.secrets.hardcoded)  # literal credential in manifest
    assert all("abc123def456" not in h.model_dump_json() for h in ia.secrets.hardcoded)  # never echoed
    assert {c.category for c in ia.capacity} >= {"replicas", "resources", "autoscaling"}
    assert wl.evidence.file == "k8s/orders.yaml" and wl.evidence.line == 2


def test_istio_mesh(tmp_path):
    w(tmp_path, "mesh.yaml", ISTIO)
    ia = analyze_infra([tmp_path])
    m = ia.mesh
    assert m.present and m.mesh == "istio"
    kinds = {p.kind for p in m.traffic_policies}
    assert {"retry", "timeout", "circuit_breaker", "connection_pool"} <= kinds
    retry = next(p for p in m.traffic_policies if p.kind == "retry")
    assert retry.settings["attempts"] == 3 and retry.host == "payments.shop.svc.cluster.local"
    assert m.mtls[0].mode == "STRICT" and "shop" in m.mtls[0].scope


def test_linkerd_mesh(tmp_path):
    w(tmp_path, "sp.yaml", """
apiVersion: linkerd.io/v1alpha2
kind: ServiceProfile
metadata: {name: payments.shop.svc.cluster.local}
spec:
  routes:
    - {name: POST /pay, isRetryable: true, timeout: 300ms}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: web}
spec:
  template:
    metadata: {annotations: {linkerd.io/inject: enabled}}
    spec: {containers: [{name: web, image: web:1}]}
""")
    m = analyze_infra([tmp_path]).mesh
    assert m.present and m.mesh == "linkerd"
    assert {"retry", "timeout"} <= {p.kind for p in m.traffic_policies}
    assert any("automatic mTLS" in x.mode for x in m.mtls)


def test_no_mesh_reported_as_absent(tmp_path):
    w(tmp_path, "k8s/a.yaml", K8S.split("---")[0].replace('annotations: {sidecar.istio.io/inject: "true"}', "annotations: {}"))
    ia = analyze_infra([tmp_path])
    assert not ia.mesh.present
    assert next(s for s in ia.status if s.step == "service_mesh").status == "no_findings"


def test_terraform(tmp_path):
    w(tmp_path, "main.tf", '''
resource "aws_db_instance" "orders" {
  engine                  = "postgres"
  instance_class          = "db.r6g.large"
  multi_az                = true
  storage_encrypted       = false
  backup_retention_period = 7
  password                = "hunter2hunter2"
}
resource "aws_appautoscaling_target" "svc" {
  min_capacity = 2
  max_capacity = 10
}
resource "aws_secretsmanager_secret" "db" { name = "db" }
''')
    ia = analyze_infra([tmp_path])
    db = next(r for r in ia.terraform_resources if r.type == "aws_db_instance")
    assert db.attributes["multi_az"] is True and db.attributes["backup_retention_period"] == 7 and db.evidence.line == 2
    assert "password" not in db.attributes
    assert any(f.setting == "storage_encrypted" and f.status == "disabled" for f in ia.encryption_audit.facts)
    assert any(f.domain == "retention" for f in ia.encryption_audit.facts)
    asg = ia.autoscalers[0]
    assert (asg.min_replicas, asg.max_replicas) == ("2", "10")
    assert any(s.mechanism == "secrets_manager" for s in ia.secrets.sourced_from)
    assert any("aws_db_instance.orders.password" in (h.key or "") for h in ia.secrets.hardcoded)


def test_helm_values_resolved_without_helm_binary(tmp_path):
    w(tmp_path, "chart/Chart.yaml", "name: orders\nversion: 0.3.0\n")
    w(tmp_path, "chart/values.yaml", "replicaCount: 4\nresources:\n  limits:\n    cpu: 500m\nautoscaling:\n  enabled: true\n  maxReplicas: 9\n")
    w(tmp_path, "chart/templates/deploy.yaml", """apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}
spec:
  replicas: {{ .Values.replicaCount }}
  template:
    spec:
      containers:
        - name: app
          image: repo/app:{{ .Chart.AppVersion }}
          resources:
            {{- toYaml .Values.resources | nindent 12 }}
""")
    ia = analyze_infra([tmp_path])
    chart = ia.helm_charts[0]
    assert chart.name == "orders" and chart.values_of_interest["autoscaling.maxReplicas"] == 9
    wl = ia.workloads[0]
    assert wl.replicas == "4" and wl.templated and wl.containers[0].limits == {"cpu": "500m"}


def test_harness_canary_with_automatic_rollback_and_migration(tmp_path):
    w(tmp_path, ".harness/pipeline.yaml", """
pipeline:
  name: orders-deploy
  stages:
    - stage:
        name: migrate
        type: Custom
        spec:
          execution:
            steps:
              - step: {name: Flyway migrate, type: ShellScript, spec: {script: flyway migrate}}
    - stage:
        name: deploy
        type: Deployment
        spec:
          execution:
            steps:
              - step: {name: Canary deploy, type: K8sCanaryDeploy}
            rollbackSteps:
              - step: {name: Rollback, type: K8sCanaryDelete}
        failureStrategies:
          - onFailure: {errors: [AllErrors], action: {type: StageRollback}}
""")
    p = analyze_infra([tmp_path]).pipelines[0]
    assert p.system == "harness" and p.deployment_strategy == "canary" and p.deploys
    assert p.rollback.mode == "automated"
    assert p.db_migration.present and p.db_migration.separate_step is True and p.db_migration.tool.lower() == "flyway"


def test_gitlab_blue_green_manual_rollback(tmp_path):
    w(tmp_path, ".gitlab-ci.yml", """
stages: [deploy]
deploy_green:
  stage: deploy
  script: ["./deploy.sh --blue-green", "kubectl apply -f k8s/"]
rollback_prod:
  stage: deploy
  when: manual
  script: ["kubectl rollout undo deployment/orders"]
""")
    p = analyze_infra([tmp_path]).pipelines[0]
    assert p.system == "gitlab_ci" and p.deployment_strategy == "blue_green" and p.rollback.mode == "manual"


def test_github_helm_atomic_and_inline_migration(tmp_path):
    w(tmp_path, ".github/workflows/cd.yml", """
name: cd
on: {push: {branches: [main]}}
jobs:
  ship:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: flyway migrate && helm upgrade --install orders ./chart --atomic
""")
    p = analyze_infra([tmp_path]).pipelines[0]
    assert p.rollback.mode == "automated"
    assert p.db_migration.present and p.db_migration.separate_step is False  # coupled with the deploy command


def test_jenkins_rollback_on_failure(tmp_path):
    w(tmp_path, "Jenkinsfile", """
pipeline { agent any
  stages {
    stage('Deploy') { steps { sh 'kubectl apply -f k8s/' } }
  }
  post { failure { sh 'kubectl rollout undo deployment/orders' } }
}""")
    p = analyze_infra([tmp_path]).pipelines[0]
    assert p.system == "jenkins" and p.deploys and p.rollback.mode == "automated"


def test_ucd_process_definition(tmp_path):
    w(tmp_path, "process.json", '{"name": "Deploy Rollback", "rootActivity": {"children": [{"name": "Install Component", "type": "plugin", "pluginName": "Deploy"}]}}')
    p = analyze_infra([tmp_path]).pipelines[0]
    assert p.system == "ucd" and p.rollback.mode == "manual"


def test_compose_and_dockerfile(tmp_path):
    w(tmp_path, "docker-compose.yml", "services:\n  db:\n    image: postgres:16\n    restart: always\n    environment:\n      - POSTGRES_PASSWORD=s3cretvalue\n    healthcheck: {test: [CMD, pg_isready]}\n")
    w(tmp_path, "Dockerfile", "FROM eclipse-temurin:21\nEXPOSE 8080\nUSER app\nHEALTHCHECK CMD curl -f localhost:8080/health\n")
    ia = analyze_infra([tmp_path])
    assert ia.compose_services[0].healthcheck and ia.compose_services[0].restart == "always"
    d = ia.dockerfiles[0]
    assert (d.user, d.has_healthcheck, d.exposed_ports) == ("app", True, ["8080"])
    assert ia.secrets.hardcoded and "s3cretvalue" not in ia.secrets.hardcoded[0].model_dump_json()


def test_unparseable_file_is_reported(tmp_path):
    w(tmp_path, "bad.yaml", "a: [unclosed\n")
    ia = analyze_infra([tmp_path])
    assert ia.parse_errors and "bad.yaml" in ia.parse_errors[0]


def test_no_iac_paths_marks_steps_skipped():
    ia = analyze_infra([])
    assert all(s.status == "skipped" for s in ia.status)
