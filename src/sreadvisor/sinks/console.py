from __future__ import annotations

from pathlib import Path

from sreadvisor.schema.dataset import ServiceDataset
from sreadvisor.sinks.base import OutputSink


class ConsoleSummarySink(OutputSink):
    name = "console_summary"

    def emit(self, dataset: ServiceDataset, out_dir: Path) -> None:
        print(f"\nService: {dataset.service_name}   (schema {dataset.schema_version}, model {dataset.model_backend})")
        if dataset.business_context:
            b = dataset.business_context
            print(f"Business context: {b.capability} [{b.category}, {b.confidence} confidence]")
        for r in dataset.repositories:
            fw = ", ".join(f"{f.name} {f.version or ''}".strip() for f in r.fingerprint.frameworks) or "-"
            print(f"\nRepository {r.repo}: {', '.join(r.fingerprint.languages) or '?'} | {fw}")
            print(
                f"  deps={len(r.fingerprint.dependencies)} entry_points={len(r.entry_points)} "
                f"flows={len(r.transaction_flows)} reliability_patterns={len(r.reliability_patterns)} "
                f"dep_classifications={len(r.dependency_classification)}"
            )
            print(
                f"  app_capacity={len(r.application_capacity)} hardcoded_secrets={len(r.secrets.hardcoded)} "
                f"secret_sources={len(r.secrets.sourced_from)} enc/audit_facts={len(r.encryption_audit.facts)} "
                f"telemetry_libs={len(r.telemetry.libraries)}"
            )
        i = dataset.infrastructure
        print(
            f"\nInfrastructure: workloads={len(i.workloads)} autoscalers={len(i.autoscalers)} "
            f"pdbs={len(i.disruption_budgets)} compose={len(i.compose_services)} helm={len(i.helm_charts)} "
            f"terraform={len(i.terraform_resources)} pipelines={len(i.pipelines)} mesh={'yes' if i.mesh.present else 'no'}"
        )
        c = dataset.completeness
        print(f"\nCompleteness: {c.get('summary', '?')}")
        for w in c.get("warnings", []):
            print(f"  ! {w}")
