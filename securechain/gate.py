"""CI/CD gate logic: applies .riskignore.json exceptions to a JSON report and
decides pass/warn/fail.

Exit code is non-zero only if a dependency strictly above --max-severity is
present and not covered by an exact package+version exception entry. The
default threshold is "safe": Low, Medium, High, and Critical all block a build
unless explicitly accepted. A risk is a risk regardless of tier, so nothing
short of a genuinely clean (Safe) dependency passes without either a real fix
or a deliberate, recorded human decision to accept it. Only Safe dependencies
never block; they are only logged.
"""

from __future__ import annotations

from dataclasses import dataclass

from securechain.riskignore import is_accepted, load_riskignore
from securechain.severity import tier_index


@dataclass
class GateResult:
    exit_code: int
    failures: list[str]
    warnings: list[str]


def evaluate_gate(report: dict, max_severity: str = "safe", ignore_file: str = ".riskignore.json") -> GateResult:
    threshold = tier_index(max_severity.capitalize())
    ignore_store = load_riskignore(ignore_file)

    failures: list[str] = []
    warnings: list[str] = []

    for dependency in report.get("dependencies", []):
        dep_tier = tier_index(dependency["severity"])
        if dep_tier <= threshold:
            continue

        exception = is_accepted(ignore_store, dependency["package"], dependency["version"])
        if exception:
            warnings.append(
                f"WARNING: {dependency['package']}@{dependency['version']} is {dependency['severity']} "
                f"but was accepted via .riskignore.json on {exception.date} by {exception.accepted_by} "
                f"(reason: {exception.reason})."
            )
        else:
            failures.append(
                f"FAIL: {dependency['package']}@{dependency['version']} is {dependency['severity']} "
                f"and is not listed in {ignore_file}."
            )

    exit_code = 1 if failures else 0
    return GateResult(exit_code=exit_code, failures=failures, warnings=warnings)
