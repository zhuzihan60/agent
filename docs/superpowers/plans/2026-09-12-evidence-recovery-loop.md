# Evidence and recovery implementation plan

Spec: ../specs/2026-09-12-evidence-recovery-loop.md

1. Typed target reads: service state, bounded journal and authorized file evidence; transport and helper contract tests. Owner: diagnostic read implementer.
2. Model schema instructions, evidence trust boundary, truthful capability probe and model metadata; provider contract tests. Owner: model implementer.
3. Repair deployment blockers affecting this loop (stable target venv, forced SSH login and plugin credential access); targeted installation tests. Owner: deployment implementer.
4. Add strict administrator evidence/recovery configuration, bounded collector and HTTP checks, supplementary diagnosis loop and pre-write gates, retained final results. Owner: controller.
5. Integrate actual model plugin in closed-loop tests, update example config and deployment instructions, run regression tests and review branch. Owner: controller with independent review.

Global constraints: fail closed on uncertain decisions and recovery; no model-defined shell commands or URLs; no changes to existing authorization and signed operation semantics; no live credentials; preserve read-only operation. Files owned by different tasks must not overlap. Implementers write regression tests before implementation and report test evidence. No shared-branch pushes, merges or releases by implementers.
