from __future__ import annotations

import hashlib
import json
import os
import pickle
import subprocess
import sys
import tempfile
import textwrap
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import cast
from unittest import mock

from fork_ops import dependency_security as dependency_security_module
from fork_ops.dependency_security import (
    DEPENDENCY_SCOPES,
    SUPPORTED_PLATFORMS,
    SUPPORTED_PYTHON_VERSIONS,
    evaluate_dependency_security,
)
from fork_ops.security_exceptions import (
    SecurityExceptionInventory,
    compute_security_exception_digest,
    compute_security_exception_record_digests,
    validate_security_exception_inventory,
)


class DependencySecurityTests(unittest.TestCase):
    def test_raw_or_unsupported_inventory_input_fails_closed_at_typed_seam(
        self,
    ) -> None:
        for case, unsupported in {
            "raw-ledger": _raw_ledger(),
            "object": object(),
        }.items():
            with self.subTest(case=case):
                dynamic_call = cast(
                    Callable[..., dict[str, object]],
                    evaluate_dependency_security,
                )
                result = dynamic_call(
                    _evidence("osv", []),
                    _evidence("dependabot", []),
                    unsupported,
                    evaluation_context=_trusted_evaluation(),
                )

                self.assertEqual(result["status"], "failed")
                self.assertEqual(
                    result["diagnostics"],
                    [
                        {
                            "code": "exceptions.invalid_inventory",
                            "source": "security-exception-inventory",
                            "message": (
                                "Security Exception 1.0 inventory must be a structural typed "
                                "projection."
                            ),
                        }
                    ],
                )

    def test_legacy_verified_approvals_keyword_is_not_a_public_seam(self) -> None:
        legacy_call = cast(
            Callable[..., dict[str, object]],
            evaluate_dependency_security,
        )

        with self.assertRaisesRegex(TypeError, "verified_approvals"):
            legacy_call(
                _evidence("osv", []),
                _evidence("dependabot", []),
                _raw_ledger(),
                evaluation_context=_trusted_evaluation(),
                verified_approvals=[],
            )

    def test_serialized_clean_evidence_cannot_produce_canonical_pass(self) -> None:
        evidence: dict[str, object] = {
            "artifact_kind": "normalized_dependency_vulnerability_evidence",
            "schema_version": "1.0",
            "status": "available",
            "platforms": list(SUPPORTED_PLATFORMS),
            "dependency_scopes": list(DEPENDENCY_SCOPES),
            "python_versions": list(SUPPORTED_PYTHON_VERSIONS),
            "advisories": list[dict[str, object]](),
        }
        inventory = _inventory()

        result = evaluate_dependency_security(
            {**evidence, "source": "osv"},
            {**evidence, "source": "dependabot"},
            inventory,
            evaluated_at="2026-08-11T23:30:00Z",
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(
            result["diagnostics"],
            [
                {
                    "code": "evidence.unverified",
                    "source": "osv",
                    "message": "osv evidence is serialized or otherwise unverified.",
                },
                {
                    "code": "evidence.unverified",
                    "source": "dependabot",
                    "message": (
                        "dependabot evidence is serialized or otherwise unverified."
                    ),
                },
                {
                    "code": "evaluation.untrusted_time",
                    "source": "evaluation",
                    "message": (
                        "A caller-provided evaluated_at value is not a trusted evaluation "
                        "interval."
                    ),
                },
            ],
        )

    def test_exact_current_complete_observations_produce_canonical_pass(self) -> None:
        result = evaluate_dependency_security(
            _verified_evidence("osv", []),
            _verified_evidence("dependabot", []),
            _inventory(),
            evaluation_context=_trusted_evaluation(),
        )

        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["evidence_trust"], "verified_observations")
        self.assertEqual(result["advisory_groups"], [])
        self.assertEqual(result["diagnostics"], [])
        self.assertEqual(
            result["assurance_boundary"],
            {
                "security_authority": False,
                "finding_waiver_authority": False,
                "gate_or_release_authority": False,
            },
        )

    def test_replayed_observation_fails_closed_even_while_not_expired(self) -> None:
        result = evaluate_dependency_security(
            _verified_evidence(
                "osv",
                [],
                observation_updates={
                    "started_at": "2026-08-11T23:28:00Z",
                    "completed_at": "2026-08-11T23:28:30Z",
                    "valid_until": "2026-08-11T23:40:00Z",
                },
            ),
            _verified_evidence("dependabot", []),
            _inventory(),
            evaluation_context=_trusted_evaluation(),
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(
            result["diagnostics"],
            [
                {
                    "code": "evidence.replayed",
                    "source": "osv",
                    "message": "osv observation predates the trusted evaluation interval.",
                }
            ],
        )

    def test_future_observation_fails_closed(self) -> None:
        result = evaluate_dependency_security(
            _verified_evidence(
                "osv",
                [],
                observation_updates={
                    "started_at": "2026-08-11T23:29:50Z",
                    "completed_at": "2026-08-11T23:31:00Z",
                    "valid_until": "2026-08-11T23:45:00Z",
                },
            ),
            _verified_evidence("dependabot", []),
            _inventory(),
            evaluation_context=_trusted_evaluation(),
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(
            result["diagnostics"],
            [
                {
                    "code": "evidence.future_observation",
                    "source": "osv",
                    "message": "osv observation completes after the trusted evaluation time.",
                }
            ],
        )

    def test_observation_is_stale_at_its_valid_until_boundary(self) -> None:
        result = evaluate_dependency_security(
            _verified_evidence(
                "osv",
                [],
                observation_updates={
                    "started_at": "2026-08-11T23:29:10Z",
                    "completed_at": "2026-08-11T23:29:10Z",
                    "valid_until": "2026-08-11T23:44:10Z",
                },
            ),
            _verified_evidence("dependabot", []),
            _inventory(),
            evaluation_context=_trusted_evaluation(
                context_updates={
                    "interval": {
                        "started_at": "2026-08-11T23:29:10Z",
                        "evaluated_at": "2026-08-11T23:44:10Z",
                    }
                }
            ),
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(
            result["diagnostics"],
            [
                {
                    "code": "evidence.stale",
                    "source": "osv",
                    "message": "osv observation is stale at the trusted evaluation time.",
                }
            ],
        )

    def test_candidate_matrix_or_epoch_mismatch_fails_closed(self) -> None:
        mismatched_candidate = _candidate_identity()
        mismatched_candidate["commit_sha"] = "f" * 40
        cases: dict[str, dependency_security_module.VerifiedDependencyEvidence] = {
            "candidate": _verified_evidence(
                "osv",
                [],
                provenance_updates={"candidate": mismatched_candidate},
            ),
            "epoch": _verified_evidence(
                "osv",
                [],
                observation_updates={"observation_epoch": "f" * 64},
            ),
        }

        for case, evidence in cases.items():
            with self.subTest(case=case):
                result = evaluate_dependency_security(
                    evidence,
                    _verified_evidence("dependabot", []),
                    _inventory(),
                    evaluation_context=_trusted_evaluation(),
                )

                self.assertEqual(result["status"], "failed")
                diagnostics = result["diagnostics"]
                if not isinstance(diagnostics, list) or not diagnostics:
                    self.fail("diagnostics must contain a provenance mismatch")
                diagnostic = diagnostics[0]
                if not isinstance(diagnostic, dict):
                    self.fail("diagnostic must be an object")
                self.assertIn(
                    diagnostic["code"],
                    {"evidence.identity_mismatch", "evidence.epoch_mismatch"},
                )

    def test_partial_zero_observation_fails_closed(self) -> None:
        result = evaluate_dependency_security(
            _verified_evidence(
                "osv",
                [],
                observation_updates={"pagination_complete": False, "page_count": 0},
            ),
            _verified_evidence("dependabot", []),
            _inventory(),
            evaluation_context=_trusted_evaluation(),
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(
            result["diagnostics"],
            [
                {
                    "code": "evidence.incomplete_observation",
                    "source": "osv",
                    "message": (
                        "osv evidence is not a positive complete source observation."
                    ),
                }
            ],
        )

    def test_canonical_payload_digest_mismatch_fails_closed(self) -> None:
        payload = _verified_payload("osv", [])
        payload["payload_sha256"] = "0" * 64
        evidence = dependency_security_module.VerifiedDependencyEvidence._from_adapter(
            payload,
            seal=dependency_security_module._OBSERVATION_SEAL,
        )

        result = evaluate_dependency_security(
            evidence,
            _verified_evidence("dependabot", []),
            _inventory(),
            evaluation_context=_trusted_evaluation(),
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(
            result["diagnostics"],
            [
                {
                    "code": "evidence.payload_digest_mismatch",
                    "source": "osv",
                    "message": (
                        "osv canonical payload digest does not match its content."
                    ),
                }
            ],
        )

    def test_mutation_serialization_and_copy_cannot_preserve_evidence_trust(self) -> None:
        mutable_payload = _verified_payload("osv", [])
        verified = dependency_security_module.VerifiedDependencyEvidence._from_adapter(
            mutable_payload,
            seal=dependency_security_module._OBSERVATION_SEAL,
        )
        mutable_payload["source"] = "dependabot"
        projection = verified.to_dict()

        self.assertEqual(projection["source"], "osv")
        with self.assertRaisesRegex(TypeError, "cannot cross a serialization boundary"):
            pickle.dumps(verified)
        for unverified in (projection, json.loads(json.dumps(projection)), dict(projection)):
            with self.subTest(kind=type(unverified).__name__):
                result = evaluate_dependency_security(
                    unverified,
                    _verified_evidence("dependabot", []),
                    _inventory(),
                    evaluation_context=_trusted_evaluation(),
                )
                self.assertEqual(result["status"], "failed")
                diagnostics = result["diagnostics"]
                if not isinstance(diagnostics, list):
                    self.fail("diagnostics must be a list")
                self.assertTrue(
                    any(
                        isinstance(diagnostic, dict)
                        and diagnostic.get("code") == "evidence.unverified"
                        for diagnostic in diagnostics
                    )
                )

    def test_unsupported_evidence_version_fails_closed(self) -> None:
        inventory = _inventory()

        result = evaluate_dependency_security(
            _verified_evidence("osv", [], root_updates={"schema_version": "3.0"}),
            _verified_evidence("dependabot", []),
            inventory,
            evaluation_context=_trusted_evaluation(),
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(
            result["diagnostics"],
            [
                {
                    "code": "evidence.unsupported_version",
                    "source": "osv",
                    "message": "osv evidence schema_version must be 2.0.",
                }
            ],
        )

    def test_affected_advisory_is_normalized_and_fails_without_inventory_record(
        self,
    ) -> None:
        osv_advisory = _advisory(
            "PYSEC-2026-1",
            aliases=["CVE-2026-0001", "GHSA-aaaa-bbbb-cccc"],
        )
        dependabot_advisory = _advisory(
            "GHSA-aaaa-bbbb-cccc",
            aliases=["PYSEC-2026-1", "CVE-2026-0001"],
        )

        result = evaluate_dependency_security(
            _evidence("osv", [osv_advisory]),
            _evidence("dependabot", [dependabot_advisory]),
            _inventory(),
            evaluation_context=_trusted_evaluation(),
        )

        self.assertEqual(result["status"], "failed")
        full_coverage = [
            {
                "python_version": python_version,
                "dependency_scopes": list(DEPENDENCY_SCOPES),
            }
            for python_version in SUPPORTED_PYTHON_VERSIONS
        ]
        source_claims = [
            {
                "affected": True,
                "affected_range": "<1.3.1",
                "fixed_versions": ["1.3.1"],
                "coverage": full_coverage,
            }
        ]
        self.assertEqual(
            result["advisory_groups"],
            [
                {
                    "canonical_id": "GHSA-aaaa-bbbb-cccc",
                    "aliases": [
                        "CVE-2026-0001",
                        "GHSA-aaaa-bbbb-cccc",
                        "PYSEC-2026-1",
                    ],
                    "package": "starlette",
                    "locked_version": "1.0.0",
                    "affected": True,
                    "affected_range": "<1.3.1",
                    "fixed_versions": ["1.3.1"],
                    "dependency_scopes": list(DEPENDENCY_SCOPES),
                    "python_versions": list(SUPPORTED_PYTHON_VERSIONS),
                    "coverage": full_coverage,
                    "sources": ["dependabot", "osv"],
                    "source_claims": [
                        {
                            "source": "dependabot",
                            "identifiers": [
                                "CVE-2026-0001",
                                "GHSA-aaaa-bbbb-cccc",
                                "PYSEC-2026-1",
                            ],
                            "claims": source_claims,
                        },
                        {
                            "source": "osv",
                            "identifiers": [
                                "CVE-2026-0001",
                                "GHSA-aaaa-bbbb-cccc",
                                "PYSEC-2026-1",
                            ],
                            "claims": source_claims,
                        },
                    ],
                    "disposition": "unexcepted",
                    "inventory_record_ids": [],
                }
            ],
        )
        self.assertEqual(
            result["summary"],
            {
                "advisory_group_count": 1,
                "affected_group_count": 1,
                "excepted_group_count": 0,
                "unexcepted_group_count": 1,
                "disagreement_count": 0,
            },
        )
        self.assertEqual(
            result["diagnostics"],
            [
                {
                    "code": "finding.unexcepted",
                    "source": "reconciliation",
                    "message": (
                        "GHSA-aaaa-bbbb-cccc affects starlette 1.0.0. Security Exception 1.0 "
                        "inventory records do not waive dependency findings."
                    ),
                }
            ],
        )

    def test_approved_or_renewed_inventory_record_never_waives_dependency_finding(
        self,
    ) -> None:
        exception_id = "22222222-2222-4222-8222-222222222222"
        osv_advisory = _advisory(
            "PYSEC-2026-1",
            aliases=["CVE-2026-0001", "GHSA-aaaa-bbbb-cccc"],
        )
        dependabot_advisory = _advisory(
            "GHSA-aaaa-bbbb-cccc",
            aliases=["PYSEC-2026-1", "CVE-2026-0001"],
        )

        for state in ("approved", "renewed"):
            with self.subTest(state=state):
                inventory = _inventory(_dependency_inventory_record(state=state))

                result = evaluate_dependency_security(
                    _evidence("osv", [osv_advisory]),
                    _evidence("dependabot", [dependabot_advisory]),
                    inventory,
                    evaluation_context=_trusted_evaluation(),
                )

                self.assertEqual(result["status"], "failed")
                summary = result["summary"]
                if not isinstance(summary, dict):
                    self.fail("summary must be a table")
                self.assertEqual(summary["excepted_group_count"], 0)
                self.assertEqual(summary["unexcepted_group_count"], 1)
                advisory_groups = result["advisory_groups"]
                if (
                    not isinstance(advisory_groups, list)
                    or len(advisory_groups) != 1
                    or not isinstance(advisory_groups[0], dict)
                ):
                    self.fail("advisory_groups must contain one table")
                self.assertEqual(advisory_groups[0]["disposition"], "unexcepted")
                self.assertEqual(
                    advisory_groups[0]["inventory_record_ids"],
                    [exception_id],
                )
                self.assertNotIn("exception_id", advisory_groups[0])
                self.assertEqual(
                    result["security_exception_inventory"],
                    {
                        "contract_version": "1.0",
                        "finding_effect": "inventory_only",
                        "unmatched_dependency_record_ids": [],
                    },
                )
                diagnostics = result["diagnostics"]
                if not isinstance(diagnostics, list):
                    self.fail("diagnostics must be a list")
                self.assertTrue(
                    any(
                        "Security Exception 1.0 inventory records do not waive dependency "
                        "findings."
                        in diagnostic["message"]
                        for diagnostic in diagnostics
                        if isinstance(diagnostic, dict)
                    )
                )

    def test_inaccessible_source_evidence_fails_closed(self) -> None:
        result = evaluate_dependency_security(
            _verified_evidence("osv", [], root_updates={"status": "unavailable"}),
            _evidence("dependabot", []),
            _inventory(),
            evaluation_context=_trusted_evaluation(),
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(
            result["diagnostics"],
            [
                {
                    "code": "evidence.unavailable",
                    "source": "osv",
                    "message": "osv evidence is unavailable.",
                }
            ],
        )

    def test_material_osv_dependabot_disagreement_fails_closed(self) -> None:
        osv_advisory = _advisory(
            "PYSEC-2026-1",
            aliases=["GHSA-aaaa-bbbb-cccc"],
        )
        dependabot_advisory = {
            **_advisory(
                "GHSA-aaaa-bbbb-cccc",
                aliases=["PYSEC-2026-1"],
            ),
            "affected": False,
        }

        result = evaluate_dependency_security(
            _evidence("osv", [osv_advisory]),
            _evidence("dependabot", [dependabot_advisory]),
            _inventory(),
            evaluation_context=_trusted_evaluation(),
        )

        self.assertEqual(result["status"], "failed")
        summary = result["summary"]
        if not isinstance(summary, dict):
            self.fail("summary must be a table")
        self.assertEqual(summary["disagreement_count"], 1)
        advisory_groups = result["advisory_groups"]
        if (
            not isinstance(advisory_groups, list)
            or not advisory_groups
            or not isinstance(advisory_groups[0], dict)
        ):
            self.fail("advisory_groups must contain a table")
        self.assertEqual(advisory_groups[0]["disposition"], "disagreement")
        self.assertEqual(
            result["diagnostics"],
            [
                {
                    "code": "evidence.material_disagreement",
                    "source": "reconciliation",
                    "message": (
                        "OSV and Dependabot disagree on whether GHSA-aaaa-bbbb-cccc "
                        "affects or fixes starlette 1.0.0. Security Exception 1.0 inventory "
                        "records do not waive dependency findings."
                    ),
                }
            ],
        )

    def test_shared_aliases_do_not_merge_distinct_locked_tuples(self) -> None:
        osv_advisory = _advisory(
            "PYSEC-2026-1",
            aliases=["GHSA-aaaa-bbbb-cccc"],
        )
        cases: dict[str, dict[str, object]] = {
            "locked-version": {"locked_version": "2.0.0"},
            "package": {"package": "other-package"},
        }

        for case, difference in cases.items():
            with self.subTest(case=case):
                dependabot_advisory = {
                    **_advisory(
                        "GHSA-aaaa-bbbb-cccc",
                        aliases=["PYSEC-2026-1"],
                    ),
                    **difference,
                }
                result = evaluate_dependency_security(
                    _evidence("osv", [osv_advisory]),
                    _evidence("dependabot", [dependabot_advisory]),
                    _inventory(),
                    evaluation_context=_trusted_evaluation(),
                )

                advisory_groups = result["advisory_groups"]
                if not isinstance(advisory_groups, list):
                    self.fail("advisory_groups must be a list")
                self.assertEqual(len(advisory_groups), 2)
                tuples = {
                    (group["package"], group["locked_version"])
                    for group in advisory_groups
                    if isinstance(group, dict)
                }
                self.assertEqual(
                    tuples,
                    {
                        ("starlette", "1.0.0"),
                        (
                            "other-package" if case == "package" else "starlette",
                            "2.0.0" if case == "locked-version" else "1.0.0",
                        ),
                    },
                )
                self.assertTrue(
                    all(
                        isinstance(group, dict)
                        and group["disposition"] == "disagreement"
                        for group in advisory_groups
                    )
                )

    def test_matching_sources_agree_on_split_scope_python_coverage(self) -> None:
        def split_advisories(advisory_id: str, alias: str) -> list[dict[str, object]]:
            base = {
                **_advisory(advisory_id, aliases=[alias]),
                "affected": False,
            }
            return [
                {
                    **base,
                    "dependency_scopes": ["runtime"],
                    "python_versions": ["3.11"],
                },
                {
                    **base,
                    "dependency_scopes": ["optional"],
                    "python_versions": ["3.12"],
                },
            ]

        result = evaluate_dependency_security(
            _evidence(
                "osv",
                split_advisories("PYSEC-2026-1", "GHSA-aaaa-bbbb-cccc"),
            ),
            _evidence(
                "dependabot",
                split_advisories("GHSA-aaaa-bbbb-cccc", "PYSEC-2026-1"),
            ),
            _inventory(),
            evaluation_context=_trusted_evaluation(),
        )

        self.assertEqual(result["status"], "passed")
        advisory_groups = result["advisory_groups"]
        if (
            not isinstance(advisory_groups, list)
            or len(advisory_groups) != 1
            or not isinstance(advisory_groups[0], dict)
        ):
            self.fail("advisory_groups must contain one table")
        group = advisory_groups[0]
        self.assertEqual(group["disposition"], "fixed")
        self.assertEqual(group["dependency_scopes"], ["runtime", "optional"])
        self.assertEqual(group["python_versions"], ["3.11", "3.12"])
        expected_claims = [
            {
                "affected": False,
                "affected_range": "<1.3.1",
                "fixed_versions": ["1.3.1"],
                "coverage": [
                    {"python_version": "3.11", "dependency_scopes": ["runtime"]},
                    {"python_version": "3.12", "dependency_scopes": ["optional"]},
                ],
            }
        ]
        self.assertEqual(group["coverage"], expected_claims[0]["coverage"])
        self.assertEqual(
            group["source_claims"],
            [
                {
                    "source": "dependabot",
                    "identifiers": ["GHSA-aaaa-bbbb-cccc", "PYSEC-2026-1"],
                    "claims": expected_claims,
                },
                {
                    "source": "osv",
                    "identifiers": ["GHSA-aaaa-bbbb-cccc", "PYSEC-2026-1"],
                    "claims": expected_claims,
                },
            ],
        )

    def test_all_material_advisory_fields_must_agree(self) -> None:
        osv_advisory = _advisory(
            "PYSEC-2026-1",
            aliases=["GHSA-aaaa-bbbb-cccc"],
        )
        differences: dict[str, dict[str, object]] = {
            "affected-range": {"affected_range": "<1.4.0"},
            "dependency-scopes": {"dependency_scopes": ["runtime"]},
            "python-versions": {"python_versions": ["3.11", "3.12", "3.13"]},
        }

        for case, difference in differences.items():
            with self.subTest(case=case):
                dependabot_advisory = {
                    **_advisory(
                        "GHSA-aaaa-bbbb-cccc",
                        aliases=["PYSEC-2026-1"],
                    ),
                    **difference,
                }
                result = evaluate_dependency_security(
                    _evidence("osv", [osv_advisory]),
                    _evidence("dependabot", [dependabot_advisory]),
                    _inventory(),
                    evaluation_context=_trusted_evaluation(),
                )

                self.assertEqual(result["status"], "failed")
                advisory_groups = result["advisory_groups"]
                if (
                    not isinstance(advisory_groups, list)
                    or not advisory_groups
                    or not isinstance(advisory_groups[0], dict)
                ):
                    self.fail("advisory_groups must contain a table")
                self.assertEqual(advisory_groups[0]["disposition"], "disagreement")
                diagnostics = result["diagnostics"]
                if not isinstance(diagnostics, list) or not diagnostics:
                    self.fail("diagnostics must contain a material disagreement")
                diagnostic = diagnostics[0]
                if not isinstance(diagnostic, dict):
                    self.fail("diagnostic must be a table")
                self.assertEqual(diagnostic["code"], "evidence.material_disagreement")

    def test_disagreement_output_preserves_every_source_claim(self) -> None:
        osv_advisory = {
            **_advisory("PYSEC-2026-1", aliases=["GHSA-aaaa-bbbb-cccc"]),
            "dependency_scopes": ["runtime"],
            "python_versions": ["3.11"],
        }
        dependabot_advisory = {
            **_advisory("GHSA-aaaa-bbbb-cccc", aliases=["PYSEC-2026-1"]),
            "affected_range": "<2.0.0",
            "fixed_versions": ["2.0.0"],
            "dependency_scopes": ["optional"],
            "python_versions": ["3.12"],
        }

        result = evaluate_dependency_security(
            _evidence("osv", [osv_advisory]),
            _evidence("dependabot", [dependabot_advisory]),
            _inventory(),
            evaluation_context=_trusted_evaluation(),
        )

        advisory_groups = result["advisory_groups"]
        if (
            not isinstance(advisory_groups, list)
            or len(advisory_groups) != 1
            or not isinstance(advisory_groups[0], dict)
        ):
            self.fail("advisory_groups must contain one table")
        group = advisory_groups[0]
        self.assertEqual(group["disposition"], "disagreement")
        self.assertEqual(group["fixed_versions"], ["1.3.1", "2.0.0"])
        self.assertEqual(group["dependency_scopes"], ["runtime", "optional"])
        self.assertEqual(group["python_versions"], ["3.11", "3.12"])
        self.assertEqual(
            group["source_claims"],
            [
                {
                    "source": "dependabot",
                    "identifiers": ["GHSA-aaaa-bbbb-cccc", "PYSEC-2026-1"],
                    "claims": [
                        {
                            "affected": True,
                            "affected_range": "<2.0.0",
                            "fixed_versions": ["2.0.0"],
                            "coverage": [
                                {
                                    "python_version": "3.12",
                                    "dependency_scopes": ["optional"],
                                }
                            ],
                        }
                    ],
                },
                {
                    "source": "osv",
                    "identifiers": ["GHSA-aaaa-bbbb-cccc", "PYSEC-2026-1"],
                    "claims": [
                        {
                            "affected": True,
                            "affected_range": "<1.3.1",
                            "fixed_versions": ["1.3.1"],
                            "coverage": [
                                {
                                    "python_version": "3.11",
                                    "dependency_scopes": ["runtime"],
                                }
                            ],
                        }
                    ],
                },
            ],
        )

    def test_other_subject_inventory_records_do_not_break_dependency_evaluation(
        self,
    ) -> None:
        result = evaluate_dependency_security(
            _evidence("osv", []),
            _evidence("dependabot", []),
            _inventory(_other_subject_inventory_record()),
            evaluation_context=_trusted_evaluation(),
        )

        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["advisory_groups"], [])
        self.assertEqual(
            result["security_exception_inventory"],
            {
                "contract_version": "1.0",
                "finding_effect": "inventory_only",
                "unmatched_dependency_record_ids": [],
            },
        )

    def test_inventory_record_matching_requires_exact_dependency_identity(
        self,
    ) -> None:
        exception_id = "22222222-2222-4222-8222-222222222222"
        osv_advisory = _advisory(
            "PYSEC-2026-1",
            aliases=["CVE-2026-0001", "GHSA-aaaa-bbbb-cccc"],
        )
        dependabot_advisory = _advisory(
            "GHSA-aaaa-bbbb-cccc",
            aliases=["PYSEC-2026-1", "CVE-2026-0001"],
        )
        cases = {
            "package": _dependency_inventory_record(package="other-package"),
            "locked-version": _dependency_inventory_record(locked_version="2.0.0"),
            "aliases": _dependency_inventory_record(
                aliases=["GHSA-aaaa-bbbb-cccc", "PYSEC-2026-1"],
            ),
            "dependency-scopes": _dependency_inventory_record(
                dependency_scopes=["runtime"],
            ),
            "python-versions": _dependency_inventory_record(
                python_versions=["3.11", "3.12", "3.13"],
            ),
        }

        for case, record in cases.items():
            with self.subTest(case=case):
                result = evaluate_dependency_security(
                    _evidence("osv", [osv_advisory]),
                    _evidence("dependabot", [dependabot_advisory]),
                    _inventory(record),
                    evaluation_context=_trusted_evaluation(),
                )

                self.assertEqual(result["status"], "failed")
                advisory_groups = result["advisory_groups"]
                if (
                    not isinstance(advisory_groups, list)
                    or len(advisory_groups) != 1
                    or not isinstance(advisory_groups[0], dict)
                ):
                    self.fail("advisory_groups must contain one table")
                self.assertEqual(advisory_groups[0]["disposition"], "unexcepted")
                self.assertEqual(advisory_groups[0]["inventory_record_ids"], [])
                inventory_evidence = result["security_exception_inventory"]
                if not isinstance(inventory_evidence, dict):
                    self.fail("security_exception_inventory must be a table")
                self.assertEqual(
                    inventory_evidence["unmatched_dependency_record_ids"],
                    [exception_id],
                )

        exact_subset_result = evaluate_dependency_security(
            _evidence(
                "osv",
                [{**osv_advisory, "python_versions": ["3.11", "3.12"]}],
            ),
            _evidence(
                "dependabot",
                [{**dependabot_advisory, "python_versions": ["3.11", "3.12"]}],
            ),
            _inventory(
                _dependency_inventory_record(python_versions=["3.11", "3.12"])
            ),
            evaluation_context=_trusted_evaluation(),
        )
        exact_subset_groups = exact_subset_result["advisory_groups"]
        if (
            not isinstance(exact_subset_groups, list)
            or len(exact_subset_groups) != 1
            or not isinstance(exact_subset_groups[0], dict)
        ):
            self.fail("advisory_groups must contain one table")
        self.assertEqual(
            exact_subset_groups[0]["inventory_record_ids"],
            [exception_id],
        )

        platform_result = evaluate_dependency_security(
            _verified_evidence(
                "osv",
                [osv_advisory],
                root_updates={"platforms": ["windows"]},
            ),
            _evidence("dependabot", [dependabot_advisory]),
            _inventory(_dependency_inventory_record()),
            evaluation_context=_trusted_evaluation(),
        )
        self.assertEqual(platform_result["status"], "failed")
        self.assertEqual(platform_result["advisory_groups"], [])
        platform_diagnostics = platform_result["diagnostics"]
        if not isinstance(platform_diagnostics, list):
            self.fail("diagnostics must be a list")
        self.assertIn(
            "evidence.unsupported_platform",
            {
                diagnostic["code"]
                for diagnostic in platform_diagnostics
                if isinstance(diagnostic, dict)
            },
        )
        platform_inventory = platform_result["security_exception_inventory"]
        if not isinstance(platform_inventory, dict):
            self.fail("security_exception_inventory must be a table")
        self.assertEqual(
            platform_inventory["unmatched_dependency_record_ids"],
            [exception_id],
        )

    def test_incomplete_scope_or_python_coverage_fails_closed(self) -> None:
        cases = {
            "platform": (
                _verified_evidence(
                    "osv",
                    [],
                    root_updates={"platforms": ["windows"]},
                ),
                "evidence.unsupported_platform",
            ),
            "scope": (
                _verified_evidence(
                    "osv",
                    [],
                    root_updates={"dependency_scopes": ["runtime"]},
                ),
                "evidence.incomplete_scope",
            ),
            "python": (
                _verified_evidence(
                    "osv",
                    [],
                    root_updates={"python_versions": ["3.11", "3.12", "3.13"]},
                ),
                "evidence.incomplete_python_matrix",
            ),
        }

        for case, (osv_evidence, expected_code) in cases.items():
            with self.subTest(case=case):
                result = evaluate_dependency_security(
                    osv_evidence,
                    _evidence("dependabot", []),
                    _inventory(),
                    evaluation_context=_trusted_evaluation(),
                )
                diagnostics = result["diagnostics"]
                if not isinstance(diagnostics, list) or not diagnostics:
                    self.fail("diagnostics must contain a matrix coverage failure")
                diagnostic = diagnostics[0]
                if not isinstance(diagnostic, dict):
                    self.fail("diagnostic must be a table")
                self.assertEqual(diagnostic["code"], expected_code)

    def test_uv_adapter_invokes_locked_json_audit_and_normalizes_preview_output(self) -> None:
        calls: list[tuple[list[str], Path]] = []
        raw_preview: dict[str, object] = {
            "schema": {"version": "preview"},
            "summary": {"audited_packages": 1, "vulnerabilities": 1},
            "vulnerabilities": [
                {
                    "dependency": {"name": "PyJWT", "version": "2.12.1"},
                    "id": "GHSA-aaaa-bbbb-cccc",
                    "aliases": ["PYSEC-2026-1", "CVE-2026-0001"],
                    "description": "Preview-only prose must not cross the adapter boundary.",
                    "fix_versions": ["2.13.0", "2.9.0", "2.10.0"],
                }
            ],
            "adverse_statuses": list[dict[str, object]](),
        }

        def runner(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
            calls.append((command, cwd))
            return subprocess.CompletedProcess(command, 1, json.dumps(raw_preview), "")

        result = collect_uv_audit_evidence(
            Path("/repo"),
            package_scopes_by_python=_package_scopes_by_python(),
            runner=runner,
        )

        self.assertEqual(
            calls,
            [
                (
                    [
                        "uv",
                        "audit",
                        "--locked",
                        "--output-format",
                        "json",
                        "--python-platform",
                        "linux",
                        "--python-version",
                        version,
                    ],
                    Path("/repo"),
                )
                for version in SUPPORTED_PYTHON_VERSIONS
            ],
        )
        self.assertEqual(result["schema_version"], "2.0")
        self.assertEqual(result["status"], "available")
        self.assertEqual(
            result["advisories"],
            [
                {
                    "advisory_id": "GHSA-aaaa-bbbb-cccc",
                    "aliases": ["CVE-2026-0001", "PYSEC-2026-1"],
                    "package": "pyjwt",
                    "locked_version": "2.12.1",
                    "affected": True,
                    "affected_range": "",
                    "fixed_versions": ["2.10.0", "2.13.0", "2.9.0"],
                    "dependency_scopes": ["runtime", "optional"],
                    "python_versions": list(SUPPORTED_PYTHON_VERSIONS),
                }
            ],
        )
        provenance = result["provenance"]
        if not isinstance(provenance, dict):
            self.fail("provenance must be an object")
        observation = provenance["source_observation"]
        if not isinstance(observation, dict):
            self.fail("source observation must be an object")
        self.assertIs(observation["authenticated"], False)
        self.assertIs(observation["pagination_complete"], True)
        self.assertEqual(observation["page_count"], 4)
        self.assertEqual(observation["item_count"], 1)
        self.assertEqual(result["payload_sha256"], _payload_sha256(dict(result)))

    def test_default_uv_adapter_uses_explicit_binary_and_minimal_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            repo = root / "repo"
            repo.mkdir()
            (repo / "pyproject.toml").write_text(
                "[project]\nname='fixture'\nversion='1'\ndependencies=[]\n",
                encoding="utf-8",
            )
            (repo / "uv.lock").write_text("version = 1\n", encoding="utf-8")
            observations = root / "observations.jsonl"
            fake_uv = root / "trusted-uv"
            fake_uv.write_text(
                textwrap.dedent(
                    f"""\
                    #!{sys.executable}
                    import json
                    import os
                    import pathlib
                    import sys

                    record = {{"argv": sys.argv, "environment": dict(os.environ)}}
                    with pathlib.Path({str(observations)!r}).open("a", encoding="utf-8") as output:
                        output.write(json.dumps(record, sort_keys=True) + "\\n")
                    print(json.dumps({{"vulnerabilities": [], "adverse_statuses": []}}))
                    """
                ),
                encoding="utf-8",
            )
            fake_uv.chmod(0o755)
            inventories = _package_scopes_by_python()
            versions = {
                python_version: {
                    package: _package_versions().get(package, "1.0.0")
                    for package in scopes
                }
                for python_version, scopes in inventories.items()
            }
            host_secret = "must-not-cross-collector-boundary"
            with mock.patch.dict(os.environ, {"GITHUB_TOKEN": host_secret}):
                result = dependency_security_module.collect_uv_audit_evidence(
                    repo,
                    package_scopes_by_python=inventories,
                    package_versions_by_python=versions,
                    candidate_identity=_candidate_identity_for_inventories(
                        inventories,
                        versions,
                    ),
                    producer_identity=_producer_identity(),
                    observation_epoch="d" * 64,
                    uv_executable=fake_uv,
                )

            self.assertIsInstance(result, dict)
            provenance = result["provenance"]
            if not isinstance(provenance, dict):
                self.fail("provenance must be an object")
            source = provenance["source_observation"]
            if not isinstance(source, dict):
                self.fail("source observation must be an object")
            self.assertIs(source["authenticated"], False)
            evaluated = evaluate_dependency_security(
                result,
                _verified_evidence("dependabot", []),
                _inventory(),
                evaluation_context=_trusted_evaluation(),
            )
            self.assertEqual(evaluated["status"], "failed")
            diagnostics = evaluated["diagnostics"]
            if not isinstance(diagnostics, list):
                self.fail("diagnostics must be a list")
            self.assertTrue(
                any(
                    diagnostic.get("code") == "evidence.unverified"
                    for diagnostic in diagnostics
                    if isinstance(diagnostic, dict)
                )
            )
            records = [json.loads(line) for line in observations.read_text().splitlines()]
            self.assertEqual(len(records), 4)
            for record in records:
                self.assertEqual(record["argv"][0], str(fake_uv))
                self.assertIn("--no-config", record["argv"])
                self.assertIn("--no-sources", record["argv"])
                self.assertIn("--no-build", record["argv"])
                environment = record["environment"]
                self.assertNotIn("GITHUB_TOKEN", environment)
                self.assertEqual(environment["UV_NO_CONFIG"], "1")
                self.assertEqual(environment["UV_KEYRING_PROVIDER"], "disabled")

    def test_uv_adapter_does_not_publish_host_paths_from_inspection_errors(self) -> None:
        secret_path = "/home/operator/private/worktree/pyproject.toml"
        with mock.patch.object(
            dependency_security_module,
            "_validate_uv_audit_project",
            side_effect=OSError(secret_path),
        ):
            result = dependency_security_module.collect_uv_audit_evidence(
                Path("/repo"),
                package_scopes_by_python=_package_scopes_by_python(),
                package_versions_by_python=_package_versions_by_python(),
                candidate_identity=_candidate_identity(),
                producer_identity=_producer_identity(),
                observation_epoch="d" * 64,
                uv_executable="/trusted/uv",
            )

        self.assertEqual(result["status"], "unavailable")
        self.assertNotIn(secret_path, json.dumps(result))

    def test_default_uv_adapter_rejects_candidate_config_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            (repo / "pyproject.toml").write_text(
                "[project]\nname='fixture'\nversion='1'\ndependencies=[]\n",
                encoding="utf-8",
            )
            (repo / "uv.lock").write_text("version = 1\n", encoding="utf-8")
            (repo / "uv.toml").write_text(
                'default-index = "http://169.254.169.254/latest"\n',
                encoding="utf-8",
            )
            executable = repo / "trusted-uv"
            sentinel = repo / "executed"
            executable.write_text(
                f"#!{sys.executable}\nfrom pathlib import Path\n"
                f"Path({str(sentinel)!r}).write_text('executed')\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)
            inventories = _package_scopes_by_python()
            versions = {
                python_version: {
                    package: _package_versions().get(package, "1.0.0")
                    for package in scopes
                }
                for python_version, scopes in inventories.items()
            }

            result = dependency_security_module.collect_uv_audit_evidence(
                repo,
                package_scopes_by_python=inventories,
                package_versions_by_python=versions,
                candidate_identity=_candidate_identity_for_inventories(
                    inventories,
                    versions,
                ),
                producer_identity=_producer_identity(),
                observation_epoch="d" * 64,
                uv_executable=executable,
            )

            if not isinstance(result, dict):
                self.fail("local uv audit evidence must remain observational")
            self.assertEqual(result["status"], "unavailable")
            self.assertFalse(sentinel.exists())

    def test_default_uv_adapter_never_selects_uv_from_ambient_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            (repo / "pyproject.toml").write_text(
                "[project]\nname='fixture'\nversion='1'\ndependencies=[]\n",
                encoding="utf-8",
            )
            (repo / "uv.lock").write_text("version = 1\n", encoding="utf-8")
            sentinel = repo / "executed"
            executable = repo / "uv"
            executable.write_text(
                f"#!{sys.executable}\nfrom pathlib import Path\n"
                f"Path({str(sentinel)!r}).write_text('executed')\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)
            inventories = _package_scopes_by_python()
            versions = {
                python_version: {
                    package: _package_versions().get(package, "1.0.0")
                    for package in scopes
                }
                for python_version, scopes in inventories.items()
            }

            with mock.patch.dict(os.environ, {"PATH": str(repo)}):
                result = dependency_security_module.collect_uv_audit_evidence(
                    repo,
                    package_scopes_by_python=inventories,
                    package_versions_by_python=versions,
                    candidate_identity=_candidate_identity_for_inventories(
                        inventories,
                        versions,
                    ),
                    producer_identity=_producer_identity(),
                    observation_epoch="d" * 64,
                )

            if not isinstance(result, dict):
                self.fail("local uv audit evidence must remain observational")
            self.assertEqual(result["status"], "unavailable")
            self.assertFalse(sentinel.exists())

    def test_default_uv_adapter_caps_combined_process_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            (repo / "pyproject.toml").write_text(
                "[project]\nname='fixture'\nversion='1'\ndependencies=[]\n",
                encoding="utf-8",
            )
            (repo / "uv.lock").write_text("version = 1\n", encoding="utf-8")
            executable = repo / "trusted-uv"
            executable.write_text(
                textwrap.dedent(
                    f"""\
                    #!{sys.executable}
                    import sys
                    import threading

                    def flood(stream):
                        stream.write(b"x" * (5 * 1024 * 1024))
                        stream.flush()

                    threads = [
                        threading.Thread(target=flood, args=(sys.stdout.buffer,)),
                        threading.Thread(target=flood, args=(sys.stderr.buffer,)),
                    ]
                    for thread in threads:
                        thread.start()
                    for thread in threads:
                        thread.join()
                    """
                ),
                encoding="utf-8",
            )
            executable.chmod(0o755)
            inventories = _package_scopes_by_python()
            versions = {
                python_version: {
                    package: _package_versions().get(package, "1.0.0")
                    for package in scopes
                }
                for python_version, scopes in inventories.items()
            }

            result = dependency_security_module.collect_uv_audit_evidence(
                repo,
                package_scopes_by_python=inventories,
                package_versions_by_python=versions,
                candidate_identity=_candidate_identity_for_inventories(
                    inventories,
                    versions,
                ),
                producer_identity=_producer_identity(),
                observation_epoch="d" * 64,
                uv_executable=executable,
            )

            if not isinstance(result, dict):
                self.fail("local uv audit evidence must remain observational")
            self.assertEqual(result["status"], "unavailable")
            self.assertLess(len(json.dumps(result)), 4096)

    def test_uv_adapter_uses_only_the_matching_python_inventory(self) -> None:
        inventories = _package_scopes_by_python()
        inventories["3.11"]["pyjwt"] = ["runtime"]
        inventories["3.12"]["pyjwt"] = ["optional"]
        for python_version in ("3.13", "3.14"):
            del inventories[python_version]["pyjwt"]

        def runner(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
            del cwd
            vulnerabilities: list[dict[str, object]] = []
            if command[-1] in {"3.11", "3.12"}:
                vulnerabilities.append(
                    {
                        "dependency": {"name": "PyJWT", "version": "2.12.1"},
                        "id": "GHSA-aaaa-bbbb-cccc",
                        "aliases": ["PYSEC-2026-1"],
                        "fix_versions": list[str](),
                    }
                )
            raw = {
                "vulnerabilities": vulnerabilities,
                "adverse_statuses": list[dict[str, object]](),
            }
            return subprocess.CompletedProcess(command, 1, json.dumps(raw), "")

        result = collect_uv_audit_evidence(
            Path("/repo"),
            package_scopes_by_python=inventories,
            runner=runner,
        )

        self.assertEqual(result["status"], "available")
        self.assertEqual(
            result["advisories"],
            [
                {
                    "advisory_id": "GHSA-aaaa-bbbb-cccc",
                    "aliases": ["PYSEC-2026-1"],
                    "package": "pyjwt",
                    "locked_version": "2.12.1",
                    "affected": True,
                    "affected_range": "",
                    "fixed_versions": list[str](),
                    "dependency_scopes": ["runtime"],
                    "python_versions": ["3.11"],
                },
                {
                    "advisory_id": "GHSA-aaaa-bbbb-cccc",
                    "aliases": ["PYSEC-2026-1"],
                    "package": "pyjwt",
                    "locked_version": "2.12.1",
                    "affected": True,
                    "affected_range": "",
                    "fixed_versions": list[str](),
                    "dependency_scopes": ["optional"],
                    "python_versions": ["3.12"],
                },
            ],
        )

    def test_uv_adapter_reports_unavailable_evidence_without_preview_payload(self) -> None:
        def runner(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
            del cwd
            return subprocess.CompletedProcess(command, 2, "preview payload", "lock mismatch")

        result = collect_uv_audit_evidence(
            Path("/repo"),
            package_scopes_by_python=_package_scopes_by_python(),
            runner=runner,
        )

        self.assertEqual(
            result,
            {
                "artifact_kind": "normalized_dependency_vulnerability_evidence",
                "schema_version": "2.0",
                "source": "osv",
                "status": "unavailable",
                "platforms": list(SUPPORTED_PLATFORMS),
                "dependency_scopes": list(DEPENDENCY_SCOPES),
                "python_versions": list(SUPPORTED_PYTHON_VERSIONS),
                "advisories": [],
                "diagnostics": [
                    {
                        "code": "evidence.unavailable",
                        "source": "osv",
                        "message": (
                            "uv audit did not produce usable evidence for Python 3.11 (exit 2)."
                        ),
                    }
                ],
            },
        )
        self.assertNotIn("preview payload", json.dumps(result))
        self.assertNotIn("lock mismatch", json.dumps(result))

    def test_uv_adapter_requires_complete_scope_inventory_and_package_membership(self) -> None:
        calls: list[list[str]] = []
        preview = {
            "vulnerabilities": [
                {
                    "dependency": {"name": "PyJWT", "version": "2.12.1"},
                    "id": "GHSA-aaaa-bbbb-cccc",
                    "aliases": list[str](),
                    "fix_versions": list[str](),
                }
            ],
            "adverse_statuses": list[dict[str, object]](),
        }

        def runner(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
            del cwd
            calls.append(command)
            return subprocess.CompletedProcess(command, 1, json.dumps(preview), "")

        missing_python = _package_scopes_by_python()
        del missing_python["3.14"]
        unknown_python = _package_scopes_by_python()
        unknown_python["3.15"] = _package_scopes()
        incomplete_minor = _package_scopes_by_python()
        incomplete_minor["3.12"] = {"pyjwt": ["runtime"]}
        complete_without_pyjwt = _package_scopes_by_python()
        del complete_without_pyjwt["3.11"]["pyjwt"]
        cases: dict[str, dict[str, dict[str, list[str]]] | None] = {
            "missing-inventory": None,
            "missing-python-minor": missing_python,
            "unknown-python-minor": unknown_python,
            "incomplete-python-minor": incomplete_minor,
            "missing-package-membership": complete_without_pyjwt,
        }

        for case, inventory in cases.items():
            with self.subTest(case=case):
                calls.clear()
                result = collect_uv_audit_evidence(
                    Path("/repo"),
                    package_scopes_by_python=inventory,
                    runner=runner,
                )

                self.assertEqual(result["status"], "unavailable")
                self.assertLessEqual(len(calls), 1)

    def test_uv_adapter_rejects_a_reported_version_outside_the_candidate_matrix(
        self,
    ) -> None:
        def runner(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
            del cwd
            raw = {
                "vulnerabilities": [
                    {
                        "dependency": {"name": "PyJWT", "version": "99.0.0"},
                        "id": "GHSA-aaaa-bbbb-cccc",
                        "aliases": list[str](),
                        "fix_versions": list[str](),
                    }
                ],
                "adverse_statuses": list[dict[str, object]](),
            }
            return subprocess.CompletedProcess(command, 1, json.dumps(raw), "")

        result = collect_uv_audit_evidence(
            Path("/repo"),
            package_scopes_by_python=_package_scopes_by_python(),
            runner=runner,
        )

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["advisories"], [])

    def test_uv_adapter_fails_closed_when_one_python_lane_is_unavailable(self) -> None:
        calls: list[str] = []

        def runner(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
            del cwd
            python_version = command[-1]
            calls.append(python_version)
            if python_version == "3.13":
                return subprocess.CompletedProcess(command, 2, "", "unavailable")
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps({"vulnerabilities": [], "adverse_statuses": []}),
                "",
            )

        result = collect_uv_audit_evidence(
            Path("/repo"),
            package_scopes_by_python=_package_scopes_by_python(),
            runner=runner,
        )

        self.assertEqual(calls, ["3.11", "3.12", "3.13"])
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(
            result["diagnostics"],
            [
                {
                    "code": "evidence.unavailable",
                    "source": "osv",
                    "message": (
                        "uv audit did not produce usable evidence for Python 3.13 (exit 2)."
                    ),
                }
            ],
        )

    def test_uv_adapter_fails_closed_when_an_audit_times_out(self) -> None:
        def runner(
            command: list[str],
            cwd: Path,
        ) -> subprocess.CompletedProcess[str]:
            del cwd
            raise subprocess.TimeoutExpired(command, 120)

        result = collect_uv_audit_evidence(
            Path("/repo"),
            package_scopes_by_python=_package_scopes_by_python(),
            runner=runner,
        )

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(
            result["diagnostics"],
            [
                {
                    "code": "evidence.unavailable",
                    "source": "osv",
                    "message": "uv audit timed out for Python 3.11.",
                }
            ],
        )

    def test_uv_adapter_rejects_malformed_list_members(self) -> None:
        for field in ("aliases", "fix_versions"):
            with self.subTest(field=field):
                vulnerability: dict[str, object] = {
                    "dependency": {"name": "starlette", "version": "1.0.0"},
                    "id": "GHSA-aaaa-bbbb-cccc",
                    "aliases": ["PYSEC-2026-1"],
                    "fix_versions": ["1.3.1"],
                }
                members = vulnerability[field]
                if not isinstance(members, list):
                    self.fail(f"{field} must be a list")
                vulnerability[field] = [*members, 7]

                def runner(
                    command: list[str],
                    cwd: Path,
                    vulnerability: dict[str, object] = vulnerability,
                ) -> subprocess.CompletedProcess[str]:
                    del cwd
                    raw = {
                        "vulnerabilities": [vulnerability],
                        "adverse_statuses": list[dict[str, object]](),
                    }
                    return subprocess.CompletedProcess(command, 1, json.dumps(raw), "")

                result = collect_uv_audit_evidence(
                    Path("/repo"),
                    package_scopes_by_python=_package_scopes_by_python(),
                    runner=runner,
                )

                self.assertEqual(result["status"], "unavailable")

    def test_normalized_evidence_rejects_malformed_matrix_list_members(self) -> None:
        result = evaluate_dependency_security(
            _verified_evidence(
                "osv",
                [],
                root_updates={"dependency_scopes": [*DEPENDENCY_SCOPES, 7]},
            ),
            _evidence("dependabot", []),
            _inventory(),
            evaluation_context=_trusted_evaluation(),
        )

        self.assertEqual(result["status"], "failed")
        diagnostics = result["diagnostics"]
        if not isinstance(diagnostics, list) or not diagnostics:
            self.fail("diagnostics must contain a matrix validation failure")
        diagnostic = diagnostics[0]
        if not isinstance(diagnostic, dict):
            self.fail("diagnostic must be a table")
        self.assertEqual(diagnostic["code"], "evidence.incomplete_scope")

    def test_normalized_advisory_contract_rejects_unknown_fields(self) -> None:
        malformed = {**_advisory("GHSA-aaaa-bbbb-cccc", aliases=[]), "raw": True}

        result = evaluate_dependency_security(
            _evidence("osv", [malformed]),
            _evidence("dependabot", []),
            _inventory(),
            evaluation_context=_trusted_evaluation(),
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(
            result["diagnostics"],
            [
                {
                    "code": "evidence.invalid",
                    "source": "osv",
                    "message": "advisories[0] has invalid or incomplete fields.",
                }
            ],
        )

    def test_normalized_advisory_contract_rejects_malformed_list_members(self) -> None:
        cases: dict[str, list[object]] = {
            "aliases": ["PYSEC-2026-1", 7],
            "fixed_versions": ["1.3.1", 7],
            "dependency_scopes": ["runtime", 7],
            "python_versions": ["3.11", 7],
        }

        for field, members in cases.items():
            with self.subTest(field=field):
                malformed = _advisory("GHSA-aaaa-bbbb-cccc", aliases=[])
                malformed[field] = members
                result = evaluate_dependency_security(
                    _evidence("osv", [malformed]),
                    _evidence("dependabot", []),
                    _inventory(),
                    evaluation_context=_trusted_evaluation(),
                )

                self.assertEqual(result["status"], "failed")
                self.assertEqual(
                    result["diagnostics"],
                    [
                        {
                            "code": "evidence.invalid",
                            "source": "osv",
                            "message": (
                                "advisories[0] has invalid or incomplete fields."
                            ),
                        }
                    ],
                )

    def test_normalized_evidence_contract_rejects_unknown_root_fields(self) -> None:
        result = evaluate_dependency_security(
            _verified_evidence(
                "osv",
                [],
                root_updates={"preview_schema": "leaked"},
            ),
            _evidence("dependabot", []),
            _inventory(),
            evaluation_context=_trusted_evaluation(),
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(
            result["diagnostics"],
            [
                {
                    "code": "evidence.invalid",
                    "source": "osv",
                    "message": "osv evidence contains unknown root fields.",
                }
            ],
        )

    def test_available_evidence_requires_empty_well_formed_diagnostics(self) -> None:
        valid = evaluate_dependency_security(
            _evidence("osv", []),
            _evidence("dependabot", []),
            _inventory(),
            evaluation_context=_trusted_evaluation(),
        )
        self.assertEqual(valid["status"], "passed")

        malformed_values: dict[str, object] = {
            "not-a-list": "unavailable",
            "not-a-table": ["unavailable"],
            "unknown-field": [
                {
                    "code": "evidence.unavailable",
                    "source": "osv",
                    "message": "not actually available",
                    "detail": "unexpected",
                }
            ],
            "non-string-field": [
                {
                    "code": "evidence.unavailable",
                    "source": "osv",
                    "message": 7,
                }
            ],
            "nonempty-while-available": [
                {
                    "code": "evidence.unavailable",
                    "source": "osv",
                    "message": "not actually available",
                }
            ],
        }

        for case, diagnostics in malformed_values.items():
            with self.subTest(case=case):
                result = evaluate_dependency_security(
                    _verified_evidence(
                        "osv",
                        [],
                        root_updates={"diagnostics": diagnostics},
                    ),
                    _evidence("dependabot", []),
                    _inventory(),
                    evaluation_context=_trusted_evaluation(),
                )

                self.assertEqual(result["status"], "failed")
                result_diagnostics = result["diagnostics"]
                if not isinstance(result_diagnostics, list) or not result_diagnostics:
                    self.fail("diagnostics must contain an evidence validation failure")
                diagnostic = result_diagnostics[0]
                if not isinstance(diagnostic, dict):
                    self.fail("diagnostic must be a table")
                self.assertEqual(diagnostic["code"], "evidence.invalid")
                self.assertEqual(diagnostic["source"], "osv")


def _evidence(
    source: str,
    advisories: list[dict[str, object]],
) -> dependency_security_module.VerifiedDependencyEvidence:
    return _verified_evidence(source, advisories)


def collect_uv_audit_evidence(
    repo_path: str | Path,
    *,
    package_scopes_by_python: dict[str, dict[str, list[str]]] | None,
    runner: dependency_security_module.UvAuditRunner,
) -> dict[str, object]:
    package_versions_by_python = (
        {
            python_version: {
                package: _package_versions().get(package, "1.0.0")
                for package in scopes
            }
            for python_version, scopes in package_scopes_by_python.items()
        }
        if package_scopes_by_python is not None
        else None
    )
    candidate_identity = (
        _candidate_identity_for_inventories(
            package_scopes_by_python,
            package_versions_by_python,
        )
        if package_scopes_by_python is not None
        and package_versions_by_python is not None
        else _candidate_identity()
    )
    result = dependency_security_module.collect_uv_audit_evidence(
        repo_path,
        package_scopes_by_python=package_scopes_by_python,
        package_versions_by_python=package_versions_by_python,
        candidate_identity=candidate_identity,
        producer_identity=_producer_identity(),
        observation_epoch="d" * 64,
        runner=runner,
    )
    if isinstance(result, dependency_security_module.VerifiedDependencyEvidence):
        raise AssertionError("An injected runner must never produce trusted evidence.")
    return result


def _verified_evidence(
    source: str,
    advisories: list[dict[str, object]],
    *,
    root_updates: dict[str, object] | None = None,
    provenance_updates: dict[str, object] | None = None,
    observation_updates: dict[str, object] | None = None,
) -> dependency_security_module.VerifiedDependencyEvidence:
    payload = _verified_payload(
        source,
        advisories,
        root_updates=root_updates,
        provenance_updates=provenance_updates,
        observation_updates=observation_updates,
    )
    return dependency_security_module.VerifiedDependencyEvidence._from_adapter(
        payload,
        seal=dependency_security_module._OBSERVATION_SEAL,
    )


def _verified_payload(
    source: str,
    advisories: list[dict[str, object]],
    *,
    root_updates: dict[str, object] | None = None,
    provenance_updates: dict[str, object] | None = None,
    observation_updates: dict[str, object] | None = None,
) -> dict[str, object]:
    provenance = _provenance(source)
    if provenance_updates:
        provenance.update(provenance_updates)
    observation = provenance["source_observation"]
    if not isinstance(observation, dict):
        raise AssertionError("source observation fixture must be an object")
    if observation_updates:
        observation.update(observation_updates)
    elif "item_count" in observation:
        observation["item_count"] = len(advisories)
    payload: dict[str, object] = {
        "artifact_kind": "normalized_dependency_vulnerability_evidence",
        "schema_version": "2.0",
        "source": source,
        "status": "available",
        "platforms": list(SUPPORTED_PLATFORMS),
        "dependency_scopes": list(DEPENDENCY_SCOPES),
        "python_versions": list(SUPPORTED_PYTHON_VERSIONS),
        "advisories": advisories,
        "diagnostics": [],
        "provenance": provenance,
    }
    if root_updates:
        payload.update(root_updates)
    payload["payload_sha256"] = _payload_sha256(payload)
    return payload


def _trusted_evaluation(
    *,
    context_updates: dict[str, object] | None = None,
) -> dependency_security_module.TrustedDependencyEvaluation:
    context: dict[str, object] = {
        "schema_version": "1.0",
        "observation_epoch": "d" * 64,
        "candidate": _candidate_identity(),
        "matrix": _matrix_identity(),
        "producer": _producer_identity(),
        "interval": {
            "started_at": "2026-08-11T23:29:00Z",
            "evaluated_at": "2026-08-11T23:30:00Z",
        },
    }
    if context_updates:
        context.update(context_updates)
    return dependency_security_module.TrustedDependencyEvaluation._from_adapter(
        context,
        seal=dependency_security_module._EVALUATION_SEAL,
    )


def _provenance(source: str) -> dict[str, object]:
    if source == "osv":
        source_identity = "osv.dev:uv-audit"
        started_at = "2026-08-11T23:29:05Z"
        completed_at = "2026-08-11T23:29:10Z"
        valid_until = "2026-08-11T23:44:10Z"
    else:
        source_identity = "github:dependabot-alerts"
        started_at = "2026-08-11T23:29:15Z"
        completed_at = "2026-08-11T23:29:20Z"
        valid_until = "2026-08-11T23:44:20Z"
    return {
        "schema_version": "1.0",
        "candidate": _candidate_identity(),
        "matrix": _matrix_identity(),
        "producer": _producer_identity(),
        "source_observation": {
            "provider": source,
            "source_identity": source_identity,
            "authenticated": True,
            "pagination_complete": True,
            "page_count": 1,
            "item_count": 0,
            "observation_epoch": "d" * 64,
            "started_at": started_at,
            "completed_at": completed_at,
            "valid_until": valid_until,
        },
    }


def _matrix_identity() -> dict[str, object]:
    package_tuples = [
        {
            "python_version": python_version,
            "package": package,
            "locked_version": _package_versions()[package],
            "dependency_scopes": list(scopes),
        }
        for python_version in SUPPORTED_PYTHON_VERSIONS
        for package, scopes in sorted(_package_scopes().items())
    ]
    return {
        "platform": "linux",
        "python_versions": list(SUPPORTED_PYTHON_VERSIONS),
        "package_tuples": package_tuples,
    }


def _candidate_identity() -> dict[str, object]:
    matrix = _matrix_identity()
    inventory_sha256 = hashlib.sha256(
        _canonical_json({"package_tuples": matrix["package_tuples"]})
    ).hexdigest()
    return {
        "commit_sha": "a" * 40,
        "source_snapshot_sha256": "b" * 64,
        "uv_lock_sha256": "c" * 64,
        "package_scope_inventory_sha256": inventory_sha256,
    }


def _candidate_identity_for_inventories(
    scopes_by_python: dict[str, dict[str, list[str]]],
    versions_by_python: dict[str, dict[str, str]],
) -> dict[str, object]:
    package_tuples = [
        {
            "python_version": python_version,
            "package": package,
            "locked_version": versions_by_python[python_version][package],
            "dependency_scopes": list(scopes),
        }
        for python_version in SUPPORTED_PYTHON_VERSIONS
        if python_version in scopes_by_python and python_version in versions_by_python
        for package, scopes in sorted(scopes_by_python[python_version].items())
        if package in versions_by_python[python_version]
    ]
    inventory_sha256 = hashlib.sha256(
        _canonical_json({"package_tuples": package_tuples})
    ).hexdigest()
    return {
        "commit_sha": "a" * 40,
        "source_snapshot_sha256": "b" * 64,
        "uv_lock_sha256": "c" * 64,
        "package_scope_inventory_sha256": inventory_sha256,
    }


def _producer_identity() -> dict[str, object]:
    return {
        "integration": "github-actions",
        "repository": "nisavid/fork-ops",
        "workflow_ref": ".github/workflows/validation.yml@refs/heads/main",
        "workflow_sha": "e" * 40,
        "run_id": 12345,
        "run_attempt": 1,
        "conclusion": "success",
    }


def _payload_sha256(payload: dict[str, object]) -> str:
    unsigned = {key: value for key, value in payload.items() if key != "payload_sha256"}
    return hashlib.sha256(_canonical_json(unsigned)).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _inventory(*records: dict[str, object]) -> SecurityExceptionInventory:
    canonical_records = [dict(record) for record in records]
    lineage_entries: list[dict[str, object]] = []
    current_entries: list[dict[str, object]] = []
    for record in canonical_records:
        if record["state"] == "renewed":
            record["lineage_sequence"] = 2
            first = _lineage_entry(
                record,
                sequence=1,
                state="approved",
                effective_at="2026-08-01T18:00:00Z",
                result_digest="a" * 64,
                exception_id="77777777-7777-4777-8777-777777777777",
            )
            first["event_digest"] = compute_security_exception_digest(
                "event",
                {
                    key: value
                    for key, value in first.items()
                    if key not in {"event_digest", "result_digest", "record_digest"}
                },
            )
            first["record_digest"] = compute_security_exception_digest(
                "record",
                {key: value for key, value in first.items() if key != "record_digest"},
            )
            record["predecessor_record_digest"] = first["record_digest"]
            current = _lineage_entry(
                record,
                predecessor_event_digest=str(first["event_digest"]),
            )
            lineage_entries.append(first)
        else:
            current = _lineage_entry(record)
        lineage_entries.append(current)
        current_entries.append(current)
    for record, lineage_entry in zip(canonical_records, current_entries, strict=True):
        digests = compute_security_exception_record_digests(record, lineage_entry)
        record.update(
            {
                "evidence_digest": digests.evidence_digest,
                "proposal_digest": digests.proposal_digest,
                "event_digest": digests.event_digest,
                "result_digest": digests.result_digest,
                "record_digest": digests.record_digest,
            }
        )
        lineage_entry.update(
            {
                "event_digest": digests.event_digest,
                "result_digest": digests.result_digest,
                "record_digest": digests.record_digest,
            }
        )
    return validate_security_exception_inventory(
        {
            "artifact_kind": "security_exception_ledger",
            "schema_version": "1.0",
            "exceptions": canonical_records,
        },
        {
            "artifact_kind": "security_exception_private_projection",
            "schema_version": "1.0",
            "contract_version": "1.0",
            "status": "available",
            "records": [],
            "lineage_index": {
                "artifact_kind": "security_exception_lineage_index_projection",
                "schema_version": "1.0",
                "contract_version": "1.0",
                "entries": lineage_entries,
            },
        },
        {
            "artifact_kind": "security_exception_authority_observation",
            "schema_version": "1.0",
            "contract_version": "1.0",
            "status": "available",
            "provider": "github",
            "authentication_status": "unverified_projection",
            "observed_at": "2026-08-12T12:00:00Z",
            "repository_full_name": "nisavid/fork-ops",
            "repository_database_id": 1241799725,
            "repository_node_id": "R_kgDOSgRcLQ",
            "login": "nisavid",
            "account_database_id": 576874,
            "account_node_id": "MDQ6VXNlcjU3Njg3NA==",
        },
        evaluated_at="2026-08-12T12:01:00Z",
    )


def _dependency_inventory_record(
    *,
    exception_id: str = "22222222-2222-4222-8222-222222222222",
    lineage_id: str = "11111111-1111-4111-8111-111111111111",
    state: str = "approved",
    aliases: list[str] | None = None,
    package: str = "starlette",
    locked_version: str = "1.0.0",
    dependency_scopes: list[str] | None = None,
    python_versions: list[str] | None = None,
    platforms: list[str] | None = None,
    digest_character: str = "1",
) -> dict[str, object]:
    selected_aliases = (
        aliases
        if aliases is not None
        else [
            "CVE-2026-0001",
            "GHSA-aaaa-bbbb-cccc",
            "PYSEC-2026-1",
        ]
    )
    selected_scopes = (
        dependency_scopes
        if dependency_scopes is not None
        else list(DEPENDENCY_SCOPES)
    )
    selected_python_versions = (
        python_versions
        if python_versions is not None
        else list(SUPPORTED_PYTHON_VERSIONS)
    )
    selected_platforms = (
        platforms if platforms is not None else list(SUPPORTED_PLATFORMS)
    )
    return {
        "exception_id": exception_id,
        "lineage_id": lineage_id,
        "lineage_sequence": 1,
        "visibility": "public",
        "kind": "finding_exception",
        "subject_kind": "dependency_advisory",
        "subject_key": (
            f"dependency:{lineage_id}:{package}@{locked_version}|"
            f"scopes={','.join(selected_scopes)}|"
            f"python={','.join(selected_python_versions)}|"
            f"platform={','.join(selected_platforms)}"
        ),
        "package": package,
        "locked_version": locked_version,
        "dependency_scopes": selected_scopes,
        "python_versions": selected_python_versions,
        "platforms": selected_platforms,
        "severity": "medium",
        "state": state,
        "owner": "nisavid",
        "authority_login": "nisavid",
        "authority_database_id": 576874,
        "authority_node_id": "MDQ6VXNlcjU3Njg3NA==",
        "aliases": selected_aliases,
        "alias_revision": 1,
        "evidence_revision": 1,
        "evidence_digest": digest_character * 64,
        "compensating_control_ids": ["dependency-isolation"],
        "public_references": [
            "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"
        ],
        "response_started_at": "2026-08-01T12:00:00Z",
        "source_time_status": "authoritative",
        "last_approval_or_renewal": "2026-08-02T12:00:00Z",
        "review_after": "2026-08-20T12:00:00Z",
        "expires_at": "2026-08-25T12:00:00Z",
        "absolute_cap": "2026-08-31T12:00:00Z",
        "removal_condition_code": "compatible_fix_available",
        "fix_availability": "unavailable",
        "proposal_digest": digest_character * 64,
        "event_digest": digest_character * 64,
        "record_digest": digest_character * 64,
        "result_digest": digest_character * 64,
        "predecessor_record_digest": "0" * 64,
        "effects": {
            "inventory_recorded": True,
            "decision_recorded": True,
            "lifecycle_recorded": True,
            "security_posture_green": False,
            "admission_or_merge_authorized": False,
            "repository_control_relaxed_disabled_or_mutated": False,
            "assurance_validated": False,
            "baseline_or_release_eligible": False,
            "product_or_dogfood_authorized": False,
            "underlying_failure_cleared": False,
            "underlying_failure_remains_blocking": True,
        },
    }


def _other_subject_inventory_record() -> dict[str, object]:
    record = _dependency_inventory_record()
    record["subject_kind"] = "first_party_finding"
    record["subject_key"] = "first-party-finding:fork-ops:example"
    record["aliases"] = ["FIRST-PARTY-EXAMPLE"]
    for field in (
        "package",
        "locked_version",
        "dependency_scopes",
        "python_versions",
        "platforms",
    ):
        del record[field]
    return record


def _lineage_entry(
    record: dict[str, object],
    *,
    sequence: int | None = None,
    state: str | None = None,
    effective_at: str | None = None,
    predecessor_event_digest: str = "0" * 64,
    result_digest: str | None = None,
    exception_id: str | None = None,
) -> dict[str, object]:
    subject_identity = f"{record['subject_kind']}:{record['subject_key']}"
    if record["subject_kind"] == "dependency_advisory":
        dependency_scopes = cast(list[str], record["dependency_scopes"])
        python_versions = cast(list[str], record["python_versions"])
        platforms = cast(list[str], record["platforms"])
        subject_identity = (
            f"dependency:{record['package']}@{record['locked_version']}|"
            f"scopes={','.join(dependency_scopes)}|"
            f"python={','.join(python_versions)}|platform={','.join(platforms)}"
        )
    return {
        "lineage_id": record["lineage_id"],
        "exception_id": record["exception_id"] if exception_id is None else exception_id,
        "visibility": record["visibility"],
        "sequence": record["lineage_sequence"] if sequence is None else sequence,
        "state": record["state"] if state is None else state,
        "subject_key": record["subject_key"],
        "subject_identity": subject_identity,
        "alias_revision": record["alias_revision"],
        "evidence_revision": record["evidence_revision"],
        "response_started_at": record["response_started_at"],
        "absolute_cap": record["absolute_cap"],
        "effective_at": (
            record["last_approval_or_renewal"] if effective_at is None else effective_at
        ),
        "expires_at": record["expires_at"],
        "predecessor_event_digest": predecessor_event_digest,
        "event_digest": record["event_digest"],
        "result_digest": record["result_digest"] if result_digest is None else result_digest,
        "record_digest": record["record_digest"],
    }


def _raw_ledger() -> dict[str, object]:
    return {
        "artifact_kind": "security_exception_ledger",
        "schema_version": "1.0",
        "risk_acceptance_authority": "nisavid",
        "exceptions": [],
    }


def _package_scopes() -> dict[str, list[str]]:
    return {
        "fork-ops": ["runtime"],
        "mcp": ["optional"],
        "pyjwt": ["runtime", "optional"],
        "setuptools": ["build"],
        "pytest": ["test"],
        "ruff": ["development"],
        "starlette": ["runtime"],
    }


def _package_versions() -> dict[str, str]:
    return {
        "fork-ops": "0.1.0",
        "mcp": "1.29.0",
        "pyjwt": "2.12.1",
        "setuptools": "83.0.0",
        "pytest": "9.0.3",
        "ruff": "0.14.0",
        "starlette": "1.0.0",
    }


def _package_versions_by_python() -> dict[str, dict[str, str]]:
    return {
        python_version: dict(_package_versions())
        for python_version in SUPPORTED_PYTHON_VERSIONS
    }


def _package_scopes_by_python() -> dict[str, dict[str, list[str]]]:
    return {
        python_version: {
            package: list(scopes)
            for package, scopes in _package_scopes().items()
        }
        for python_version in SUPPORTED_PYTHON_VERSIONS
    }


def _advisory(advisory_id: str, *, aliases: list[str]) -> dict[str, object]:
    return {
        "advisory_id": advisory_id,
        "aliases": aliases,
        "package": "starlette",
        "locked_version": "1.0.0",
        "affected": True,
        "affected_range": "<1.3.1",
        "fixed_versions": ["1.3.1"],
        "dependency_scopes": list(DEPENDENCY_SCOPES),
        "python_versions": list(SUPPORTED_PYTHON_VERSIONS),
    }


if __name__ == "__main__":
    unittest.main()
