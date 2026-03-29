# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/pqc/hndl_analyzer.py
#  Harvest-Now-Decrypt-Later risk analysis engine for quantum threat modeling.
#  Assesses if captured data will be decryptable during its useful life.
#
# 🔗 ARCHITECTS:
#   - Bhanu Guragain (Shadow@Bh4nu) | Lead Developer  🏴 GANGA Offensive Ops 🔥
#   - Team Members:
#       • Shrijesh Pokharel
#       • Aashish Panthi
#
# ⚠️ WARNING:
#   ACCESS RESTRICTED. Authorized use only — pentesting, CTF, security research.
#   Unauthorized access to protected systems is illegal.
# ==========================================================================================
# ⚠️ Version 1.0.0 — Production Release 💀
# ==========================================================================================
"""
pqc/hndl_analyzer.py — Harvest-Now-Decrypt-Later risk analysis engine.

Models the "HNDL" threat scenario where adversaries capture encrypted
data today and store it until quantum computers can break the encryption.

Risk Model:
  HNDL_Risk = f(data_shelf_life, migration_timeline, Q-Day_estimate)

  If data_shelf_life > (Q-Day - today):
    → Data will be decryptable during its useful life
    → CRITICAL risk: immediate migration needed

  If migration_timeline > (Q-Day - today):
    → Organization cannot migrate before Q-Day
    → HIGH risk: begin migration planning immediately

Inputs:
  - Algorithm used for encryption
  - Data sensitivity lifetime (years)
  - Organization's estimated migration timeline (years)
  - Q-Day estimate (configurable, default: 2030)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class HNDLRisk(Enum):
    """HNDL threat risk level."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    SAFE = "SAFE"


@dataclass
class HNDLAssessment:
    """Result of HNDL risk assessment for a cryptographic asset."""
    algorithm: str = ""
    data_shelf_life_years: float = 0
    migration_timeline_years: float = 0
    q_day_estimate: int = 2030
    current_year: int = 2026

    # Computed fields
    years_until_qday: float = 0
    data_at_risk: bool = False
    migration_feasible: bool = False
    risk: HNDLRisk = HNDLRisk.SAFE
    risk_score: int = 0
    action: str = ""
    details: str = ""

    def compute(self) -> None:
        """Compute HNDL risk assessment."""
        self.years_until_qday = max(0, self.q_day_estimate - self.current_year)

        # Is data still valuable when quantum becomes available?
        self.data_at_risk = self.data_shelf_life_years > self.years_until_qday

        # Can the org migrate before Q-Day?
        self.migration_feasible = self.migration_timeline_years < self.years_until_qday

        # Risk matrix
        if not self.data_at_risk:
            self.risk = HNDLRisk.SAFE
            self.risk_score = 0
            self.action = "No immediate action needed. Data expires before Q-Day."
        elif not self.migration_feasible:
            self.risk = HNDLRisk.CRITICAL
            self.risk_score = 100
            self.action = (
                "CRITICAL: Begin PQC migration IMMEDIATELY. "
                "Your data will be decryptable AND you cannot migrate in time."
            )
        elif self.data_at_risk and self.migration_feasible:
            # Data is at risk but migration is possible
            urgency = self.data_shelf_life_years / (self.years_until_qday + 0.01)
            if urgency > 2.0:
                self.risk = HNDLRisk.HIGH
                self.risk_score = 80
                self.action = (
                    "HIGH: Plan PQC migration within 12 months. "
                    "Data has long shelf life relative to Q-Day."
                )
            elif urgency > 1.0:
                self.risk = HNDLRisk.MEDIUM
                self.risk_score = 50
                self.action = (
                    "MEDIUM: Include PQC migration in 2-year roadmap."
                )
            else:
                self.risk = HNDLRisk.LOW
                self.risk_score = 20
                self.action = (
                    "LOW: Monitor NIST PQC developments. "
                    "Plan migration before data shelf life expires."
                )


class HNDLAnalyzer:
    """Harvest-Now-Decrypt-Later threat model analyzer.

    Usage:
        analyzer = HNDLAnalyzer(q_day_estimate=2030)
        assessment = analyzer.assess(
            algorithm="rsa-2048",
            data_shelf_life_years=15,
            migration_timeline_years=3,
        )
        print(assessment.risk, assessment.action)
    """

    def __init__(self, q_day_estimate: int = 2030, current_year: int | None = None):
        self.q_day_estimate = q_day_estimate
        self.current_year = current_year or datetime.now().year

    def assess(
        self,
        algorithm: str,
        data_shelf_life_years: float = 10,
        migration_timeline_years: float = 2,
    ) -> HNDLAssessment:
        """Perform HNDL risk assessment for an algorithm.

        Args:
            algorithm: Cryptographic algorithm name.
            data_shelf_life_years: How long the data must remain confidential.
            migration_timeline_years: How long PQC migration would take.

        Returns:
            HNDLAssessment with computed risk and recommendations.
        """
        assessment = HNDLAssessment(
            algorithm=algorithm,
            data_shelf_life_years=data_shelf_life_years,
            migration_timeline_years=migration_timeline_years,
            q_day_estimate=self.q_day_estimate,
            current_year=self.current_year,
        )
        assessment.compute()

        logger.info(
            "HNDL assessment [%s]: risk=%s score=%d",
            algorithm, assessment.risk.value, assessment.risk_score,
        )
        return assessment

    def assess_batch(
        self,
        algorithms: list[str],
        data_shelf_life_years: float = 10,
        migration_timeline_years: float = 2,
    ) -> list[HNDLAssessment]:
        """Assess multiple algorithms at once."""
        return [
            self.assess(algo, data_shelf_life_years, migration_timeline_years)
            for algo in algorithms
        ]

    def generate_report(self, assessments: list[HNDLAssessment]) -> dict:
        """Generate a summary report from multiple assessments."""
        critical = [a for a in assessments if a.risk == HNDLRisk.CRITICAL]
        high = [a for a in assessments if a.risk == HNDLRisk.HIGH]

        return {
            "q_day_estimate": self.q_day_estimate,
            "total_assessed": len(assessments),
            "critical": len(critical),
            "high": len(high),
            "avg_risk_score": (
                round(sum(a.risk_score for a in assessments) / len(assessments), 1)
                if assessments else 0
            ),
            "immediate_actions": [
                {"algorithm": a.algorithm, "action": a.action}
                for a in critical
            ],
            "planning_required": [
                {"algorithm": a.algorithm, "action": a.action}
                for a in high
            ],
        }
