"""Attack profile generation module.

Extracted from engine.py to separate profile generation concerns
from scan orchestration.

Architecture: Task 2.3 — Decomposed into builder modules under
finder/profile_builders/.  AttackProfileGenerator is now an
orchestrator that delegates to pure builder functions.

Builder modules:
  - strategy      : determine_strategy, determine_strategy_reason
  - vectors       : determine_vectors, determine_surgical_vectors, determine_all_vectors
  - config        : determine_waf_strategy, determine_*_worker_config, determine_*_config
  - targets       : determine_page_targets, determine_resource_targets
  - platform_configs : determine_aspnet/php/wordpress/api/edu/spa_config
  - risk          : determine_risk_notes
"""

from __future__ import annotations

from typing import Any, Dict, List

from finder.site_profile import SiteProfile
from logging_config import get_logger

# W2.3: Builder imports — pure functions, no self
from finder.profile_builders.strategy import determine_strategy, determine_strategy_reason
from finder.profile_builders.vectors import determine_vectors, determine_surgical_vectors, determine_all_vectors
from finder.profile_builders.config import (
    determine_waf_strategy,
    determine_worker_config,
    determine_surgical_worker_config,
    determine_all_worker_config,
    determine_request_config,
    determine_login_config,
    determine_timing_config,
    determine_evasion_config,
)
from finder.profile_builders.targets import determine_page_targets, determine_resource_targets
from finder.profile_builders.platform_configs import (
    determine_aspnet_config,
    determine_php_config,
    determine_wordpress_config,
    determine_api_config,
    determine_edu_config,
    determine_spa_config,
)
from finder.profile_builders.risk import determine_risk_notes

logger = get_logger(__name__)


class AttackProfileGenerator:
    """Generate attack profile based on discovered site characteristics.

    This is now an orchestrator that delegates to pure builder functions
    in finder/profile_builders/. The builder functions are stateless —
    they take a SiteProfile and needed params, and return a value.

    The class preserves its public API (__init__ + generate -> dict)
    and keeps self._surgical_analysis for backward compatibility with
    engine.py (which uses getattr(generator, '_surgical_analysis', [])).

    Args:
        profile: The site profile with discovered information.
        html: Optional raw HTML content for pattern matching.
        verify_ssl: Whether SSL verification is enabled (for request config).
    """

    def __init__(self, profile: SiteProfile, html: str = "", verify_ssl: bool = True) -> None:
        self.profile = profile
        self._html = html
        self._verify_ssl = verify_ssl
        self._surgical_analysis: List[str] = []  # Backward compat for engine.py getattr

    def generate(self) -> Dict[str, Any]:
        """Generate the complete attack profile.

        Orchestrates builder calls and assembles the final profile dict.

        Returns:
            Dictionary containing all attack configuration including
            strategy, vectors, workers, WAF strategy, and platform-specific configs.
        """
        p = self.profile
        html = self._html
        verify_ssl = self._verify_ssl

        # Strategy
        strategy_name = determine_strategy(p)
        strategy_reason = determine_strategy_reason(p, html)

        # Vectors — fix hidden mutable state bug: get surgical_targets from return value
        auto_vectors = determine_vectors(p, strategy_name, html, verify_ssl)
        surgical_vectors, surgical_targets = determine_surgical_vectors(p, html)
        all_vectors = determine_all_vectors(p, html)

        # Backward compat: engine.py reads generator._surgical_analysis via getattr
        self._surgical_analysis = surgical_targets

        # Configuration
        waf_strategy = determine_waf_strategy(p)
        worker_config = determine_worker_config(p, strategy_name)
        surgical_worker_config = determine_surgical_worker_config(p)
        all_worker_config = determine_all_worker_config(p)
        request_config = determine_request_config(p, verify_ssl)
        login_config = determine_login_config(p)
        timing_config = determine_timing_config(p)
        evasion_config = determine_evasion_config(p)

        # Targets
        page_targets = determine_page_targets(p)
        resource_targets = determine_resource_targets(p, html)

        # Platform-specific configs
        asp_net_config = determine_aspnet_config(p)
        php_config = determine_php_config(p)
        wordpress_config = determine_wordpress_config(p)
        api_config = determine_api_config(p)
        edu_config = determine_edu_config(p)
        spa_config = determine_spa_config(p, html)

        # Risk
        risk_notes = determine_risk_notes(p)

        # Assemble
        attack: Dict[str, Any] = {
            "target_url": p.url,
            "recommended_strategy": strategy_name,
            "strategy_reason": strategy_reason,
            "attack_vectors": auto_vectors,
            "surgical_vectors": surgical_vectors,
            "surgical_analysis": surgical_targets,
            "all_vectors": all_vectors,
            "waf_strategy": waf_strategy,
            "worker_config": worker_config,
            "surgical_worker_config": surgical_worker_config,
            "all_worker_config": all_worker_config,
            "request_config": request_config,
            "login_config": login_config,
            "page_targets": page_targets,
            "resource_targets": resource_targets,
            "timing_config": timing_config,
            "evasion_config": evasion_config,
            "asp_net_config": asp_net_config,
            "php_config": php_config,
            "wordpress_config": wordpress_config,
            "api_config": api_config,
            "spa_config": spa_config,
            "edu_config": edu_config,
            "risk_notes": risk_notes,
        }

        p.attack_profile = attack

        self._print_strategy_display(strategy_name, strategy_reason, auto_vectors, surgical_targets, all_vectors)

        return attack

    def _print_strategy_display(self, strategy_name: str, strategy_reason: str,
                                 auto_vectors: List[str],
                                 surgical_analysis: List[str],
                                 all_vectors: List[str]) -> None:
        """Log the strategy display.

        Kept inline as presentation logic tightly coupled to the
        orchestration flow.

        Args:
            strategy_name: The selected attack strategy name.
            strategy_reason: Pre-computed strategy reason text.
            auto_vectors: List of auto-mode attack vectors.
            surgical_analysis: List of surgical target analysis strings.
            all_vectors: List of all-out mode attack vectors.
        """
        logger.info(f"STRATEGY: {strategy_name}")

        # Strategy reasons
        reason_text = strategy_reason.strip()
        for line in reason_text.split('\n'):
            if line.strip():
                r = line.strip()
                if 'WAF' in r or 'waf' in r.lower():
                    logger.warning(r)
                else:
                    logger.info(r)

        # Attack vectors summary
        if auto_vectors:
            logger.info(f"AUTO: {', '.join(auto_vectors)}")

        # Surgical targets
        if surgical_analysis:
            logger.info(f"SURGICAL TARGETS: {len(surgical_analysis)}")
            for target in surgical_analysis:
                logger.info(f"  ▸ {target}")

        # All-out vectors
        if all_vectors:
            logger.info(f"ALL-OUT: {', '.join(all_vectors)}")
