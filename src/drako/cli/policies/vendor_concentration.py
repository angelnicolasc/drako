"""Vendor Concentration Risk policy rules (VCR-001, VCR-002, VCR-003).

Detects when an AI agent project's governance, runtime, and model stack
comes from a single vendor — which compromises audit independence.

These rules are vendor-neutral in their descriptions. Finding output
names the detected vendor, but rule definitions use "a single vendor".
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from drako.cli.policies.base import BasePolicy, Finding

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata


# ---------------------------------------------------------------------------
# Vendor fingerprinting — dict-based, easily extensible
# ---------------------------------------------------------------------------

# Model name prefix → vendor
_MODEL_VENDOR: dict[str, str] = {
    "gpt-": "openai",
    "o1": "openai",
    "o3": "openai",
    "claude-": "anthropic",
    "gemini": "google",
    "llama": "meta",
    "mistral": "mistralai",
    "mixtral": "mistralai",
    "command-r": "cohere",
    "deepseek": "deepseek",
}

# Patterns in source code that override model vendor to a cloud provider
# (e.g. Azure OpenAI wraps gpt-* models but the API vendor is Microsoft)
_API_VENDOR_PATTERNS: dict[str, str] = {
    "AzureChatOpenAI": "microsoft",
    "AzureOpenAI": "microsoft",
    "azure.openai": "microsoft",
    "AZURE_OPENAI_": "microsoft",
    "AZURE_OPENAI_ENDPOINT": "microsoft",
    "VertexAI": "google",
    "vertex_ai": "google",
    "VERTEX_AI_": "google",
    "ChatVertexAI": "google",
}

# Framework name (as detected by discovery.py) → vendor
_FRAMEWORK_VENDOR: dict[str, str] = {
    "autogen": "microsoft",
    "semantic_kernel": "microsoft",
    "google_adk": "google",
    "openai_agents": "openai",
    # crewai, langgraph, langchain, llamaindex, pydantic_ai are independent
}

# Governance/compliance packages → vendor
_GOVERNANCE_PACKAGES: dict[str, str] = {
    "azure-ai-evaluation": "microsoft",
    "semantic-kernel": "microsoft",
    "semantic_kernel": "microsoft",
    "google-cloud-aiplatform": "google",
    "vertexai": "google",
}

# Cloud env-var prefixes found in source → vendor
_CLOUD_ENV_PREFIXES: dict[str, str] = {
    "AZURE_": "microsoft",
    "GOOGLE_CLOUD_": "google",
    "VERTEX_": "google",
}

# Cloud import prefixes found in source → vendor
_CLOUD_IMPORT_PREFIXES: dict[str, str] = {
    "azure": "microsoft",
    "google.cloud": "google",
    "google.auth": "google",
}


# ---------------------------------------------------------------------------
# Vendor detection helpers
# ---------------------------------------------------------------------------

def _detect_model_vendors(bom: AgentBOM, metadata: ProjectMetadata) -> set[str]:
    """Return vendor set from detected models and API usage patterns."""
    vendors: set[str] = set()

    # From model names in BOM
    for model in bom.models:
        name = model.name.lower()
        for prefix, vendor in _MODEL_VENDOR.items():
            if name.startswith(prefix):
                vendors.add(vendor)
                break

    # From API vendor patterns in source (Azure OpenAI, Vertex AI, etc.)
    all_content = "\n".join(metadata.source_files.values())
    for pattern, vendor in _API_VENDOR_PATTERNS.items():
        if pattern in all_content:
            vendors.add(vendor)

    return vendors


def _detect_framework_vendors(bom: AgentBOM) -> set[str]:
    """Return vendor set from detected frameworks."""
    vendors: set[str] = set()
    for fw in bom.frameworks:
        vendor = _FRAMEWORK_VENDOR.get(fw.name.lower())
        if vendor:
            vendors.add(vendor)
    return vendors


def _detect_cloud_vendors(metadata: ProjectMetadata) -> set[str]:
    """Return vendor set from cloud imports and env vars in source."""
    vendors: set[str] = set()
    all_content = "\n".join(metadata.source_files.values())

    for prefix, vendor in _CLOUD_ENV_PREFIXES.items():
        if prefix in all_content:
            vendors.add(vendor)

    for prefix, vendor in _CLOUD_IMPORT_PREFIXES.items():
        if f"import {prefix}" in all_content or f"from {prefix}" in all_content:
            vendors.add(vendor)

    return vendors


def _detect_governance_vendors(metadata: ProjectMetadata) -> set[str]:
    """Return vendors from governance-related dependencies."""
    vendors: set[str] = set()
    for dep in metadata.dependencies:
        dep_norm = dep.lower().replace("_", "-")
        for pkg, vendor in _GOVERNANCE_PACKAGES.items():
            pkg_norm = pkg.lower().replace("_", "-")
            if dep_norm == pkg_norm or dep_norm.startswith(pkg_norm):
                vendors.add(vendor)
    return vendors


# ---------------------------------------------------------------------------
# VCR-001: Single-vendor model + framework stack
# ---------------------------------------------------------------------------

class VCR001(BasePolicy):
    """VCR-001: Single-vendor model and framework stack."""

    policy_id = "VCR-001"
    category = "Vendor Concentration"
    severity = "MEDIUM"
    title = "Single-vendor model and framework stack"
    impact = (
        "When your model provider and agent framework come from the same vendor, "
        "framework defaults may silently favor that vendor's models in routing, "
        "fallbacks, and error handling."
    )
    attack_scenario = (
        "Framework auto-selects the vendor's most expensive model as fallback. "
        "The team doesn't notice because the framework logs it as 'normal behavior', "
        "inflating costs by 3x."
    )
    references = [
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    ]
    remediation_effort = "moderate"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        model_vendors = _detect_model_vendors(bom, metadata)
        framework_vendors = _detect_framework_vendors(bom)

        # Case 1: Model + framework from same vendor
        if model_vendors and framework_vendors:
            overlap = model_vendors & framework_vendors
            if overlap:
                vendor = next(iter(overlap))
                return [self._finding(
                    message=(
                        f"Model API and agent framework are both from the same vendor "
                        f"({vendor}). Governance decisions may be influenced by vendor "
                        f"priorities rather than your security posture."
                    ),
                    fix_snippet=(
                        "# Consider decoupling model provider from framework vendor:\n"
                        "# 1. Use LiteLLM or a model router for vendor-agnostic calls\n"
                        "# 2. Test with models from at least two providers\n"
                        "# 3. Ensure fallback models are from a different vendor"
                    ),
                )]

        # Case 2: All models from a single vendor (vendor monoculture)
        # Applies when framework is independent (not vendor-locked)
        if model_vendors and len(model_vendors) == 1 and not framework_vendors:
            # Only flag if there are 2+ models from the same vendor
            model_count = len(bom.models)
            if model_count >= 2:
                vendor = next(iter(model_vendors))
                return [self._finding(
                    message=(
                        f"All {model_count} models come from a single vendor "
                        f"({vendor}). A vendor outage or pricing change would "
                        f"affect your entire agent fleet."
                    ),
                    fix_snippet=(
                        "# Diversify model providers to reduce vendor concentration risk:\n"
                        "# 1. Use LiteLLM or a model router for vendor-agnostic calls\n"
                        "# 2. Configure fallback models from a different provider\n"
                        "# 3. Test with at least two model vendors"
                    ),
                )]

        return []


# ---------------------------------------------------------------------------
# VCR-002: Governance tooling from framework vendor
# ---------------------------------------------------------------------------

class VCR002(BasePolicy):
    """VCR-002: Governance tooling from framework vendor."""

    policy_id = "VCR-002"
    category = "Vendor Concentration"
    severity = "HIGH"
    title = "Governance tooling from framework vendor"
    impact = (
        "Your governance layer is built by the same organization that builds the "
        "framework being governed. The governance tool has structural incentives "
        "to underreport issues in its own vendor's framework."
    )
    attack_scenario = (
        "Vendor governance tool skips a critical check for a known framework bug "
        "because fixing it would require admitting a flaw. The team's 'passing' "
        "audit is meaningless."
    )
    references = [
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    ]
    remediation_effort = "significant"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        framework_vendors = _detect_framework_vendors(bom)
        governance_vendors = _detect_governance_vendors(metadata)

        if not framework_vendors or not governance_vendors:
            return []

        overlap = framework_vendors & governance_vendors
        if not overlap:
            return []

        vendor = next(iter(overlap))
        return [self._finding(
            message=(
                f"Governance/compliance tooling and agent framework are both from "
                f"the same vendor ({vendor}). This is equivalent to a company "
                f"auditing itself — use an independent governance tool."
            ),
            fix_snippet=(
                "# Use an independent governance scanner:\n"
                "# pip install drako\n"
                "# drako scan .\n"
                "#\n"
                "# Drako is vendor-neutral and flags issues across all frameworks."
            ),
        )]


# ---------------------------------------------------------------------------
# VCR-003: Cloud-model-framework lock-in
# ---------------------------------------------------------------------------

class VCR003(BasePolicy):
    """VCR-003: Cloud-model-framework lock-in (3+ layers from same vendor)."""

    policy_id = "VCR-003"
    category = "Vendor Concentration"
    severity = "HIGH"
    title = "Cloud-model-framework lock-in"
    impact = (
        "Three or more stack layers from the same vendor means switching any "
        "component requires rearchitecting the entire stack. Governance "
        "independence is zero."
    )
    attack_scenario = (
        "Vendor raises API prices by 40%. Migration is impossible because cloud "
        "infra, model API, and framework are all tightly coupled to the same "
        "vendor. Team absorbs the cost increase."
    )
    references = [
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    ]
    remediation_effort = "significant"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        model_vendors = _detect_model_vendors(bom, metadata)
        framework_vendors = _detect_framework_vendors(bom)
        cloud_vendors = _detect_cloud_vendors(metadata)
        governance_vendors = _detect_governance_vendors(metadata)

        # Collect all vendors and count how many layers each spans
        all_vendors: set[str] = (
            model_vendors | framework_vendors | cloud_vendors | governance_vendors
        )

        for vendor in all_vendors:
            layers = 0
            layer_names: list[str] = []

            if vendor in model_vendors:
                layers += 1
                layer_names.append("model API")
            if vendor in framework_vendors:
                layers += 1
                layer_names.append("agent framework")
            if vendor in cloud_vendors:
                layers += 1
                layer_names.append("cloud infrastructure")
            if vendor in governance_vendors:
                layers += 1
                layer_names.append("governance tooling")

            if layers >= 3:
                layers_str = ", ".join(layer_names)
                return [self._finding(
                    message=(
                        f"A single vendor ({vendor}) controls {layers} stack "
                        f"layers: {layers_str}. Switching any component requires "
                        f"rearchitecting the entire stack."
                    ),
                    fix_snippet=(
                        "# Reduce vendor concentration:\n"
                        "# 1. Use a vendor-neutral model router (LiteLLM)\n"
                        "# 2. Abstract cloud services behind interfaces\n"
                        "# 3. Use an independent governance tool (drako)\n"
                        "# 4. Test with at least 2 model providers"
                    ),
                )]

        return []


# ---------------------------------------------------------------------------
# Exported policy list
# ---------------------------------------------------------------------------

VCR_POLICIES: list[BasePolicy] = [
    VCR001(),
    VCR002(),
    VCR003(),
]
