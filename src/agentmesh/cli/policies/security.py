"""Security policy rules (SEC-001 through SEC-007)."""

from __future__ import annotations

import ast
import re
from typing import TYPE_CHECKING

from agentmesh.cli.policies.base import BasePolicy, Finding

if TYPE_CHECKING:
    from agentmesh.cli.bom import AgentBOM
    from agentmesh.cli.discovery import ProjectMetadata

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Common API key prefixes / patterns
_API_KEY_PATTERNS = [
    re.compile(r"""(?:"|')sk-[a-zA-Z0-9]{20,}(?:"|')"""),                     # OpenAI
    re.compile(r"""(?:"|')sk-proj-[a-zA-Z0-9_-]{20,}(?:"|')"""),              # OpenAI project
    re.compile(r"""(?:"|')sk-ant-[a-zA-Z0-9_-]{20,}(?:"|')"""),               # Anthropic
    re.compile(r"""(?:"|')AKIA[A-Z0-9]{16,}(?:"|')"""),                        # AWS
    re.compile(r"""(?:"|')ghp_[a-zA-Z0-9]{36}(?:"|')"""),                      # GitHub
    re.compile(r"""(?:"|')gho_[a-zA-Z0-9]{36}(?:"|')"""),                      # GitHub OAuth
    re.compile(r"""(?:"|')AIza[a-zA-Z0-9_-]{35}(?:"|')"""),                    # Google
    re.compile(r"""(?:"|')xox[bprs]-[a-zA-Z0-9-]{10,}(?:"|')"""),             # Slack
    re.compile(r"""(?:"|')(?:bearer|token|api[_-]?key)\s*[:=]\s*['"][a-zA-Z0-9_-]{20,}['"]""", re.IGNORECASE),
]

# Variable names that suggest API keys
_SECRET_VAR_NAMES = re.compile(
    r"(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|private[_-]?key|secret)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# SEC-001: API keys hardcoded in source code
# ---------------------------------------------------------------------------

class SEC001(BasePolicy):
    policy_id = "SEC-001"
    category = "Security"
    severity = "CRITICAL"
    title = "API key hardcoded in source code"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []

        for rel_path, content in metadata.file_contents.items():
            if not rel_path.endswith(".py"):
                continue

            try:
                tree = ast.parse(content, filename=rel_path)
            except SyntaxError:
                continue

            lines = content.splitlines()

            for node in ast.walk(tree):
                # Check string assignments to suspicious variable names
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        var_name = None
                        if isinstance(target, ast.Name):
                            var_name = target.id
                        elif isinstance(target, ast.Attribute):
                            var_name = target.attr

                        if var_name and _SECRET_VAR_NAMES.search(var_name):
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                val = node.value.value
                                if len(val) >= 8 and not val.startswith(("os.environ", "os.getenv", "{")):
                                    line_content = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                                    findings.append(Finding(
                                        policy_id=self.policy_id,
                                        category=self.category,
                                        severity=self.severity,
                                        title=self.title,
                                        message=f'Hardcoded secret in variable "{var_name}"',
                                        file_path=rel_path,
                                        line_number=node.lineno,
                                        code_snippet=line_content,
                                        fix_snippet=f'import os\n{var_name} = os.environ["{var_name.upper()}"]',
                                    ))

            # Also check for raw API key patterns in the source
            for i, line in enumerate(lines, 1):
                if line.strip().startswith("#"):
                    continue
                for pattern in _API_KEY_PATTERNS:
                    if pattern.search(line):
                        # Avoid double-counting with AST findings
                        if not any(f.file_path == rel_path and f.line_number == i for f in findings):
                            findings.append(Finding(
                                policy_id=self.policy_id,
                                category=self.category,
                                severity=self.severity,
                                title=self.title,
                                message="API key pattern detected in source code",
                                file_path=rel_path,
                                line_number=i,
                                code_snippet=line.strip()[:80],
                                fix_snippet='import os\napi_key = os.environ["API_KEY"]',
                            ))
                        break

        return findings


# ---------------------------------------------------------------------------
# SEC-002: Secrets in prompts or configuration
# ---------------------------------------------------------------------------

class SEC002(BasePolicy):
    policy_id = "SEC-002"
    category = "Security"
    severity = "CRITICAL"
    title = "Secrets in prompts or configuration"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []

        for prompt in bom.prompts:
            preview = prompt.content_preview.lower()
            if any(kw in preview for kw in ("api_key", "secret", "password", "token", "sk-", "akia")):
                findings.append(Finding(
                    policy_id=self.policy_id,
                    category=self.category,
                    severity=self.severity,
                    title=self.title,
                    message="Potential secret or API key reference found in prompt text",
                    file_path=prompt.file_path,
                    line_number=prompt.line_number,
                    code_snippet=prompt.content_preview[:60],
                    fix_snippet="Never include secrets in prompts. Use environment variables\nand inject values at runtime, not in prompt templates.",
                ))

        return findings


# ---------------------------------------------------------------------------
# SEC-003: Unrestricted filesystem access in tools
# ---------------------------------------------------------------------------

class SEC003(BasePolicy):
    policy_id = "SEC-003"
    category = "Security"
    severity = "HIGH"
    title = "Unrestricted filesystem access in tool"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []

        for tool in bom.tools:
            if tool.has_filesystem_access:
                # Check if there's any path validation in the function
                content = metadata.file_contents.get(tool.file_path, "")
                has_validation = _has_path_validation(content, tool.name)

                if not has_validation:
                    findings.append(Finding(
                        policy_id=self.policy_id,
                        category=self.category,
                        severity=self.severity,
                        title=self.title,
                        message=f'Tool "{tool.name}" has filesystem access without path validation',
                        file_path=tool.file_path,
                        line_number=tool.line_number,
                        code_snippet=f"# Tool: {tool.name} uses open()/Path without path restriction",
                        fix_snippet='from pathlib import Path\n\nALLOWED_DIR = Path("/data/output")\n\ndef validate_path(path: str) -> Path:\n    resolved = Path(path).resolve()\n    if not str(resolved).startswith(str(ALLOWED_DIR)):\n        raise ValueError(f"Path {path} outside allowed directory")\n    return resolved',
                    ))

        return findings


def _has_path_validation(content: str, func_name: str) -> bool:
    """Check if a function has any path validation patterns."""
    patterns = [
        r"allowed_dir",
        r"validate_path",
        r"startswith\(",
        r"is_relative_to\(",
        r"resolve\(\)",
        r"ALLOWED",
        r"whitelist",
        r"allowlist",
    ]
    # Try to find the function body
    func_match = re.search(rf"def\s+{re.escape(func_name)}\s*\(.*?\).*?(?=\ndef\s|\Z)", content, re.DOTALL)
    if func_match:
        func_body = func_match.group()
        return any(re.search(p, func_body, re.IGNORECASE) for p in patterns)
    return False


# ---------------------------------------------------------------------------
# SEC-004: Unrestricted network access in tools
# ---------------------------------------------------------------------------

class SEC004(BasePolicy):
    policy_id = "SEC-004"
    category = "Security"
    severity = "HIGH"
    title = "Unrestricted network access in tool"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []

        for tool in bom.tools:
            if tool.has_network_access:
                content = metadata.file_contents.get(tool.file_path, "")
                has_allowlist = _has_domain_allowlist(content, tool.name)

                if not has_allowlist:
                    findings.append(Finding(
                        policy_id=self.policy_id,
                        category=self.category,
                        severity=self.severity,
                        title=self.title,
                        message=f'Tool "{tool.name}" makes HTTP requests without domain allowlist',
                        file_path=tool.file_path,
                        line_number=tool.line_number,
                        code_snippet=f"# Tool: {tool.name} uses requests/httpx without domain restriction",
                        fix_snippet='ALLOWED_DOMAINS = ["api.example.com", "data.example.com"]\n\ndef validate_url(url: str) -> str:\n    from urllib.parse import urlparse\n    host = urlparse(url).hostname\n    if host not in ALLOWED_DOMAINS:\n        raise ValueError(f"Domain {host} not in allowlist")\n    return url',
                    ))

        return findings


def _has_domain_allowlist(content: str, func_name: str) -> bool:
    """Check if a function has domain/URL validation."""
    patterns = [
        r"allowed_domain",
        r"allowlist",
        r"whitelist",
        r"domain_check",
        r"urlparse",
        r"validate_url",
        r"ALLOWED_DOMAINS",
        r"ALLOWED_URLS",
    ]
    func_match = re.search(rf"def\s+{re.escape(func_name)}\s*\(.*?\).*?(?=\ndef\s|\Z)", content, re.DOTALL)
    if func_match:
        func_body = func_match.group()
        return any(re.search(p, func_body, re.IGNORECASE) for p in patterns)
    return False


# ---------------------------------------------------------------------------
# SEC-005: Arbitrary code execution (exec/eval/subprocess)
# ---------------------------------------------------------------------------

class SEC005(BasePolicy):
    policy_id = "SEC-005"
    category = "Security"
    severity = "CRITICAL"
    title = "Arbitrary code execution in tool"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []

        # Check tools first
        for tool in bom.tools:
            if tool.has_code_execution:
                findings.append(Finding(
                    policy_id=self.policy_id,
                    category=self.category,
                    severity=self.severity,
                    title=self.title,
                    message=f'Tool "{tool.name}" can execute arbitrary code (exec/eval/subprocess)',
                    file_path=tool.file_path,
                    line_number=tool.line_number,
                    code_snippet=f"# Tool: {tool.name} uses exec(), eval(), or subprocess",
                    fix_snippet='# Use a sandboxed execution environment\nfrom agentmesh.sandbox import safe_exec\nresult = safe_exec(code, timeout=30, allowed_modules=["math"])',
                ))

        # Also scan all files for dangerous calls not in tools
        for rel_path, content in metadata.file_contents.items():
            if not rel_path.endswith(".py"):
                continue
            try:
                tree = ast.parse(content, filename=rel_path)
            except SyntaxError:
                continue

            lines = content.splitlines()

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue

                func_name = None
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        if node.func.value.id in ("os", "subprocess"):
                            func_name = f"{node.func.value.id}.{node.func.attr}"

                if func_name in ("exec", "eval"):
                    # Skip if already reported as a tool
                    if any(f.file_path == rel_path and f.policy_id == self.policy_id for f in findings):
                        continue
                    line_content = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                    findings.append(Finding(
                        policy_id=self.policy_id,
                        category=self.category,
                        severity=self.severity,
                        title=self.title,
                        message=f"Dangerous {func_name}() call found",
                        file_path=rel_path,
                        line_number=node.lineno,
                        code_snippet=line_content[:80],
                        fix_snippet="Avoid exec()/eval() with untrusted input.\nUse ast.literal_eval() for data parsing or a sandboxed environment.",
                    ))

                if func_name and func_name.startswith(("os.system", "os.popen", "subprocess.")):
                    if any(f.file_path == rel_path and f.policy_id == self.policy_id for f in findings):
                        continue
                    line_content = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                    findings.append(Finding(
                        policy_id=self.policy_id,
                        category=self.category,
                        severity=self.severity,
                        title=self.title,
                        message=f"Shell command execution via {func_name}()",
                        file_path=rel_path,
                        line_number=node.lineno,
                        code_snippet=line_content[:80],
                        fix_snippet="Avoid shell commands with agent-controlled input.\nUse subprocess.run() with shell=False and validate all arguments.",
                    ))

        return findings


# ---------------------------------------------------------------------------
# SEC-006: No input validation on tool parameters
# ---------------------------------------------------------------------------

class SEC006(BasePolicy):
    policy_id = "SEC-006"
    category = "Security"
    severity = "MEDIUM"
    title = "No input validation on tool parameters"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []

        for tool in bom.tools:
            content = metadata.file_contents.get(tool.file_path, "")
            if not content:
                continue

            try:
                tree = ast.parse(content, filename=tool.file_path)
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name == tool.name:
                    # Check if function has type annotations on parameters
                    has_annotations = False
                    for arg in node.args.args:
                        if arg.arg == "self":
                            continue
                        if arg.annotation is not None:
                            has_annotations = True
                            break

                    # Check for validation patterns in body
                    body_src = ast.dump(node)
                    has_validation = any(
                        kw in body_src for kw in
                        ("isinstance", "validate", "ValueError", "TypeError", "assert")
                    )

                    if not has_annotations and not has_validation:
                        findings.append(Finding(
                            policy_id=self.policy_id,
                            category=self.category,
                            severity=self.severity,
                            title=self.title,
                            message=f'Tool "{tool.name}" has no type annotations or input validation',
                            file_path=tool.file_path,
                            line_number=tool.line_number,
                            code_snippet=f"def {tool.name}(...)  # No type hints or validation",
                            fix_snippet=f'@tool\ndef {tool.name}(query: str, limit: int = 10) -> str:\n    """Add type hints and validate inputs."""\n    if not query or len(query) > 1000:\n        raise ValueError("Invalid query")',
                        ))

        return findings


# ---------------------------------------------------------------------------
# SEC-007: Prompt injection vulnerability
# ---------------------------------------------------------------------------

class SEC007(BasePolicy):
    policy_id = "SEC-007"
    category = "Security"
    severity = "HIGH"
    title = "Prompt injection vulnerability"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []

        for rel_path, content in metadata.file_contents.items():
            if not rel_path.endswith(".py"):
                continue

            try:
                tree = ast.parse(content, filename=rel_path)
            except SyntaxError:
                continue

            lines = content.splitlines()

            for node in ast.walk(tree):
                # Look for f-strings or .format() in prompt-related assignments
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        name = None
                        if isinstance(target, ast.Name):
                            name = target.id
                        elif isinstance(target, ast.Attribute):
                            name = target.attr

                        if name and any(kw in name.lower() for kw in ("prompt", "system_message", "instruction")):
                            if isinstance(node.value, ast.JoinedStr):
                                # f-string in a prompt
                                line_content = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                                findings.append(Finding(
                                    policy_id=self.policy_id,
                                    category=self.category,
                                    severity=self.severity,
                                    title=self.title,
                                    message=f'User input interpolated into prompt via f-string in "{name}"',
                                    file_path=rel_path,
                                    line_number=node.lineno,
                                    code_snippet=line_content[:80],
                                    fix_snippet="# Separate system prompt from user input\nsystem_prompt = \"You are a helpful assistant.\"\n# Pass user input as a separate message, not interpolated\nmessages = [\n    {\"role\": \"system\", \"content\": system_prompt},\n    {\"role\": \"user\", \"content\": user_input},\n]",
                                ))

                            if isinstance(node.value, ast.Call):
                                func = node.value.func
                                if isinstance(func, ast.Attribute) and func.attr == "format":
                                    line_content = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                                    findings.append(Finding(
                                        policy_id=self.policy_id,
                                        category=self.category,
                                        severity=self.severity,
                                        title=self.title,
                                        message=f'User input interpolated into prompt via .format() in "{name}"',
                                        file_path=rel_path,
                                        line_number=node.lineno,
                                        code_snippet=line_content[:80],
                                        fix_snippet="# Separate system prompt from user input\nsystem_prompt = \"You are a helpful assistant.\"\n# Pass user input as a separate message, not interpolated\nmessages = [\n    {\"role\": \"system\", \"content\": system_prompt},\n    {\"role\": \"user\", \"content\": user_input},\n]",
                                    ))

        return findings


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

SECURITY_POLICIES: list[BasePolicy] = [
    SEC001(),
    SEC002(),
    SEC003(),
    SEC004(),
    SEC005(),
    SEC006(),
    SEC007(),
]
