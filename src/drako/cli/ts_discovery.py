"""TypeScript / JavaScript framework & dependency detection.

Detects TS-based AI agent frameworks (Vercel AI SDK, LangChain.js,
Mastra, AutoGen.js) from ``package.json`` dependencies and
tree-sitter import analysis.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING

from drako.ts_parser._compat import ts_available

if TYPE_CHECKING:
    from drako.cli.discovery import FrameworkInfo, ProjectMetadata

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TS_EXTENSIONS = frozenset({".ts", ".tsx", ".js", ".jsx", ".mts", ".mjs", ".cts", ".cjs"})
_MAX_TS_FILES = 200
_MAX_FILE_SIZE = 100_000  # 100 KB

_SKIP_DIRS = frozenset({
    "node_modules", ".next", "dist", "build", ".git", ".cache",
    "coverage", ".turbo", ".vercel", ".output", "__pycache__",
    "venv", ".venv",
})

# npm package name -> canonical framework name
_TS_FRAMEWORK_PACKAGES: dict[str, str] = {
    # Vercel AI SDK
    "ai": "vercel_ai",
    "@ai-sdk/openai": "vercel_ai",
    "@ai-sdk/anthropic": "vercel_ai",
    "@ai-sdk/google": "vercel_ai",
    "@ai-sdk/mistral": "vercel_ai",
    "@ai-sdk/amazon-bedrock": "vercel_ai",
    "@ai-sdk/azure": "vercel_ai",
    "@ai-sdk/cohere": "vercel_ai",
    # LangChain.js
    "langchain": "langchain_js",
    "@langchain/core": "langchain_js",
    "@langchain/openai": "langchain_js",
    "@langchain/anthropic": "langchain_js",
    "@langchain/community": "langchain_js",
    "@langchain/langgraph": "langchain_js",
    # Mastra
    "@mastra/core": "mastra",
    "@mastra/engine": "mastra",
    # AutoGen.js
    "@autogen/core": "autogen_js",
    "autogen-js": "autogen_js",
    # CrewAI TS (if it exists)
    "crewai": "crewai_js",
}

# ES import source -> canonical framework name
_TS_FRAMEWORK_IMPORTS: dict[str, str] = {
    **_TS_FRAMEWORK_PACKAGES,
    # Also match bare specifiers without scope
    "openai": "_openai",  # just an SDK, not a framework — tracked for models
    "@anthropic-ai/sdk": "_anthropic",
}


def _should_skip_dir(name: str) -> bool:
    return name.startswith(".") or name in _SKIP_DIRS


# ---------------------------------------------------------------------------
# File collection
# ---------------------------------------------------------------------------


def collect_ts_files(root: Path, metadata: ProjectMetadata) -> None:
    """Walk *root* and add TS/JS files to *metadata*.

    Populates ``metadata.ts_files`` and adds contents to
    ``metadata.file_contents``.
    """
    count = 0
    for ts_file in sorted(root.rglob("*")):
        if ts_file.suffix.lower() not in _TS_EXTENSIONS:
            continue
        rel_parts = ts_file.relative_to(root).parts
        if any(_should_skip_dir(p) for p in rel_parts[:-1]):
            continue
        try:
            size = ts_file.stat().st_size
        except OSError:
            continue
        if size > _MAX_FILE_SIZE or size == 0:
            continue
        count += 1
        if count > _MAX_TS_FILES:
            break
        try:
            content = ts_file.read_text(encoding="utf-8", errors="ignore")
            rel_path = str(ts_file.relative_to(root)).replace("\\", "/")
            metadata.ts_files.append(ts_file)
            metadata.file_contents[rel_path] = content
        except OSError:
            continue

    # Collect package.json and tsconfig.json as config files
    for cfg_name in ("package.json", "tsconfig.json", "package-lock.json"):
        cfg_path = root / cfg_name
        if cfg_path.exists() and cfg_name not in metadata.config_files:
            try:
                size = cfg_path.stat().st_size
                if 0 < size < _MAX_FILE_SIZE:
                    content = cfg_path.read_text(encoding="utf-8", errors="ignore")
                    metadata.config_files[cfg_name] = content
            except OSError:
                continue


# ---------------------------------------------------------------------------
# package.json dependency parsing
# ---------------------------------------------------------------------------


def parse_package_json(content: str) -> dict[str, str | None]:
    """Parse ``package.json`` into ``{package: version | None}``."""
    deps: dict[str, str | None] = {}
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return deps

    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for pkg, ver in data.get(section, {}).items():
            if isinstance(ver, str):
                # Strip semver range operators
                cleaned = re.sub(r"^[\^~>=<*\s]+", "", ver) or None
                deps[pkg] = cleaned
            else:
                deps[pkg] = None
    return deps


# ---------------------------------------------------------------------------
# TS framework detection
# ---------------------------------------------------------------------------


def detect_ts_frameworks(metadata: ProjectMetadata) -> list[FrameworkInfo]:
    """Detect TypeScript AI frameworks from package.json + imports.

    Returns a list sorted by confidence (highest first).
    """
    from drako.cli.discovery import FrameworkInfo

    found: dict[str, FrameworkInfo] = {}

    # Layer 1: package.json dependencies (confidence 0.9)
    pkg_json = metadata.config_files.get("package.json", "")
    if pkg_json:
        npm_deps = parse_package_json(pkg_json)
        for pkg_name in npm_deps:
            fw = _TS_FRAMEWORK_PACKAGES.get(pkg_name)
            if fw and not fw.startswith("_") and fw not in found:
                found[fw] = FrameworkInfo(
                    name=fw,
                    version=npm_deps.get(pkg_name),
                    confidence=0.9,
                )

    # Layer 2: import scanning via tree-sitter (confidence 0.7)
    if ts_available():
        from drako.ts_parser import get_parser

        parser = get_parser()
        for rel_path, content in metadata.file_contents.items():
            if not any(rel_path.endswith(ext) for ext in _TS_EXTENSIONS):
                continue
            try:
                tree = parser.parse(content, rel_path)
            except Exception:  # noqa: BLE001
                continue
            for imp in parser.find_imports(tree):
                fw = _TS_FRAMEWORK_IMPORTS.get(imp.module)
                if fw and not fw.startswith("_") and fw not in found:
                    found[fw] = FrameworkInfo(
                        name=fw,
                        version=None,
                        confidence=0.7,
                    )
            for req in parser.find_require_calls(tree):
                fw = _TS_FRAMEWORK_IMPORTS.get(req.module)
                if fw and not fw.startswith("_") and fw not in found:
                    found[fw] = FrameworkInfo(
                        name=fw,
                        version=None,
                        confidence=0.7,
                    )

    return sorted(found.values(), key=lambda f: f.confidence, reverse=True)
