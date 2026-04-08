"""Framework-specific fix suggestion modules for `drako scan --simple`.

Each module exports a `FIXES` dict mapping rule IDs to a callable that
takes a `Finding` and returns a one-sentence fix string tailored to that
framework. The router selects the module from the detected framework.
"""

from drako.simple.fixes import autogen, crewai, direct_api, langchain, langgraph

FIX_MODULES = {
    "crewai": crewai.FIXES,
    "langchain": langchain.FIXES,
    "langgraph": langgraph.FIXES,
    "autogen": autogen.FIXES,
    "direct_api": direct_api.FIXES,
}

__all__ = ["FIX_MODULES"]
