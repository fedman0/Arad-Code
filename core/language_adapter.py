"""Language adapter protocol — declares what analysis capabilities are available per language.

Keeps skill logic decoupled from language specifics. Each adapter returns an
AnalysisResult that carries both the items found AND quality metadata so callers
know whether the result is from semantic analysis or a grep fallback.
"""
from __future__ import annotations
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Protocol, runtime_checkable
from pydantic import BaseModel, Field

from .models import AnalysisQuality


class CapabilityLevel(str, Enum):
    NONE = "none"
    TEXTUAL = "textual"
    STRUCTURAL = "structural"
    SEMANTIC = "semantic"
    FLOW = "flow"
    FRAMEWORK = "framework"


class CapabilityManifest(BaseModel):
    language: str
    symbol_resolution: CapabilityLevel = CapabilityLevel.NONE
    call_graph: CapabilityLevel = CapabilityLevel.NONE
    data_flow: CapabilityLevel = CapabilityLevel.NONE
    type_inference: CapabilityLevel = CapabilityLevel.NONE
    framework_awareness: CapabilityLevel = CapabilityLevel.NONE
    notes: list[str] = Field(default_factory=list)

    def best_level(self) -> CapabilityLevel:
        levels = [
            self.symbol_resolution, self.call_graph,
            self.data_flow, self.type_inference, self.framework_awareness,
        ]
        order = list(CapabilityLevel)
        return max(levels, key=lambda l: order.index(l))


class SymbolInfo(BaseModel):
    name: str
    qualified_name: str
    kind: str
    file_path: str
    line_start: int
    line_end: int
    signature: str = ""
    decorators: list[str] = Field(default_factory=list)


class CallEdgeInfo(BaseModel):
    caller_qn: str
    callee_qn: str
    call_site_file: str
    call_site_line: int
    certainty: str = "unknown"


class AnalysisResult(BaseModel):
    items: list[Any] = Field(default_factory=list)
    quality: AnalysisQuality = Field(default_factory=AnalysisQuality)
    truncated: bool = False
    error: Optional[str] = None


@runtime_checkable
class LanguageAdapter(Protocol):
    def capabilities(self) -> CapabilityManifest: ...
    def enumerate_symbols(self, repo_path: str, file_path: str) -> AnalysisResult: ...
    def find_references(self, repo_path: str, symbol_name: str,
                        file_glob: Optional[str] = None) -> AnalysisResult: ...
    def resolve_callers(self, repo_path: str, qualified_name: str) -> AnalysisResult: ...
    def resolve_callees(self, repo_path: str, qualified_name: str) -> AnalysisResult: ...


class TreeSitterAdapter:
    """Structural adapter using tree-sitter AST.

    Provides STRUCTURAL-level capability: can enumerate symbols with accurate
    line numbers and decorators, but cannot resolve cross-file symbol identities
    or follow data flow.
    """

    _SUPPORTED = {
        ".py", ".cs", ".ts", ".tsx", ".js", ".jsx",
        ".go", ".java", ".rb", ".rs", ".cpp", ".cc", ".c", ".h",
        ".php", ".kt", ".swift",
    }

    def capabilities(self) -> CapabilityManifest:
        return CapabilityManifest(
            language="multi (tree-sitter)",
            symbol_resolution=CapabilityLevel.STRUCTURAL,
            call_graph=CapabilityLevel.TEXTUAL,
            data_flow=CapabilityLevel.NONE,
            type_inference=CapabilityLevel.NONE,
            framework_awareness=CapabilityLevel.NONE,
            notes=[
                "Symbol enumeration uses AST — accurate line numbers and decorators",
                "Cross-file resolution falls back to grep",
                "Data flow and type inference not available",
            ],
        )

    def enumerate_symbols(self, repo_path: str, file_path: str) -> AnalysisResult:
        from .code_analysis import parse_file_structure
        import json
        raw = parse_file_structure(repo_path, file_path)
        try:
            data = json.loads(raw)
        except Exception as ex:
            return AnalysisResult(
                quality=AnalysisQuality(method="textual", confidence="speculative",
                                        limitations=[f"parse error: {ex}"]),
                error=str(ex),
            )
        q = data.get("_quality", {})
        used_ast = q.get("used_ast", False)
        method = "structural" if used_ast else "textual"
        conf = "medium" if used_ast else "speculative"
        reason = q.get("fallback_reason", "tree-sitter unavailable or no grammar for this file type")
        limitations = [] if used_ast else [reason]
        return AnalysisResult(
            items=data.get("symbols", []),
            quality=AnalysisQuality(method=method, confidence=conf, limitations=limitations),
        )

    def find_references(self, repo_path: str, symbol_name: str,
                        file_glob: Optional[str] = None,
                        max_matches: int = 100) -> AnalysisResult:
        from .code_analysis import find_all_usages
        raw = find_all_usages(repo_path, symbol_name, file_glob, max_matches)
        all_lines = raw.splitlines()
        truncated = "[TRUNCATED]" in all_lines
        lines = [l for l in all_lines if l.strip() and l.strip() not in ("No usages found", "[TRUNCATED]")]
        return AnalysisResult(
            items=lines,
            quality=AnalysisQuality(
                method="textual",
                confidence="low",
                limitations=[
                    "grep-based: may include false positives (same name, different symbol)",
                    "does not resolve overloads or aliased imports",
                ],
            ),
            truncated=truncated,
        )

    def resolve_callers(self, repo_path: str, qualified_name: str) -> AnalysisResult:
        return self.find_references(repo_path, qualified_name.split(".")[-1])

    def resolve_callees(self, repo_path: str, qualified_name: str) -> AnalysisResult:
        return AnalysisResult(
            quality=AnalysisQuality(
                method="textual",
                confidence="speculative",
                limitations=["callee resolution requires semantic analysis; not available in TreeSitterAdapter"],
            ),
            error="callee resolution not supported at structural level",
        )


class TextualAdapter:
    """Minimal grep-only fallback adapter.

    Used when tree-sitter grammars are unavailable. Everything is TEXTUAL level.
    """

    def capabilities(self) -> CapabilityManifest:
        return CapabilityManifest(
            language="any (textual fallback)",
            symbol_resolution=CapabilityLevel.TEXTUAL,
            call_graph=CapabilityLevel.TEXTUAL,
            data_flow=CapabilityLevel.NONE,
            type_inference=CapabilityLevel.NONE,
            framework_awareness=CapabilityLevel.NONE,
            notes=["All results are grep-based; false positives possible; no structural guarantees"],
        )

    def enumerate_symbols(self, repo_path: str, file_path: str) -> AnalysisResult:
        from .code_analysis import parse_file_structure
        import json
        raw = parse_file_structure(repo_path, file_path)
        try:
            data = json.loads(raw)
        except Exception as ex:
            return AnalysisResult(error=str(ex),
                                   quality=AnalysisQuality(method="textual", confidence="speculative"))
        return AnalysisResult(
            items=data.get("symbols", []),
            quality=AnalysisQuality(
                method="textual", confidence="speculative",
                limitations=["regex-based symbol detection; no AST guarantees"],
            ),
        )

    def find_references(self, repo_path: str, symbol_name: str,
                        file_glob: Optional[str] = None,
                        max_matches: int = 100) -> AnalysisResult:
        from .code_analysis import find_all_usages
        raw = find_all_usages(repo_path, symbol_name, file_glob, max_matches)
        all_lines = raw.splitlines()
        truncated = "[TRUNCATED]" in all_lines
        lines = [l for l in all_lines if l.strip() and l.strip() not in ("No usages found", "[TRUNCATED]")]
        return AnalysisResult(
            items=lines,
            quality=AnalysisQuality(method="textual", confidence="speculative",
                                    limitations=["grep-based; false positives likely"]),
            truncated=truncated,
        )

    def resolve_callers(self, repo_path: str, qualified_name: str) -> AnalysisResult:
        return self.find_references(repo_path, qualified_name.split(".")[-1])

    def resolve_callees(self, repo_path: str, qualified_name: str) -> AnalysisResult:
        return AnalysisResult(
            quality=AnalysisQuality(method="textual", confidence="speculative",
                                    limitations=["callee resolution not available at textual level"]),
            error="not supported",
        )


_TREE_SITTER_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".cs", ".java", ".go",
    ".rb", ".cpp", ".c", ".h", ".hpp", ".rs", ".swift", ".kt",
    ".php", ".lua", ".r", ".ex", ".exs", ".scala", ".m",
}


def get_adapter_for(file_path: str) -> LanguageAdapter:
    """Return the best available adapter for the given file extension."""
    ext = Path(file_path).suffix.lower()
    if ext not in _TREE_SITTER_EXTENSIONS:
        return TextualAdapter()
    try:
        from tree_sitter_languages import get_parser as _  # noqa
        return TreeSitterAdapter()
    except ImportError:
        return TextualAdapter()


def get_default_adapter() -> LanguageAdapter:
    """Return the best available adapter regardless of file type."""
    try:
        from tree_sitter_languages import get_parser as _  # noqa
        return TreeSitterAdapter()
    except ImportError:
        return TextualAdapter()
