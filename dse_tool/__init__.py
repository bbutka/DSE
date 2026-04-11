"""Compatibility shim for the active DSE_Core package tree.

The repository still contains an older top-level ``dse_tool`` snapshot.  When
running from the repo root, Python sees that directory before ``DSE_Core`` and
can import stale modules.  Keep legacy files importable as a fallback, but put
the active ``DSE_Core/dse_tool`` package first on this package path.
"""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_ACTIVE_PACKAGE = _ROOT / "DSE_Core" / "dse_tool"

if _ACTIVE_PACKAGE.is_dir():
    __path__ = [str(_ACTIVE_PACKAGE)] + [
        path for path in __path__
        if Path(path).resolve() != _ACTIVE_PACKAGE
    ]
