"""Compatibility shim for the active DSE_Core IP catalog package."""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_ACTIVE_PACKAGE = _ROOT / "DSE_Core" / "ip_catalog"

if _ACTIVE_PACKAGE.is_dir():
    __path__ = [str(_ACTIVE_PACKAGE)] + [
        path for path in __path__
        if Path(path).resolve() != _ACTIVE_PACKAGE
    ]
