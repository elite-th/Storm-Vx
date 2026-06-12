#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ui.dashboard — Re-export of DashboardRenderer from tester.vf_dashboard.

This module provides backward compatibility. The actual DashboardRenderer
implementation lives in tester/vf_dashboard.py (which has the full v22
dashboard with sparklines, labeled dividers, gradient bars, etc.).

BUG-FIX: The old ui/dashboard.py had a minimal DashboardRenderer with a
completely different __init__ signature (taking only a TerminalUI instance),
which was never actually used by VF_TESTER.py. VF_TESTER creates its
DashboardRenderer from tester/vf_dashboard.py directly. This stub caused
confusion because importing from ui.dashboard would give the wrong class.

Now this module simply re-exports the correct DashboardRenderer from
tester.vf_dashboard, so any code importing from either location gets
the same, correct class.
"""
from __future__ import annotations

# Re-export the actual DashboardRenderer from the tester module
from tester.vf_dashboard import DashboardRenderer

__all__ = ["DashboardRenderer"]
