import tkinter as tk
from tkinter import ttk
from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from dse_tool.core.solution_parser import SolutionResult


class ResultsPanel(ttk.Frame):
    """Displays the three strategy solutions as side-by-side cards."""

    def __init__(self, parent: tk.Widget, **kwargs) -> None:
        super().__init__(parent, **kwargs)
        self._solutions: List["SolutionResult"] = []
        self._cards: List[ttk.LabelFrame] = []
        self._report_window: tk.Toplevel | None = None
        self._system_caps: dict = {}
        self._report_text: str = ""
        self._build_ui()

    def _build_ui(self) -> None:
        # Container for the three strategy cards
        cards_frame = ttk.Frame(self)
        cards_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # Create three empty cards
        strategy_keys = ["strategy_1", "strategy_2", "strategy_3"]
        for skey in strategy_keys:
            card = self._make_card(cards_frame, skey)
            self._cards.append(card)

        # View Full Report button
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=4, pady=(0, 4))
        self._view_report_btn = ttk.Button(
            btn_frame, text="View Full Report", command=self._on_view_report
        )
        self._view_report_btn.pack(side=tk.RIGHT)
        self._view_report_btn.state(["disabled"])
        self._compare_btn = ttk.Button(
            btn_frame, text="Compare Strategies", command=self._on_compare
        )
        self._compare_btn.pack(side=tk.RIGHT, padx=4)
        self._compare_btn.state(["disabled"])
        self._exec_summary_btn = ttk.Button(
            btn_frame, text="Executive Summary", command=self._on_exec_summary
        )
        self._exec_summary_btn.pack(side=tk.RIGHT, padx=4)
        self._exec_summary_btn.state(["disabled"])

    def _make_card(self, parent: tk.Widget, skey: str) -> ttk.LabelFrame:
        card = ttk.LabelFrame(parent, text=skey.replace("_", " ").title(), padding=6)
        card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4, pady=4)

        # SAT/UNSAT indicator
        sat_frame = ttk.Frame(card)
        sat_frame.pack(fill=tk.X)
        sat_lbl = tk.Label(sat_frame, text="—", font=("TkDefaultFont", 11, "bold"))
        sat_lbl.pack()
        setattr(self, f"_sat_{skey}", sat_lbl)

        # Metrics
        metrics_frame = ttk.Frame(card)
        metrics_frame.pack(fill=tk.BOTH, expand=True, pady=(4, 0))
        for lbl_text, attr_name in [("LUTs:", "lut"), ("FFs:", "ff"),
                                     ("Power:", "power"), ("Risk Score:", "risk")]:
            row = ttk.Frame(metrics_frame)
            row.pack(fill=tk.X)
            ttk.Label(row, text=lbl_text, width=12).pack(side=tk.LEFT)
            val = ttk.Label(row, text="—", font=("TkDefaultFont", 9, "bold"))
            val.pack(side=tk.LEFT)
            setattr(self, f"_{attr_name}_{skey}", val)

        p1_btn = ttk.Button(metrics_frame, text="Details...", width=9,
                            command=lambda sk=skey: self._open_phase1_details(sk))
        p1_btn.pack(anchor=tk.W, pady=(2, 0))
        setattr(self, f"_p1btn_{skey}", p1_btn)

        # Phase 2 info
        phase2_frame = ttk.LabelFrame(card, text="Phase 2", padding=4)
        phase2_frame.pack(fill=tk.X, pady=(4, 0))
        phase2_val = ttk.Label(phase2_frame, text="—", wraplength=140, justify=tk.LEFT)
        phase2_val.pack(anchor=tk.W)
        setattr(self, f"_phase2_{skey}", phase2_val)
        p2_btn = ttk.Button(phase2_frame, text="Details...", width=9,
                            command=lambda sk=skey: self._open_phase2_details(sk))
        p2_btn.pack(anchor=tk.W, pady=(2, 0))
        setattr(self, f"_p2btn_{skey}", p2_btn)

        # Phase 3 info
        phase3_frame = ttk.LabelFrame(card, text="Phase 3", padding=4)
        phase3_frame.pack(fill=tk.X, pady=(4, 0))
        phase3_val = ttk.Label(phase3_frame, text="—", wraplength=140, justify=tk.LEFT)
        phase3_val.pack(anchor=tk.W)
        setattr(self, f"_phase3_{skey}", phase3_val)
        p3_btn = ttk.Button(phase3_frame, text="Details...", width=9,
                            command=lambda sk=skey: self._open_phase3_details(sk))
        p3_btn.pack(anchor=tk.W, pady=(2, 0))
        setattr(self, f"_p3btn_{skey}", p3_btn)

        return card

    def set_system_caps(self, caps: dict) -> None:
        """Store system resource caps for use by the executive summary."""
        self._system_caps = dict(caps) if caps else {}

    def set_report_text(self, report_text: str) -> None:
        """Store the orchestrator-generated report for later viewing."""
        self._report_text = report_text or ""

    def set_results(self, solutions: List["SolutionResult"]) -> None:
        """Populate the cards with solution data."""
        self._solutions = solutions
        strategy_keys = ["strategy_1", "strategy_2", "strategy_3"]

        for i, (card, skey) in enumerate(zip(self._cards, strategy_keys)):
            sol = solutions[i] if i < len(solutions) else None

            # Update card title
            name = (sol.label or f"Strategy {i+1}") if sol else f"Strategy {i+1}"
            card.configure(text=name)

            # SAT/UNSAT — check sol.phase1.satisfiable when phase1 is set
            sat_lbl: tk.Label = getattr(self, f"_sat_{skey}")
            if sol and sol.phase1 is not None:
                sat_lbl.config(
                    text="SAT" if sol.phase1.satisfiable else "UNSAT",
                    foreground="green" if sol.phase1.satisfiable else "red"
                )
            elif sol and sol.error:
                # Fallback solution with error
                sat_lbl.config(text="UNSAT", foreground="red")
            else:
                sat_lbl.config(text="—", foreground="black")

            # Metrics from Phase 1
            p1 = sol.phase1 if sol else None
            metric_map = [
                ("lut", "total_luts"),
                ("ff",  "total_ffs"),
                ("power", "total_power"),
            ]
            for attr_name, field_key in metric_map:
                lbl: ttk.Label = getattr(self, f"_{attr_name}_{skey}")
                if lbl is None:
                    continue
                if p1 is not None:
                    val = getattr(p1, field_key, None)
                    lbl.config(text=str(val) if val is not None else "—")
                else:
                    lbl.config(text="—")

            # Risk from Phase 1
            risk_lbl: ttk.Label = getattr(self, f"_risk_{skey}")
            if risk_lbl is None:
                continue
            if p1 is not None:
                risk_lbl.config(text=str(p1.total_risk()))
            else:
                risk_lbl.config(text="—")

            # Phase 2 info
            phase2_lbl: ttk.Label = getattr(self, f"_phase2_{skey}")
            if phase2_lbl is None:
                pass
            elif sol and sol.phase2 is not None:
                p2 = sol.phase2
                parts = []
                if p2.placed_fws:
                    parts.append(f"FWs: {', '.join(p2.placed_fws)}")
                if p2.placed_ps:
                    parts.append(f"PSs: {', '.join(p2.placed_ps)}")
                if getattr(p2, "closed_loop_score", ()):
                    parts.append(f"Mode: closed-loop ({p2.closed_loop_candidates_evaluated} cand)")
                elif p2.satisfiable:
                    parts.append(f"Mode: {sol.phase2_mode_label()}")
                phase2_lbl.config(text=", ".join(parts) if parts else "—")
            else:
                phase2_lbl.config(text="—")

            # Phase 3 info
            phase3_lbl: ttk.Label = getattr(self, f"_phase3_{skey}")
            if phase3_lbl is None:
                pass
            elif sol and sol.scenarios:
                scenario_parts = []
                for sc in sol.scenarios[:3]:
                    compromised_str = ",".join(sc.compromised) if sc.compromised else "none"
                    scenario_parts.append(
                        f"{sc.name}({compromised_str}) score={sc.total_risk:.0f}"
                    )
                if len(sol.scenarios) > 3:
                    scenario_parts.append(f"+{len(sol.scenarios) - 3} more")

                # Summarise worst functional status across scenarios
                sat_scenarios = [s for s in sol.scenarios if s.satisfiable]
                non_func = sum(1 for s in sat_scenarios if s.system_non_functional)
                degraded = sum(1 for s in sat_scenarios if s.system_degraded and not s.system_non_functional)
                if non_func:
                    scenario_parts.append(f"NON-FUNC:{non_func}")
                elif degraded:
                    scenario_parts.append(f"DEGRADED:{degraded}")
                function_def_count = sum(
                    len(getattr(s, "function_deficiencies", []) or getattr(s, "function_findings", []))
                    for s in sat_scenarios
                )
                if function_def_count:
                    scenario_parts.append(f"FUNC-DEF:{function_def_count}")
                phase3_lbl.config(text="; ".join(scenario_parts))
            else:
                phase3_lbl.config(text="—")

        self._view_report_btn.state(["!disabled"])
        self._compare_btn.state(["!disabled"])
        self._exec_summary_btn.state(["!disabled"])

    def clear(self) -> None:
        """Reset all cards to empty state."""
        self._solutions = []
        self._report_text = ""
        strategy_keys = ["strategy_1", "strategy_2", "strategy_3"]
        for i, card in enumerate(self._cards):
            card.configure(text=f"Strategy {i+1}")
            skey = strategy_keys[i]
            sat_lbl: tk.Label = getattr(self, f"_sat_{skey}")
            sat_lbl.config(text="—", foreground="black")
            for attr_name in ["lut", "ff", "power", "risk"]:
                lbl: ttk.Label = getattr(self, f"_{attr_name}_{skey}")
                lbl.config(text="—")
            for prefix in ["phase2", "phase3"]:
                lbl: ttk.Label = getattr(self, f"_{prefix}_{skey}")
                lbl.config(text="—")
        self._view_report_btn.state(["disabled"])
        self._compare_btn.state(["disabled"])
        self._exec_summary_btn.state(["disabled"])
        if self._report_window:
            self._report_window.destroy()
            self._report_window = None

    def _open_phase2_details(self, skey: str) -> None:
        """Open the Phase 2 detail dialog for the given strategy key."""
        strategy_keys = ["strategy_1", "strategy_2", "strategy_3"]
        idx = strategy_keys.index(skey) if skey in strategy_keys else -1
        sol = self._solutions[idx] if 0 <= idx < len(self._solutions) else None
        if sol is None or sol.phase2 is None:
            from tkinter import messagebox
            messagebox.showinfo("Phase 2 Details", "No Phase 2 results available for this strategy.")
            return
        _Phase2DetailDialog(self, sol.phase2)

    def _open_phase3_details(self, skey: str) -> None:
        """Open the Phase 3 scenario navigator for the given strategy key."""
        strategy_keys = ["strategy_1", "strategy_2", "strategy_3"]
        idx = strategy_keys.index(skey) if skey in strategy_keys else -1
        sol = self._solutions[idx] if 0 <= idx < len(self._solutions) else None
        if sol is None or not sol.scenarios:
            from tkinter import messagebox
            messagebox.showinfo("Phase 3 Details", "No Phase 3 scenario results available for this strategy.")
            return
        _Phase3DetailDialog(self, sol.scenarios)

    def _open_phase1_details(self, skey: str) -> None:
        idx = ["strategy_1", "strategy_2", "strategy_3"].index(skey)
        if idx >= len(self._solutions):
            return
        sol = self._solutions[idx]
        if sol is None or sol.phase1 is None:
            return
        _Phase1DetailDialog(self, sol.phase1)

    def _on_exec_summary(self) -> None:
        if not self._solutions:
            return
        caps = getattr(self, "_system_caps", {})
        _ExecutiveSummaryDialog(self, self._solutions, system_caps=caps)

    def _on_compare(self) -> None:
        if not self._solutions:
            return
        _StrategyComparisonDialog(self, self._solutions)

    def _on_view_report(self) -> None:
        from dse_tool.core.comparison import generate_report_text
        if not self._solutions:
            return
        report_text = self._report_text or generate_report_text(self._solutions)
        self.view_report(report_text)

    def view_report(self, report_text: str) -> None:
        """Open a toplevel window with the full report text."""
        if self._report_window and self._report_window.winfo_exists():
            self._report_window.lift()
            return

        self._report_window = tk.Toplevel(self)
        self._report_window.title("Full Comparison Report")
        self._report_window.geometry("800x600")

        text_widget = tk.Text(self._report_window, wrap=tk.NONE, font=("Courier New", 9))
        v_scroll = ttk.Scrollbar(self._report_window, orient=tk.VERTICAL, command=text_widget.yview)
        h_scroll = ttk.Scrollbar(self._report_window, orient=tk.HORIZONTAL, command=text_widget.xview)
        text_widget.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X)

        text_widget.insert("1.0", report_text)
        text_widget.configure(state="disabled")


# ---------------------------------------------------------------------------
# Executive Summary Dialog
# ---------------------------------------------------------------------------

class _ExecutiveSummaryDialog(tk.Toplevel):
    """
    Analyses all Phase 1/2/3 data across strategies and presents a concise
    executive summary emphasizing the most important findings, the primary
    bottleneck ("long pole"), and whether the architecture needs redesign.
    """

    _FONT  = ("Courier New", 10)
    _BG    = "#0a0a18"
    _FG    = "#d0d8e8"

    # Colour tags for severity levels
    _COLOURS = {
        "CRITICAL": "#ff4444",
        "HIGH":     "#ff8844",
        "MEDIUM":   "#dddd44",
        "LOW":      "#88cc88",
        "GOOD":     "#44dd44",
        "HEADER":   "#88aaff",
        "VERDICT_OK":  "#44dd88",
        "VERDICT_BAD": "#ff5555",
        "LONGPOLE":    "#ffaa00",
    }

    def __init__(self, parent, solutions, *, system_caps: dict | None = None) -> None:
        super().__init__(parent)
        self.transient(parent)
        self.title("Executive Security & Resilience Summary")
        self.geometry("900x700")
        self.grab_set()

        self._solutions = solutions
        self._system_caps = system_caps or {}
        self._build_ui()
        self.wait_window()

    def _build_ui(self) -> None:
        # Generate the summary
        from dse_tool.core.executive_summary import (
            ExecutiveSummaryAnalyser, format_executive_summary,
        )

        max_luts = self._system_caps.get("max_luts", 0) or 53200
        max_power = self._system_caps.get("max_power", 0) or 15000

        analyser = ExecutiveSummaryAnalyser(
            self._solutions, max_luts=max_luts, max_power=max_power,
        )
        summary = analyser.analyse()
        text = format_executive_summary(summary)

        # Main text widget
        frm = ttk.Frame(self)
        frm.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        self._text = tk.Text(
            frm, font=self._FONT, bg=self._BG, fg=self._FG,
            wrap=tk.WORD, state=tk.DISABLED, padx=12, pady=8,
            insertbackground=self._FG, spacing1=1, spacing3=1,
        )
        vsb = ttk.Scrollbar(frm, orient=tk.VERTICAL, command=self._text.yview)
        self._text.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self._text.pack(fill=tk.BOTH, expand=True)

        # Configure tags
        for tag, colour in self._COLOURS.items():
            self._text.tag_configure(tag, foreground=colour)
        self._text.tag_configure("HEADER", foreground="#88aaff",
                                 font=("Courier New", 10, "bold"))
        self._text.tag_configure("VERDICT_OK", foreground="#44dd88",
                                 font=("Courier New", 11, "bold"))
        self._text.tag_configure("VERDICT_BAD", foreground="#ff5555",
                                 font=("Courier New", 11, "bold"))
        self._text.tag_configure("LONGPOLE", foreground="#ffaa00",
                                 font=("Courier New", 10, "bold"))
        self._text.tag_configure("SEP", foreground="#555577")

        # Insert and colorize
        self._text.configure(state=tk.NORMAL)
        self._insert_coloured(text, summary)
        self._text.configure(state=tk.DISABLED)

        # Bottom buttons
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=8, pady=(0, 8))
        ttk.Button(btn_frame, text="Copy to Clipboard",
                   command=self._copy).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="Close",
                   command=self.destroy).pack(side=tk.RIGHT, padx=4)

        # Status label
        arch_tag = ("ADEQUATE" if summary.architecture_adequate
                    else "REDESIGN RECOMMENDED")
        tag_colour = ("green" if summary.architecture_adequate else "red")
        ttk.Label(btn_frame, text=f"Architecture: {arch_tag}",
                  foreground=tag_colour,
                  font=("TkDefaultFont", 10, "bold")).pack(side=tk.LEFT, padx=12)

    def _insert_coloured(self, text: str, summary) -> None:
        """Insert text with syntax colouring for the summary format."""
        import re
        for line in text.split("\n"):
            stripped = line.strip()

            # Separator lines
            if stripped and all(c in "=-" for c in stripped):
                self._text.insert(tk.END, line + "\n", "SEP")
                continue

            # Section headers (ALL CAPS lines)
            if stripped and stripped == stripped.upper() and len(stripped) > 3 and not stripped.startswith(">>>"):
                self._text.insert(tk.END, line + "\n", "HEADER")
                continue

            # Architecture verdict banner
            if ">>> ADEQUATE <<<" in line:
                self._text.insert(tk.END, line + "\n", "VERDICT_OK")
                continue
            if ">>> REDESIGN RECOMMENDED <<<" in line:
                self._text.insert(tk.END, line + "\n", "VERDICT_BAD")
                continue
            if "ARCHITECTURE REDESIGN REQUIRED" in line:
                self._text.insert(tk.END, line + "\n", "VERDICT_BAD")
                continue

            # Long pole marker
            if "<<<< LONG POLE" in line:
                self._text.insert(tk.END, line + "\n", "LONGPOLE")
                continue

            # Severity tags in bottleneck lines
            sev_match = re.search(r'\[(CRITICAL|HIGH|MEDIUM|LOW)\]', line)
            if sev_match:
                sev = sev_match.group(1)
                self._text.insert(tk.END, line + "\n", sev)
                continue

            # "Long Pole" section content
            if stripped.startswith("Category") or stripped.startswith("Severity"):
                self._text.insert(tk.END, line + "\n", "LONGPOLE")
                continue

            # Default
            self._text.insert(tk.END, line + "\n")

    def _copy(self) -> None:
        content = self._text.get("1.0", tk.END)
        self.clipboard_clear()
        self.clipboard_append(content)


# ---------------------------------------------------------------------------
# Phase 2 Detail Dialog
# ---------------------------------------------------------------------------

class _Phase2DetailDialog(tk.Toplevel):
    """Detailed view of Phase 2 ZTA policy results."""

    _FONT  = ("Courier New", 9)
    _BG    = "#0d0d1a"
    _FG    = "#c8d0e0"

    def __init__(self, parent, p2) -> None:
        super().__init__(parent)
        self.transient(parent)
        self.title("Phase 2 — ZTA Policy Details")
        self.geometry("760x560")
        self.grab_set()

        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        self._add_rules_tab(nb, p2)
        self._add_tightness_tab(nb, p2)
        self._add_trust_tab(nb, p2)
        self._add_privileges_tab(nb, p2)

        ttk.Button(self, text="Close", command=self.destroy).pack(pady=4)
        self.wait_window()

    def _make_text(self, parent) -> tk.Text:
        frm = ttk.Frame(parent)
        frm.pack(fill=tk.BOTH, expand=True)
        t = tk.Text(frm, font=self._FONT, bg=self._BG, fg=self._FG,
                    wrap=tk.NONE, state=tk.DISABLED)
        vs = ttk.Scrollbar(frm, orient=tk.VERTICAL, command=t.yview)
        hs = ttk.Scrollbar(frm, orient=tk.HORIZONTAL, command=t.xview)
        t.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        hs.pack(side=tk.BOTTOM, fill=tk.X)
        vs.pack(side=tk.RIGHT, fill=tk.Y)
        t.pack(fill=tk.BOTH, expand=True)
        return t

    def _write(self, t: tk.Text, text: str) -> None:
        t.configure(state=tk.NORMAL)
        t.delete("1.0", tk.END)
        t.insert("1.0", text)
        t.configure(state=tk.DISABLED)

    def _add_rules_tab(self, nb, p2) -> None:
        tab = ttk.Frame(nb)
        nb.add(tab, text="  Allow / Deny Rules  ")
        t = self._make_text(tab)
        lines = []
        allows = sorted(set(p2.final_allows))
        denies = sorted(set(p2.final_denies))
        lines.append(f"ALLOW rules ({len(allows)})")
        lines.append("─" * 50)
        if allows:
            lines.append(f"  {'Master':<20} {'IP Core':<20} {'Op'}")
            lines.append(f"  {'─'*19} {'─'*19} {'─'*5}")
            for master, ip, op in allows:
                lines.append(f"  {master:<20} {ip:<20} {op}")
        else:
            lines.append("  (none)")
        lines.append("")
        lines.append(f"DENY rules ({len(denies)})")
        lines.append("─" * 50)
        if denies:
            lines.append(f"  {'Master':<20} {'IP Core':<20} {'Op'}")
            lines.append(f"  {'─'*19} {'─'*19} {'─'*5}")
            for master, ip, op in denies:
                lines.append(f"  {master:<20} {ip:<20} {op}")
        else:
            lines.append("  (none)")
        self._write(t, "\n".join(lines))

    def _add_tightness_tab(self, nb, p2) -> None:
        tab = ttk.Frame(nb)
        nb.add(tab, text="  Policy Precision  ")
        t = self._make_text(tab)
        lines = []
        tightness = p2.policy_tightness  # dict master -> int 0-100
        over = set(p2.over_privileged)
        avg  = p2.avg_policy_tightness()
        coverage = p2.avg_effective_policy_tightness(mode="normal")
        lines.append(f"Average policy precision: {avg:.1f}/100  (100=tight, 0=permissive)")
        lines.append(f"Average normal-mode coverage: {coverage:.1f}/100  (100=all needed accesses satisfied)")
        lines.append("Precision measures grant selectivity; coverage measures post-firewall access satisfaction.")
        lines.append("─" * 50)
        if tightness:
            lines.append(f"  {'Master':<25} {'Score':>6}  {'Status'}")
            lines.append(f"  {'─'*24} {'─'*6}  {'─'*15}")
            for master, score in sorted(tightness.items(), key=lambda x: x[1]):
                status = "OVER-PRIVILEGED" if master in over else ("tight" if score >= 80 else "loose")
                lines.append(f"  {master:<25} {score:>6}  {status}")
        else:
            lines.append("  (no policy precision data)")
        self._write(t, "\n".join(lines))

    def _add_trust_tab(self, nb, p2) -> None:
        tab = ttk.Frame(nb)
        nb.add(tab, text="  Trust Gaps  ")
        t = self._make_text(tab)
        lines = []
        gaps = [
            ("RoT",          p2.trust_gap_rot),
            ("Secure Boot",  p2.trust_gap_sboot),
            ("Attestation",  p2.trust_gap_attest),
            ("Key Storage",  p2.trust_gap_keys),
        ]
        any_gap = any(v for _, v in gaps)
        lines.append("Components missing hardware trust anchors:")
        lines.append("─" * 50)
        for label, names in gaps:
            if names:
                lines.append(f"  Missing {label}:")
                for n in sorted(names):
                    lines.append(f"    - {n}")
        if not any_gap:
            lines.append("  No trust gaps detected.")
        lines.append("")
        lines.append(f"Unattested privileged access pairs ({len(p2.unattested_access)}):")
        lines.append("─" * 50)
        for master, ip in sorted(p2.unattested_access):
            lines.append(f"  {master}  →  {ip}")
        if not p2.unattested_access:
            lines.append("  (none)")
        lines.append("")
        lines.append(f"Unsigned policy servers ({len(p2.unsigned_ps)}):")
        lines.append("─" * 50)
        for ps in sorted(p2.unsigned_ps):
            lines.append(f"  {ps}")
        if not p2.unsigned_ps:
            lines.append("  (none)")
        self._write(t, "\n".join(lines))

    def _add_privileges_tab(self, nb, p2) -> None:
        tab = ttk.Frame(nb)
        nb.add(tab, text="  Privileges  ")
        t = self._make_text(tab)
        lines = []
        lines.append(f"Excess privileges ({len(p2.excess_privileges)}):")
        lines.append("─" * 50)
        for row in sorted(p2.excess_privileges):
            lines.append("  " + "  ".join(str(x) for x in row))
        if not p2.excess_privileges:
            lines.append("  (none — good)")
        lines.append("")
        lines.append(f"Missing privileges ({len(p2.missing_privileges)}):")
        lines.append("─" * 50)
        for row in sorted(p2.missing_privileges):
            lines.append("  " + "  ".join(str(x) for x in row))
        if not p2.missing_privileges:
            lines.append("  (none)")
        lines.append("")
        cost = getattr(p2, "total_cost", None)
        lines.append(f"Total FW+PS deployment cost: {cost if cost is not None else 'N/A'}")
        if getattr(p2, "closed_loop_score", ()):
            lines.append(
                f"Closed-loop score: {tuple(p2.closed_loop_score)} "
                f"(candidates evaluated: {p2.closed_loop_candidates_evaluated})"
            )
            repair_intents = getattr(p2, "closed_loop_repair_intents", [])
            if repair_intents:
                lines.append("")
                lines.append(f"Architecture repair intents ({len(repair_intents)}):")
                lines.append("─" * 50)
                for intent in repair_intents:
                    function = intent.get("function", "unknown")
                    repair = intent.get("repair", "unknown")
                    status = intent.get("status", "pending")
                    axis = intent.get("required_diversity_axis", "")
                    domains = intent.get("minimum_independent_domains", "")
                    axis_text = f" on {axis}" if axis else ""
                    domains_text = f" ({domains} independent domains)" if domains else ""
                    lines.append(f"  {function}: {repair}{axis_text}{domains_text} [{status}]")
        elif p2.resilience_objective_penalty():
            lines.append(
                f"Heuristic resilience penalty: {p2.resilience_objective_penalty()}"
            )
            lines.append(
                "Guidance: exact closed-loop Phase 2 is recommended for high-assurance studies."
            )
        else:
            lines.append("Phase 2 mode: cost-only heuristic")
            lines.append(
                "Guidance: exact closed-loop Phase 2 is recommended for high-assurance studies."
            )
        if p2.unsat_reason:
            lines.append(f"\nUNSAT reason: {p2.unsat_reason}")
        self._write(t, "\n".join(lines))


# ---------------------------------------------------------------------------
# Phase 3 Scenario Navigator Dialog
# ---------------------------------------------------------------------------

class _Phase3DetailDialog(tk.Toplevel):
    """Full scenario navigator for Phase 3 resilience results."""

    _FONT = ("Courier New", 9)
    _BG   = "#0d0d1a"
    _FG   = "#c8d0e0"

    def __init__(self, parent, scenarios) -> None:
        super().__init__(parent)
        self.transient(parent)
        self.title("Phase 3 — Resilience Scenario Navigator")
        self.geometry("900x560")
        self.grab_set()

        self._scenarios = scenarios

        paned = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # Left: scenario list
        left = ttk.Frame(paned)
        paned.add(left, weight=1)
        ttk.Label(left, text="Scenarios").pack(anchor=tk.W)
        self._listbox = tk.Listbox(left, font=("TkDefaultFont", 9), selectmode=tk.SINGLE)
        sb = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self._listbox.yview)
        self._listbox.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self._listbox.pack(fill=tk.BOTH, expand=True)
        for i, sc in enumerate(scenarios):
            risk = sc.total_risk
            self._listbox.insert(tk.END, f"{sc.name}  [score={risk:.0f}]")
        self._listbox.bind("<<ListboxSelect>>", self._on_select)

        # Right: detail text
        right = ttk.Frame(paned)
        paned.add(right, weight=3)
        self._detail = tk.Text(right, font=self._FONT, bg=self._BG, fg=self._FG,
                               wrap=tk.WORD, state=tk.DISABLED)
        vs = ttk.Scrollbar(right, orient=tk.VERTICAL, command=self._detail.yview)
        self._detail.configure(yscrollcommand=vs.set)
        vs.pack(side=tk.RIGHT, fill=tk.Y)
        self._detail.pack(fill=tk.BOTH, expand=True)

        ttk.Button(self, text="Close", command=self.destroy).pack(pady=4)

        if scenarios:
            self._listbox.selection_set(0)
            self._show(scenarios[0])

        self.wait_window()

    def _on_select(self, _event) -> None:
        sel = self._listbox.curselection()
        if sel:
            self._show(self._scenarios[sel[0]])

    def _show(self, sc) -> None:
        lines = []
        lines.append(f"Scenario: {sc.name}")
        lines.append("=" * 56)
        lines.append(f"Compromised  : {', '.join(sc.compromised) or '—'}")
        lines.append(f"Failed       : {', '.join(sc.failed) or '—'}")
        lines.append(f"Total score  : {sc.total_risk:.2f}")
        lines.append("")

        # Blast radii — structural and effective
        eff_br = getattr(sc, "effective_blast_radii", {})
        has_effective = bool(eff_br)
        header = "Blast radii (structural / effective):" if has_effective else "Blast radii (per component):"
        lines.append(header)
        lines.append("─" * 56)
        if sc.blast_radii:
            for comp, r in sorted(sc.blast_radii.items(), key=lambda x: -x[1]):
                eff = eff_br.get(comp, r)
                bar = "█" * min(r, 25)
                if has_effective and eff < r:
                    eff_bar = "░" * min(eff, 25)
                    lines.append(f"  {comp:<18} {r:>3}/{eff:<3}  {eff_bar}{'▓' * min(r - eff, 25)}")
                else:
                    lines.append(f"  {comp:<18} {r:>3}      {bar}")
        else:
            lines.append("  (no data)")
        if has_effective:
            lines.append("  (█ = structural, ░ = effective with firewalls)")
        lines.append("")

        # Asset risks
        lines.append("Asset risks under this scenario:")
        lines.append("─" * 40)
        if sc.scenario_risks:
            for asset, risk in sorted(sc.scenario_risks.items(), key=lambda x: -x[1]):
                lines.append(f"  {asset:<25} {risk}")
        else:
            lines.append("  (no data)")
        lines.append("")

        # Services
        lines.append(f"Services OK        : {', '.join(sc.services_ok) or '—'}")
        lines.append(f"Services degraded  : {', '.join(sc.services_degraded) or '—'}")
        lines.append(f"Services unavail   : {', '.join(sc.services_unavail) or '—'}")
        lines.append("")

        # Unavailable / compromised / cut-off
        if sc.unavailable:
            lines.append(f"Unavailable assets : {', '.join(sc.unavailable)}")
        assets_comp = getattr(sc, "assets_compromised", [])
        if assets_comp:
            lines.append(f"Compromised assets : {', '.join(assets_comp)}")
        if sc.cut_off:
            lines.append(f"Cut-off nodes      : {', '.join(sc.cut_off)}")
        lines.append("")

        # Control plane
        cp_flags = []
        if getattr(sc, "cp_degraded",    False): cp_flags.append("DEGRADED")
        if getattr(sc, "cp_stale",       False): cp_flags.append("STALE")
        if getattr(sc, "cp_compromised", False): cp_flags.append("COMPROMISED")
        lines.append(f"Control plane      : {', '.join(cp_flags) or 'OK'}")
        peps_bypassed = getattr(sc, "peps_bypassed", [])
        ps_comp       = getattr(sc, "ps_compromised", [])
        if peps_bypassed:
            lines.append(f"PEPs bypassed      : {', '.join(peps_bypassed)}")
        if ps_comp:
            lines.append(f"PSes compromised   : {', '.join(ps_comp)}")
        lines.append("")

        # Exposure types
        direct     = getattr(sc, "direct_exp",     [])
        cross      = getattr(sc, "cross_exp",      [])
        same       = getattr(sc, "same_exp",       [])
        unmediated = getattr(sc, "unmediated_exp", [])
        if direct:
            lines.append(f"Direct exposure    : {', '.join(str(x) for x in direct)}")
        if cross:
            lines.append(f"Cross-trust expos. : {', '.join(str(x) for x in cross)}")
        if same:
            lines.append(f"Same-trust expos.  : {', '.join(str(x) for x in same)}")
        if unmediated:
            lines.append(f"Unmediated exposure: {', '.join(str(x) for x in unmediated)}")

        # ── Attack paths (WP5) ──────────────────────────────────────────
        attack_paths = getattr(sc, "attack_paths", [])
        struct_paths = getattr(sc, "structural_attack_paths", [])
        escalation   = getattr(sc, "escalation_paths", [])
        if attack_paths or struct_paths:
            lines.append("")
            lines.append("Attack Paths to Critical Targets (effective / structural):")
            lines.append("─" * 56)
            # Build lookup for structural distances
            struct_lookup = {}
            for src, tgt, dist in struct_paths:
                struct_lookup[(src, tgt)] = dist
            if attack_paths:
                for src, tgt, dist in sorted(attack_paths, key=lambda x: x[2]):
                    sd = struct_lookup.get((src, tgt))
                    if sd is not None and sd < dist:
                        lines.append(f"  {src} -> {tgt}  ({dist} hops, {sd} without FW)")
                    else:
                        lines.append(f"  {src} -> {tgt}  ({dist} hops)")
            elif struct_paths:
                lines.append("  (no effective paths — firewalls block all attack routes)")
                lines.append("  Structural (worst-case, no firewalls):")
                for src, tgt, dist in sorted(struct_paths, key=lambda x: x[2]):
                    lines.append(f"    {src} -> {tgt}  ({dist} hops)")
        if escalation:
            lines.append("")
            lines.append("Privilege Escalation Paths:")
            lines.append("─" * 40)
            for src, tgt, sd, td in escalation:
                lines.append(f"  {src}({sd}) -> {tgt}({td})")

        # ── Functional resilience ────────────────────────────────────────
        caps_ok   = getattr(sc, "capabilities_ok",       [])
        caps_deg  = getattr(sc, "capabilities_degraded",  [])
        caps_lost = getattr(sc, "capabilities_lost",      [])
        ess_lost  = getattr(sc, "essential_caps_lost",     [])
        reasons   = getattr(sc, "capability_reasons",      {})
        sys_func  = getattr(sc, "system_functional",       True)
        sys_deg   = getattr(sc, "system_degraded",         False)
        sys_nf    = getattr(sc, "system_non_functional",   False)

        has_caps = caps_ok or caps_deg or caps_lost
        lines.append("")
        lines.append("Mission Capabilities:")
        lines.append("=" * 56)

        if has_caps:
            # System-level status banner
            if sys_nf:
                lines.append("  SYSTEM STATUS: NON-FUNCTIONAL")
            elif sys_deg:
                lines.append("  SYSTEM STATUS: DEGRADED")
            elif sys_func:
                lines.append("  SYSTEM STATUS: FULLY FUNCTIONAL")
            else:
                lines.append("  SYSTEM STATUS: UNKNOWN (no solver verdict)")
            lines.append("")
        else:
            lines.append("  (no mission capabilities defined for this topology)")
            lines.append("")

        if has_caps:

            if caps_ok:
                lines.append(f"  OK         : {', '.join(sorted(caps_ok))}")
            if caps_deg:
                lines.append(f"  DEGRADED   : {', '.join(sorted(caps_deg))}")
            if caps_lost:
                lines.append(f"  LOST       : {', '.join(sorted(caps_lost))}")
            if ess_lost:
                lines.append(f"  ESSENTIAL  : {', '.join(sorted(ess_lost))} (CRITICAL)")
            lines.append("")

            # Show reasons for each lost/degraded capability
            for cap in sorted(set(caps_lost + caps_deg)):
                cap_reasons = reasons.get(cap, [])
                if cap_reasons:
                    status = "LOST" if cap in caps_lost else "DEGRADED"
                    lines.append(f"  {cap} [{status}]:")
                    for r in cap_reasons:
                        lines.append(f"    - {r}")

        # Function-support findings are separate from mission capabilities.
        function_statuses = getattr(sc, "function_statuses", {})
        function_scores = getattr(sc, "function_scores", {})
        function_deficiencies = getattr(sc, "function_deficiencies", []) or []
        if not function_deficiencies and getattr(sc, "function_findings", []):
            function_deficiencies = sc.derive_function_deficiencies()

        if function_statuses or function_deficiencies:
            lines.append("")
            lines.append("Function Support:")
            lines.append("=" * 56)
            for function_name, status in sorted(function_statuses.items()):
                score = function_scores.get(function_name, 0)
                lines.append(f"  {function_name:<24} {status:<9} score={score}")
            if function_deficiencies:
                lines.append("")
                lines.append("  Structured findings:")
                for deficiency in function_deficiencies:
                    domain = deficiency.get("failed_domain", "")
                    values = deficiency.get("failed_domain_values", [])
                    if domain:
                        value_text = ",".join(str(v) for v in values) if values else "n/a"
                        domain_text = f" under {domain}={value_text}"
                    else:
                        domain_text = ""
                    lines.append(
                        f"    - {deficiency.get('function', 'unknown')}: "
                        f"{deficiency.get('issue', deficiency.get('finding', 'unknown'))}"
                        f"{domain_text}"
                    )

        body = "\n".join(lines)
        self._detail.configure(state=tk.NORMAL)
        self._detail.delete("1.0", tk.END)
        self._detail.insert("1.0", body)
        self._detail.configure(state=tk.DISABLED)


# ---------------------------------------------------------------------------
# Phase 1 Detail Dialog
# ---------------------------------------------------------------------------

class _Phase1DetailDialog(tk.Toplevel):
    """Detailed view of Phase 1 security & resource results."""

    _FONT = ("Courier New", 9)
    _BG   = "#0d0d1a"
    _FG   = "#c8d0e0"

    def __init__(self, parent, p1) -> None:
        super().__init__(parent)
        self.transient(parent)
        self.title("Phase 1 — Security Score & Resource Details")
        self.geometry("720x500")
        self.grab_set()

        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        self._add_resources_tab(nb, p1)
        self._add_security_tab(nb, p1)
        self._add_risk_tab(nb, p1)

        info = f"Strategy: {getattr(p1,'strategy','—')}   " \
               f"Optimal: {'Yes' if p1.optimal else 'No'}   " \
               f"SAT: {'Yes' if p1.satisfiable else 'No'}"
        ttk.Label(self, text=info, foreground="#888888").pack(pady=(0, 2))
        ttk.Button(self, text="Close", command=self.destroy).pack(pady=(0, 6))
        self.wait_window()

    def _make_text(self, parent) -> "tk.Text":
        frm = ttk.Frame(parent)
        frm.pack(fill=tk.BOTH, expand=True)
        t = tk.Text(frm, font=self._FONT, bg=self._BG, fg=self._FG,
                    wrap=tk.NONE, state=tk.DISABLED)
        vs = ttk.Scrollbar(frm, orient=tk.VERTICAL,   command=t.yview)
        hs = ttk.Scrollbar(frm, orient=tk.HORIZONTAL, command=t.xview)
        t.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        hs.pack(side=tk.BOTTOM, fill=tk.X)
        vs.pack(side=tk.RIGHT,  fill=tk.Y)
        t.pack(fill=tk.BOTH, expand=True)
        return t

    def _write(self, t, text: str) -> None:
        t.configure(state=tk.NORMAL)
        t.delete("1.0", tk.END)
        t.insert("1.0", text)
        t.configure(state=tk.DISABLED)

    def _add_resources_tab(self, nb, p1) -> None:
        tab = ttk.Frame(nb)
        nb.add(tab, text="  Resources  ")
        t = self._make_text(tab)
        lines = []
        lines.append("FPGA Resource Utilisation")
        lines.append("=" * 45)
        resources = [
            ("LUTs",    p1.total_luts),
            ("FFs",     p1.total_ffs),
            ("DSPs",    p1.total_dsps),
            ("LUTRAMs", p1.total_lutram),
            ("BRAMs",   p1.total_bram),
            ("Power",   p1.total_power),
        ]
        for name, val in resources:
            bar = "█" * min(int((val or 0) / 50), 30) if val else ""
            lines.append(f"  {name:<10} {val or 0:>8}  {bar}")
        self._write(t, "\n".join(lines))

    def _add_security_tab(self, nb, p1) -> None:
        tab = ttk.Frame(nb)
        nb.add(tab, text="  Security Features  ")
        t = self._make_text(tab)
        lines = []
        sec  = p1.security  or {}
        log  = p1.realtime  or {}
        lines.append(f"Security features placed  ({len(sec)} components):")
        lines.append("─" * 50)
        if sec:
            lines.append(f"  {'Component':<25} {'Security Feature'}")
            lines.append(f"  {'─'*24} {'─'*20}")
            for comp in sorted(sec):
                lines.append(f"  {comp:<25} {sec[comp]}")
        else:
            lines.append("  (no security features placed)")
        lines.append("")
        lines.append(f"Realtime detection  ({len(log)} components):")
        lines.append("─" * 50)
        if log:
            lines.append(f"  {'Component':<25} {'Detection Mode'}")
            lines.append(f"  {'─'*24} {'─'*20}")
            for comp in sorted(log):
                lines.append(f"  {comp:<25} {log[comp]}")
        else:
            lines.append("  (no realtime detection configured)")
        self._write(t, "\n".join(lines))

    def _add_risk_tab(self, nb, p1) -> None:
        tab = ttk.Frame(nb)
        nb.add(tab, text="  Score Breakdown  ")
        t = self._make_text(tab)
        lines = []

        HDR = f"  {'Component':<10} {'Register':<10} {'Op':<8} {'Risk':>5}  {'Security':<16} {'Detection'}"
        SEP = "  " + "─" * 80

        # ── Section 1: Non-redundant components (multiplicative security risk) ──
        sec_risks = p1.security_risk or []
        lines.append("NON-REDUNDANT COMPONENTS  —  Multiplicative Security Score")
        lines.append("  Score = Impact x Exposure x Detection x ExploitFactor / 100")
        lines.append(SEP)
        if sec_risks:
            lines.append(HDR)
            lines.append(SEP)
            for comp, reg, op, risk in sorted(sec_risks, key=lambda x: -x[3]):
                sec  = p1.security.get(comp, "—")
                log  = p1.realtime.get(comp,  "—")
                lines.append(f"  {comp:<10} {reg:<10} {op:<8} {risk:>5}  {sec:<16} {log}")
        else:
            lines.append("  (no data — check #show security_risk/4 in encoding)")

        # ── Section 2: Redundant group members (probabilistic avail risk) ──
        lines.append("")
        avail_risks = p1.avail_risk or []
        lines.append("REDUNDANT GROUP MEMBERS  —  Probabilistic Availability Score")
        lines.append("  Score = Impact x denorm_combined_prob x ExploitFactor / 1000  (floor set by Mu x 10)")
        lines.append(SEP)
        if avail_risks:
            lines.append(HDR)
            lines.append(SEP)
            for comp, reg, op, risk in sorted(avail_risks, key=lambda x: -x[3]):
                sec  = p1.security.get(comp, "—")
                log  = p1.realtime.get(comp,  "—")
                lines.append(f"  {comp:<10} {reg:<10} {op:<8} {risk:>5}  {sec:<16} {log}")
        else:
            lines.append("  (no data — check #show avail_risk/4 in encoding)")

        # ── Section 3: Per-component totals (risk budget contribution) ──
        lines.append("")
        lines.append("PER-COMPONENT SCORE TOTALS  (sum over all assets and actions)")
        lines.append(SEP)
        by_comp = p1.risk_by_component()
        if by_comp:
            lines.append(f"  {'Component':<12} {'Total Score':>10}  Bar")
            lines.append(SEP)
            for comp, r in sorted(by_comp.items(), key=lambda x: -x[1]):
                bar = "█" * min(r // max(1, max(by_comp.values()) // 20), 20)
                lines.append(f"  {comp:<12} {r:>10}  {bar}")
        else:
            lines.append("  (no risk data)")

        # ── Section 4: Per-asset-register max risk ──
        lines.append("")
        lines.append("MAX SCORE PER ASSET REGISTER  (max over read/write operations)")
        lines.append(SEP)
        per_asset = p1.max_risk_per_asset()
        if per_asset:
            max_v = max(per_asset.values()) if per_asset else 1
            lines.append(f"  {'Register':<12} {'Max Score':>8}  Bar")
            lines.append(SEP)
            for asset, r in sorted(per_asset.items(), key=lambda x: -x[1]):
                bar = "█" * min(r * 20 // max(max_v, 1), 20)
                lines.append(f"  {asset:<12} {r:>8}  {bar}")
        else:
            lines.append("  (no asset risk data)")

        lines.append("")
        lines.append(f"WEIGHTED OBJECTIVE SCORE: {p1.total_risk()}")
        lines.append(f"SUMMARY MAX-PER-ASSET SCORE: {p1.summary_total_risk()}")

        # ── Section 5: CIA dimension summary ──
        lines.append("")
        lines.append("CIA DIMENSION SUMMARY")
        lines.append(SEP)
        lines.append("  Dimension  Raw Risk  Weight  Weighted")
        lines.append(SEP)
        from ..core.solution_ranker import CIA_WEIGHTS
        action_map  = {"read": "C — Confidentiality", "write": "I — Integrity", "avail": "A — Availability"}
        dim_totals: dict = {"read": 0, "write": 0, "avail": 0}
        all_entries = list(p1.security_risk) + list(p1.avail_risk) or list(p1.new_risk)
        for _c, _a, action, risk in all_entries:
            if action in dim_totals:
                dim_totals[action] += risk
        for action, label in action_map.items():
            raw = dim_totals[action]
            w   = CIA_WEIGHTS.get(action, 1.0)
            wt  = raw * w
            lines.append(f"  {label:<28} {raw:>8}  {w:>6.1f}  {wt:>8.1f}")
        weighted_total = sum(dim_totals[a] * CIA_WEIGHTS.get(a, 1.0) for a in dim_totals)
        lines.append(SEP)
        lines.append(f"  {'WEIGHTED TOTAL':<28} {'':>8}  {'':>6}  {weighted_total:>8.1f}")
        lines.append("  (security_score uses weighted total; lower is better)")

        # Risk weights (amplification proxy)
        if p1.risk_weights:
            lines.append("")
            lines.append("TOPOLOGY PRIORITY WEIGHTS  (amplification proxy per asset)")
            lines.append(SEP)
            lines.append(f"  {'Asset':<14} {'Weight':>6}  (higher = prioritised by Phase 1 solver)")
            lines.append(SEP)
            for asset, w in sorted(p1.risk_weights.items(), key=lambda x: -x[1]):
                bar = "█" * (w // 5)
                lines.append(f"  {asset:<14} {w:>6}  {bar}")

        lines.append("")
        lines.append("INTERPRETATION NOTES")
        lines.append(SEP)
        lines.append("  - Phase 1 values are ordinal security scores used for ranking, not calibrated probabilities.")
        lines.append("  - Weighted objective score is the value optimized by the solver.")

        self._write(t, "\n".join(lines))


# ---------------------------------------------------------------------------
# Strategy Comparison Dialog
# ---------------------------------------------------------------------------

class _StrategyComparisonDialog(tk.Toplevel):
    """Side-by-side comparison table for all three strategies."""

    _FONT  = ("Courier New", 9)
    _BG    = "#0d0d1a"
    _FG    = "#c8d0e0"
    _WIN   = "#44aa44"   # "winner" highlight colour
    _LOSE  = "#884444"

    def __init__(self, parent, solutions) -> None:
        super().__init__(parent)
        self.transient(parent)
        self.title("Strategy Comparison")
        self.geometry("700x480")
        self.grab_set()

        self._solutions = solutions
        self._build(solutions)
        ttk.Button(self, text="Close", command=self.destroy).pack(pady=6)
        self.wait_window()

    def _build(self, solutions) -> None:
        frm = ttk.Frame(self, padding=8)
        frm.pack(fill=tk.BOTH, expand=True)

        headers = ["Metric"] + [
            (s.label or f"Strategy {i+1}") if s else f"Strategy {i+1}"
            for i, s in enumerate(solutions)
        ]

        # Collect rows: (metric_name, [val_str, ...], lower_is_better)
        rows = self._build_rows(solutions)

        # Render as grid
        for col, hdr in enumerate(headers):
            bg = "#1a1a3a" if col == 0 else "#111128"
            tk.Label(frm, text=hdr, font=("TkDefaultFont", 9, "bold"),
                     bg=bg, fg="#8888ee", relief="groove",
                     width=18 if col == 0 else 14,
                     anchor="w" if col == 0 else "center",
                     padx=4).grid(row=0, column=col, sticky="nsew", padx=1, pady=1)

        for r, (metric, vals, lower_better) in enumerate(rows, start=1):
            # Determine winner (best value)
            best_idx = self._best_idx(vals, lower_better)

            tk.Label(frm, text=metric, font=self._FONT,
                     bg="#111122", fg=self._FG, anchor="w",
                     width=18, padx=4).grid(row=r, column=0,
                                            sticky="nsew", padx=1, pady=1)
            for col, val in enumerate(vals, start=1):
                is_best = (col - 1) == best_idx
                is_worst = (col - 1) == self._worst_idx(vals, lower_better)
                bg = "#112211" if is_best else ("#221111" if is_worst else "#0d0d1a")
                fg = self._WIN if is_best else (self._LOSE if is_worst else self._FG)
                tk.Label(frm, text=val, font=self._FONT,
                         bg=bg, fg=fg, anchor="center",
                         width=14).grid(row=r, column=col,
                                        sticky="nsew", padx=1, pady=1)

        for col in range(len(headers)):
            frm.columnconfigure(col, weight=1)

    def _build_rows(self, solutions):
        """Return list of (name, [str_val,...], lower_is_better)."""
        rows = []

        def get(sol, *attrs, default="—"):
            obj = sol
            for a in attrs:
                obj = getattr(obj, a, None)
                if obj is None:
                    return default
            return obj

        def fmt(v, default="—"):
            if v is None or v == default:
                return default
            if isinstance(v, float):
                return f"{v:.1f}"
            return str(v)

        # SAT status
        rows.append(("SAT",
                      [("SAT" if get(s, "phase1", "satisfiable") == True else "UNSAT")
                       for s in solutions],
                      False))
        # Resource metrics
        for attr, label, lib in [
            ("total_luts",  "LUTs",    True),
            ("total_ffs",   "FFs",     True),
            ("total_dsps",  "DSPs",    True),
            ("total_bram",  "BRAMs",   True),
            ("total_power", "Power",   True),
        ]:
            rows.append((label,
                         [fmt(get(s, "phase1", attr)) for s in solutions],
                         lib))
        # Risk
        rows.append(("Objective Score",
                      [fmt(s.phase1.total_risk() if (s and s.phase1) else None)
                       for s in solutions],
                      True))
        # Phase 2
        rows.append(("P2 SAT",
                      [("SAT" if get(s, "phase2", "satisfiable") == True else "—")
                       for s in solutions],
                      False))
        rows.append(("FWs placed",
                      [str(len(get(s, "phase2", "placed_fws", default=[])))
                       for s in solutions],
                      False))
        rows.append(("PSes placed",
                      [str(len(get(s, "phase2", "placed_ps", default=[])))
                       for s in solutions],
                      False))
        rows.append(("Protected IPs",
                      [str(len(set(ip for _, ip in get(s, "phase2", "protected", default=[]))))
                       for s in solutions],
                      False))
        rows.append(("P2 Cost",
                      [fmt(get(s, "phase2", "total_cost")) for s in solutions],
                      True))
        rows.append(("Policy Precision",
                      [fmt(s.phase2.avg_policy_tightness() if (s and s.phase2) else None)
                       for s in solutions],
                      False))
        rows.append(("Policy Coverage",
                      [fmt(s.phase2.avg_effective_policy_tightness(mode="normal") if (s and s.phase2) else None)
                       for s in solutions],
                      False))
        # Phase 3
        rows.append(("Scenarios",
                      [str(len(s.scenarios)) if (s and s.scenarios) else "—"
                       for s in solutions],
                      False))
        rows.append(("Worst Scenario Score",
                      [fmt(s.worst_scenario().total_risk if (s and s.worst_scenario()) else None)
                       for s in solutions],
                      True))
        rows.append(("Avg Blast Radius",
                      [fmt(s.avg_blast_radius()) for s in solutions],
                      True))
        # Capability retention across scenarios
        def _cap_retention(sol):
            sat = [sc for sc in sol.scenarios if sc.satisfiable] if sol and sol.scenarios else []
            if not sat:
                return "—"
            scores = []
            for sc in sat:
                total = len(sc.capabilities_ok) + len(sc.capabilities_degraded) + len(sc.capabilities_lost)
                if total > 0:
                    pct = (len(sc.capabilities_ok) + 0.5 * len(sc.capabilities_degraded)) / total * 100
                    scores.append(pct)
            return fmt(sum(scores) / len(scores)) if scores else "—"

        rows.append(("Cap. Retention %",
                      [_cap_retention(s) for s in solutions],
                      False))

        def _nonfunc_count(sol):
            sat = [sc for sc in sol.scenarios if sc.satisfiable] if sol and sol.scenarios else []
            return str(sum(1 for sc in sat if sc.system_non_functional)) if sat else "—"

        rows.append(("Non-Func Scenarios",
                      [_nonfunc_count(s) for s in solutions],
                      True))

        def _function_def_count(sol):
            sat = [sc for sc in sol.scenarios if sc.satisfiable] if sol and sol.scenarios else []
            return str(sum(
                len(getattr(sc, "function_deficiencies", []) or getattr(sc, "function_findings", []))
                for sc in sat
            )) if sat else "—"

        rows.append(("Function Defs",
                      [_function_def_count(s) for s in solutions],
                      True))
        return rows

    @staticmethod
    def _numeric(vals):
        result = []
        for v in vals:
            try:
                result.append(float(v))
            except (ValueError, TypeError):
                result.append(None)
        return result

    def _best_idx(self, vals, lower_better: bool) -> int:
        nums = self._numeric(vals)
        valid = [(i, v) for i, v in enumerate(nums) if v is not None]
        if not valid:
            return -1
        return min(valid, key=lambda x: x[1] if lower_better else -x[1])[0]

    def _worst_idx(self, vals, lower_better: bool) -> int:
        nums = self._numeric(vals)
        valid = [(i, v) for i, v in enumerate(nums) if v is not None]
        if not valid:
            return -1
        return max(valid, key=lambda x: x[1] if lower_better else -x[1])[0]

