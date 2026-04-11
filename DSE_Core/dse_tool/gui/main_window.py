"""
main_window.py
==============
Root application window for the DSE Tool.

Ties together the NetworkEditor, ProgressPanel, ResultsPanel, and DSEOrchestrator
into a single coherent GUI.
"""

from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Resolve paths relative to this file
# __file__ = dse_tool/gui/main_window.py
# go up to dse_tool/ then up to project root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CLINGO_DIR = os.path.join(BASE_DIR, "Clingo")
TESTCASE_LP = os.path.join(CLINGO_DIR, "tgt_system_tc9_inst.lp")

# ---------------------------------------------------------------------------
# Recent-files preference helpers (Feature 1)
# ---------------------------------------------------------------------------

_PREFS_PATH = os.path.join(os.path.expanduser("~"), ".dse_tool_prefs.json")
_MAX_RECENT = 8


def _load_prefs() -> dict:
    try:
        import json as _json
        with open(_PREFS_PATH, encoding="utf-8") as f:
            return _json.load(f)
    except Exception:
        return {}


def _save_prefs(data: dict) -> None:
    try:
        import json as _json
        with open(_PREFS_PATH, "w", encoding="utf-8") as f:
            _json.dump(data, f, indent=2)
    except Exception:
        pass


def _add_recent_file(path: str) -> None:
    prefs = _load_prefs()
    recent = prefs.get("recent_files", [])
    if path in recent:
        recent.remove(path)
    recent.insert(0, path)
    prefs["recent_files"] = recent[:_MAX_RECENT]
    _save_prefs(prefs)


class MainWindow(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("DSE Security Analysis Tool")
        self.geometry("1400x800")
        self._orchestrator = None
        self._poll_job: str | None = None
        self._progress_queue = queue.Queue()
        self.solver_config: dict = {}  # optional solver strategy overrides

        self._build_ui()
        self._build_menu()

        # Center window on screen
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        self._build_toolbar()
        self._build_main_area()
        self._build_status_bar()

    def _build_toolbar(self) -> None:
        toolbar = ttk.Frame(self, padding=(4, 4))
        toolbar.pack(side=tk.TOP, fill=tk.X)

        self._run_btn = ttk.Button(toolbar, text="Run Analysis", command=self._start_analysis)
        self._run_btn.pack(side=tk.LEFT, padx=2)

        self._stop_btn = ttk.Button(toolbar, text="Stop", command=self._stop_analysis, state=tk.DISABLED)
        self._stop_btn.pack(side=tk.LEFT, padx=2)

        self._clear_btn = ttk.Button(toolbar, text="Clear", command=self._on_clear)
        self._clear_btn.pack(side=tk.LEFT, padx=2)

        # Load Example — single button with a pull-down selector
        load_frame = ttk.Frame(toolbar)
        load_frame.pack(side=tk.LEFT, padx=2)

        from dse_tool.gui.network_editor import NetworkEditor
        examples = NetworkEditor.available_examples()
        self._example_var = tk.StringVar(value=examples[0] if examples else "")
        self._example_combo = ttk.Combobox(
            load_frame, textvariable=self._example_var,
            values=examples, state="readonly", width=22,
        )
        self._example_combo.pack(side=tk.LEFT, padx=(0, 2))

        self._load_example_btn = ttk.Button(
            load_frame, text="Load Example", command=self._on_load_example,
        )
        self._load_example_btn.pack(side=tk.LEFT)

        self._solver_cfg_btn = ttk.Button(toolbar, text="Solver Config",
                                          command=self._edit_solver_config)
        self._solver_cfg_btn.pack(side=tk.LEFT, padx=2)

        self._show_asp_btn = ttk.Button(toolbar, text="Show ASP Facts",
                                        command=self._show_asp_facts)
        self._show_asp_btn.pack(side=tk.LEFT, padx=2)

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=6)

        self._status_label = ttk.Label(toolbar, text="Ready")
        self._status_label.pack(side=tk.LEFT, padx=4)

    def _build_main_area(self) -> None:
        paned = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # Left: Network Editor
        from dse_tool.gui.network_editor import NetworkEditor
        self._network_editor = NetworkEditor(paned)
        paned.add(self._network_editor, weight=3)

        # Right: Vertical paned window
        right_pane = ttk.PanedWindow(paned, orient=tk.VERTICAL)
        paned.add(right_pane, weight=2)

        from dse_tool.gui.progress_panel import ProgressPanel
        self._progress_panel = ProgressPanel(right_pane, self._progress_queue)
        right_pane.add(self._progress_panel, weight=1)

        from dse_tool.gui.results_panel import ResultsPanel
        self._results_panel = ResultsPanel(right_pane)
        right_pane.add(self._results_panel, weight=1)

    def _build_status_bar(self) -> None:
        statusbar = ttk.Frame(self, padding=(2, 2))
        statusbar.pack(side=tk.BOTTOM, fill=tk.X)
        self._statusbar_label = ttk.Label(statusbar, text="Ready")
        self._statusbar_label.pack(side=tk.LEFT, padx=4)

    # ------------------------------------------------------------------
    # Menu bar
    # ------------------------------------------------------------------

    def _build_menu(self) -> None:
        menubar = tk.Menu(self)
        self.configure(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open Network...", command=self._on_open_json)
        file_menu.add_command(label="Save Network...", command=self._on_save_json)
        # Recent Files cascade (Feature 1)
        recent_menu = tk.Menu(file_menu, tearoff=0)
        file_menu.add_cascade(label="Recent Files", menu=recent_menu)
        self._recent_menu = recent_menu
        self._populate_recent_menu()
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close)

        # Edit menu
        edit_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Edit", menu=edit_menu)
        edit_menu.add_command(label="Clear All", command=self._on_clear)
        edit_menu.add_command(label="Solver Config...", command=self._edit_solver_config)

        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Show ASP Facts...", command=self._show_asp_facts)
        # CSV export (Feature 2)
        view_menu.add_separator()
        view_menu.add_command(label="Export Results as CSV...", command=self._export_csv)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self._on_about)

    # ------------------------------------------------------------------
    # Solver config dialog (Group 5a)
    # ------------------------------------------------------------------

    def _edit_solver_config(self) -> None:
        dlg = _SolverConfigDialog(self, self.solver_config)
        if dlg.result is not None:
            self.solver_config = dlg.result

    def _show_asp_facts(self) -> None:
        model = self._network_editor.get_network_model()
        if not model:
            messagebox.showwarning("No Network", "Please load or draw a network first.")
            return
        _ASPFactsDialog(self, model)

    # ------------------------------------------------------------------
    # Analysis control
    # ------------------------------------------------------------------

    def _start_analysis(self) -> None:
        """Start the DSE orchestrator in a background daemon thread."""
        if self._orchestrator is not None and not self._orchestrator.done:
            messagebox.showinfo("Already Running", "Analysis is already in progress.")
            return

        network_model = self._network_editor.get_network_model()
        if not network_model:
            messagebox.showwarning("No Network", "Please load or draw a network before running analysis.")
            return

        # Topology validation
        warnings = self._network_editor.validate_topology()
        if warnings:
            msg = "Topology issues detected:\n\n" + "\n".join(f"  - {w}" for w in warnings)
            msg += "\n\nContinue with analysis anyway?"
            if not messagebox.askyesno("Topology Warnings", msg):
                return

        # Parse warnings back to per-node dict for canvas overlay
        warn_by_node: dict = {}
        for w in warnings:
            import re as _re
            m = _re.search(r"'([^']+)'", w)
            if m:
                node_name = m.group(1)
                warn_by_node.setdefault(node_name, []).append(w)
        self._network_editor.set_validation_warnings(warn_by_node)

        # Reset panels
        self._progress_panel.reset_indicators()
        self._progress_panel.clear_log()
        self._progress_panel.start_timer()
        self._results_panel.clear()
        # Clear previous overlays
        self._network_editor.set_analysis_results(None)

        # Create orchestrator
        from dse_tool.agents.orchestrator import DSEOrchestrator
        self._orchestrator = DSEOrchestrator(
            network_model=network_model,
            clingo_files_dir=CLINGO_DIR,
            testcase_lp=TESTCASE_LP,
            progress_queue=self._progress_queue,
            full_phase3=False,
            phase_timeout=60,
            solver_config=self.solver_config,
        )

        # Start in daemon thread
        thread = threading.Thread(target=self._orchestrator.run, daemon=True)
        thread.start()

        # Update UI state
        self._run_btn.configure(state=tk.DISABLED)
        self._stop_btn.configure(state=tk.NORMAL)
        self._set_status("Running...")

        # Start polling
        self._poll_orchestrator()

    def _stop_analysis(self) -> None:
        """Request the orchestrator to stop."""
        if self._orchestrator:
            self._orchestrator.stop()
        self._stop_btn.configure(state=tk.DISABLED)
        self._set_status("Stopping...")

    def _poll_orchestrator(self) -> None:
        """Poll the orchestrator for completion/errors and update the UI."""
        if self._orchestrator is None:
            return

        if self._orchestrator.done:
            self._progress_panel.stop_timer()
            self._stop_btn.configure(state=tk.DISABLED)
            self._run_btn.configure(state=tk.NORMAL)

            if self._orchestrator.error:
                self._set_status(f"Error: {self._orchestrator.error[:80]}")
                self._progress_panel.post("ERROR", f"Analysis error:\n{self._orchestrator.error}")
            elif self._orchestrator.solutions:
                self._show_results(self._orchestrator.solutions)
                self._set_status("Complete")
            else:
                self._set_status("No solutions")
            self._orchestrator = None
            return

        if self._orchestrator.error:
            self._progress_panel.stop_timer()
            self._set_status(f"Error: {self._orchestrator.error[:80]}")
            self._stop_btn.configure(state=tk.DISABLED)
            self._run_btn.configure(state=tk.NORMAL)
            self._orchestrator = None
            return

        # Schedule next poll
        self._poll_job = self.after(200, self._poll_orchestrator)

    def _show_results(self, solutions) -> None:
        """Display results, update phase indicators, and wire overlays."""
        self._progress_panel.post("SUCCESS", "=== Results Received ===")
        self._progress_panel.set_phase_state(1, "done")
        self._progress_panel.set_phase_state(2, "done")
        self._progress_panel.set_phase_state(3, "done")
        self._results_panel.set_results(solutions)
        if self._orchestrator and getattr(self._orchestrator, "report_text", ""):
            self._results_panel.set_report_text(self._orchestrator.report_text)
        # Pass system resource caps so Executive Summary can use them
        if self._orchestrator and hasattr(self._orchestrator, "network_model"):
            self._results_panel.set_system_caps(
                self._orchestrator.network_model.system_caps
            )
        self._check_resource_budgets(solutions)
        # Clear validation warning badges now that analysis completed successfully
        self._network_editor.set_validation_warnings({})

        # Build overlay results dict keyed by strategy name
        overlay_results: dict = {}
        for sol in solutions:
            if sol and sol.phase1 is not None:
                # Pass the full SolutionResult so the overlay can access phase2 too
                overlay_results[sol.strategy] = sol
        if overlay_results:
            self._network_editor.set_analysis_results(overlay_results)

    # ------------------------------------------------------------------
    # Toolbar actions
    # ------------------------------------------------------------------

    def _on_clear(self) -> None:
        self._progress_panel.reset_indicators()
        self._progress_panel.clear_log()
        self._progress_panel.stop_timer()
        self._results_panel.clear()
        self._set_status("Ready")

    def _on_load_example(self) -> None:
        """Load the selected example topology from the combo box."""
        name = self._example_var.get()
        if not name:
            messagebox.showwarning("Load Example", "Select an example topology first.")
            return
        try:
            self._network_editor.load_example(name)
            self._set_status(f"{name} topology loaded")
        except Exception as e:
            messagebox.showerror("Load Error", str(e))

    # Backwards-compatible convenience methods
    def _on_load_tc9(self) -> None:
        self._network_editor.load_tc9_example()
        self._set_status("TC9 topology loaded")

    def _on_load_refsoc(self) -> None:
        self._network_editor.load_reference_soc()
        self._set_status("SecureSoC-16 reference topology loaded")

    def _on_open_json(self) -> None:
        path = filedialog.askopenfilename(
            title="Open Network Topology",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialdir=BASE_DIR,
        )
        if path:
            try:
                import json
                with open(path) as f:
                    data = json.load(f)
                self._network_editor.load_from_json(data)
                _add_recent_file(path)
                self._populate_recent_menu()
                self._set_status(f"Loaded: {os.path.basename(path)}")
            except Exception as e:
                messagebox.showerror("Load Error", str(e))

    def _on_save_json(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Save Network Topology",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialdir=BASE_DIR,
        )
        if path:
            try:
                import json
                data = self._network_editor.save_to_json()
                with open(path, "w") as f:
                    json.dump(data, f, indent=2)
                _add_recent_file(path)
                self._populate_recent_menu()
                self._set_status(f"Saved: {os.path.basename(path)}")
            except Exception as e:
                messagebox.showerror("Save Error", str(e))

    # ------------------------------------------------------------------
    # Recent-files helpers (Feature 1)
    # ------------------------------------------------------------------

    def _populate_recent_menu(self) -> None:
        self._recent_menu.delete(0, tk.END)
        recent = _load_prefs().get("recent_files", [])
        if not recent:
            self._recent_menu.add_command(label="(none)", state="disabled")
            return
        for path in recent:
            label = os.path.basename(path)
            self._recent_menu.add_command(
                label=label,
                command=lambda p=path: self._open_recent(p))

    def _open_recent(self, path: str) -> None:
        if not os.path.exists(path):
            messagebox.showerror("File Not Found", f"File not found:\n{path}")
            return
        try:
            import json
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            self._network_editor.load_from_json(data)
            _add_recent_file(path)
            self._populate_recent_menu()
            self._set_status(f"Loaded: {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Load Error", str(e))

    # ------------------------------------------------------------------
    # CSV export (Feature 2)
    # ------------------------------------------------------------------

    def _export_csv(self) -> None:
        solutions = getattr(self._orchestrator, "solutions", None) if self._orchestrator else None
        # Fall back to results stored in results_panel
        if not solutions:
            solutions = getattr(self._results_panel, "_solutions", None)
        if not solutions:
            messagebox.showwarning("No Results", "Run analysis first to generate results.")
            return
        path = filedialog.asksaveasfilename(
            title="Export Results as CSV",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All", "*.*")],
            initialdir=BASE_DIR,
        )
        if not path:
            return
        try:
            from ..core.comparison import export_csv
            caps = {}
            if self._orchestrator and hasattr(self._orchestrator, "network_model"):
                caps = self._orchestrator.network_model.system_caps
            export_csv(
                solutions, path,
                max_luts=caps.get("max_luts", 0),
                max_power=caps.get("max_power", 0),
                max_ffs=caps.get("max_ffs", 0),
            )
            self._set_status(f"Exported: {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    # ------------------------------------------------------------------
    # Resource budget warnings (Feature 3)
    # ------------------------------------------------------------------

    def _check_resource_budgets(self, solutions) -> None:
        """Warn if any strategy exceeds the system resource caps."""
        caps = getattr(self._network_editor, "system_caps", {})
        if not caps:
            return
        cap_map = {
            "total_luts":  "max_luts",
            "total_ffs":   "max_ffs",
            "total_dsps":  "max_dsps",
            "total_bram":  "max_bram",
            "total_power": "max_power",
        }
        overruns = []
        for sol in solutions:
            if not sol or not sol.phase1 or not sol.phase1.satisfiable:
                continue
            p1 = sol.phase1
            label = sol.label or sol.strategy
            for p1_attr, cap_key in cap_map.items():
                cap = caps.get(cap_key)
                val = getattr(p1, p1_attr, None)
                if cap and val and val > cap:
                    overruns.append(
                        f"  {label}: {p1_attr.replace('total_','')} "
                        f"= {val} > budget {cap}"
                    )
        if overruns:
            msg = "Resource budget exceeded in solution(s):\n\n" + "\n".join(overruns)
            msg += "\n\nConsider adjusting FPGA Config or solver strategy."
            messagebox.showwarning("Resource Budget Warning", msg)

    # ------------------------------------------------------------------
    # Status helpers
    # ------------------------------------------------------------------

    def _set_status(self, text: str) -> None:
        self._statusbar_label.config(text=text)
        self._status_label.config(text=text)

    # ------------------------------------------------------------------
    # Menu actions
    # ------------------------------------------------------------------

    @staticmethod
    def _on_about() -> None:
        messagebox.showinfo(
            "About DSE Security Analysis Tool",
            "DSE Security Analysis Tool\n\n"
            "Design Space Exploration for Security-enabled SoC Topologies.\n\n"
            "Coordinates Phase 1 (security/power), Phase 2 (ZTA policy), "
            "and Phase 3 (resilience) analysis across three strategy variants.\n\n"
            "Phase 1 and Phase 3 values are design-time proxy scores, not calibrated "
            "probabilities. Phase 3 covers the modeled scenario set, not all possible "
            "attacks. Exact closed-loop Phase 2 is recommended for high-assurance studies. "
            "Phase 3 uses ASP / Clingo by default; the Python fast backend is optional.",
        )

    # ------------------------------------------------------------------
    # Window events
    # ------------------------------------------------------------------

    def _on_close(self) -> None:
        if self._poll_job:
            self.after_cancel(self._poll_job)
        if self._orchestrator and not self._orchestrator.done:
            self._orchestrator.stop()
        self.destroy()


# ---------------------------------------------------------------------------
# Solver Config dialog (Group 5a)
# ---------------------------------------------------------------------------

from ..agents.phase1_agent import STRATEGY_EXTRA as _DEFAULT_STRATEGY_EXTRA


class _SolverConfigDialog(tk.Toplevel):
    """
    Dialog for editing per-strategy ASP objective overrides.

    The solver_config dict has the key 'strategy_overrides' which maps
    strategy name -> extra ASP facts string.  If empty / not present the
    Phase1Agent falls back to its built-in STRATEGY_EXTRA dict.
    """

    STRATEGIES = ["max_security", "min_resources", "balanced"]
    PHASE2_OBJECTIVES = [
        ("Default Cost Only", ""),
        ("Heuristic Control Plane", "control_plane"),
        ("Exact Closed Loop (Phase 3)", "phase3_closed_loop"),
    ]
    PHASE3_BACKENDS = [
        ("ASP / Clingo (Default)", "asp"),
        ("Python Fast Evaluator", "python"),
    ]

    def __init__(self, parent: tk.Widget, config: dict) -> None:
        super().__init__(parent)
        self.transient(parent)
        self.title("Solver Strategy Configuration")
        self.grab_set()
        self.result: dict | None = None

        overrides: dict = dict(config.get("strategy_overrides", {}))
        self._base_config = dict(config)

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frm,
                  text="Override per-strategy ASP objectives (leave blank to use defaults):",
                  wraplength=500).pack(anchor="w", pady=(0, 6))

        phase2_row = ttk.Frame(frm)
        phase2_row.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(phase2_row, text="Phase 2 objective:", width=18).pack(side=tk.LEFT)
        phase2_current = str(config.get("phase2_objective", "") or "")
        self._phase2_var = tk.StringVar()
        phase2_labels = [label for label, _ in self.PHASE2_OBJECTIVES]
        reverse_map = {value: label for label, value in self.PHASE2_OBJECTIVES}
        self._phase2_var.set(reverse_map.get(phase2_current, phase2_labels[0]))
        self._phase2_combo = ttk.Combobox(
            phase2_row,
            textvariable=self._phase2_var,
            values=phase2_labels,
            state="readonly",
            width=28,
        )
        self._phase2_combo.pack(side=tk.LEFT, padx=(0, 8))
        ttk.Label(
            frm,
            text=(
                "Phase 2 modes: default cost-only, heuristic control-plane proxy, "
                "or exact closed-loop evaluation using actual Phase 3 scenarios. "
                "Use exact closed-loop for safety-critical or high-assurance studies."
            ),
            wraplength=500,
        ).pack(anchor="w", pady=(0, 8))

        phase3_row = ttk.Frame(frm)
        phase3_row.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(phase3_row, text="Phase 3 backend:", width=18).pack(side=tk.LEFT)
        phase3_current = str(config.get("phase3_backend", "asp") or "asp")
        self._phase3_var = tk.StringVar()
        phase3_labels = [label for label, _ in self.PHASE3_BACKENDS]
        phase3_reverse_map = {value: label for label, value in self.PHASE3_BACKENDS}
        self._phase3_var.set(phase3_reverse_map.get(phase3_current, phase3_labels[0]))
        self._phase3_combo = ttk.Combobox(
            phase3_row,
            textvariable=self._phase3_var,
            values=phase3_labels,
            state="readonly",
            width=28,
        )
        self._phase3_combo.pack(side=tk.LEFT, padx=(0, 8))
        ttk.Label(
            frm,
            text=(
                "Phase 3 uses ASP / Clingo by default. Select the Python fast evaluator "
                "only when you explicitly want the approximate fast path."
            ),
            wraplength=500,
        ).pack(anchor="w", pady=(0, 8))

        self._text_widgets: dict = {}
        nb = ttk.Notebook(frm)
        nb.pack(fill=tk.BOTH, expand=True)

        for strategy in self.STRATEGIES:
            tab = ttk.Frame(nb)
            nb.add(tab, text=strategy.replace("_", " ").title())

            ttk.Label(tab, text=f"Extra ASP facts / objectives for '{strategy}':").pack(
                anchor="w", pady=4, padx=4)
            tw = tk.Text(tab, width=60, height=8, font=("Courier New", 9))
            default_text = overrides.get(
                strategy,
                _DEFAULT_STRATEGY_EXTRA.get(strategy, "")
            )
            tw.insert("1.0", default_text)
            tw.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
            sb = ttk.Scrollbar(tab, orient=tk.VERTICAL, command=tw.yview)
            tw.configure(yscrollcommand=sb.set)
            sb.pack(side=tk.RIGHT, fill=tk.Y)
            self._text_widgets[strategy] = tw

        btn_row = ttk.Frame(frm)
        btn_row.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(btn_row, text="OK",             command=self._ok).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="Reset Defaults", command=self._reset).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="Cancel",         command=self.destroy).pack(side=tk.LEFT)
        self.wait_window()

    def _ok(self) -> None:
        new_overrides = {}
        for strategy, tw in self._text_widgets.items():
            text = tw.get("1.0", tk.END).strip()
            if text:
                new_overrides[strategy] = text + "\n"
        objective_map = {label: value for label, value in self.PHASE2_OBJECTIVES}
        phase2_objective = objective_map.get(self._phase2_var.get(), "")
        phase3_map = {label: value for label, value in self.PHASE3_BACKENDS}
        phase3_backend = phase3_map.get(self._phase3_var.get(), "asp")
        result = dict(self._base_config)
        if new_overrides:
            result["strategy_overrides"] = new_overrides
        else:
            result.pop("strategy_overrides", None)
        if phase2_objective:
            result["phase2_objective"] = phase2_objective
        else:
            result.pop("phase2_objective", None)
        result["phase3_backend"] = phase3_backend
        self.result = result
        self.destroy()

    def _reset(self) -> None:
        for strategy, tw in self._text_widgets.items():
            tw.delete("1.0", tk.END)
            tw.insert("1.0", _DEFAULT_STRATEGY_EXTRA.get(strategy, ""))


# ---------------------------------------------------------------------------
# ASP Facts viewer dialog
# ---------------------------------------------------------------------------

import re as _re
import collections as _collections


class _ASPFactsDialog(tk.Toplevel):
    """
    Shows the raw ASP facts generated from the current network topology.

    Layout
    ------
    Top bar  : search entry + Prev/Next + match counter
    Notebook : "Facts" tab (full text) | "Summary" tab (fact-type counts + warnings)
    Bottom   : Copy All | Save... | Close
    """

    _FONT = ("Courier New", 9)
    _BG   = "#0d0d1a"
    _FG   = "#c8d0e0"
    _HL   = "#ffdd44"   # search highlight
    _HL_CURRENT = "#ff8800"

    def __init__(self, parent: tk.Widget, model) -> None:
        super().__init__(parent)
        self.transient(parent)
        self.title("ASP Facts — Generated from Canvas Topology")
        self.geometry("860x640")
        self.grab_set()

        from dse_tool.core.asp_generator import ASPGenerator
        self._asp_text = ASPGenerator(model).generate()
        self._model    = model
        self._search_matches: list = []
        self._match_idx: int = 0

        self._build_ui()
        self._populate_summary()
        self.wait_window()

    # ------------------------------------------------------------------ build

    def _build_ui(self) -> None:
        # ── Search bar ────────────────────────────────────────────────────
        search_bar = ttk.Frame(self, padding=(6, 4))
        search_bar.pack(side=tk.TOP, fill=tk.X)

        ttk.Label(search_bar, text="Search:").pack(side=tk.LEFT)
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._do_search())
        search_entry = ttk.Entry(search_bar, textvariable=self._search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=4)
        search_entry.bind("<Return>",       lambda _: self._next_match(+1))
        search_entry.bind("<Shift-Return>", lambda _: self._next_match(-1))

        self._prev_btn = ttk.Button(search_bar, text="◀", width=3,
                                    command=lambda: self._next_match(-1))
        self._prev_btn.pack(side=tk.LEFT, padx=1)
        self._next_btn = ttk.Button(search_bar, text="▶", width=3,
                                    command=lambda: self._next_match(+1))
        self._next_btn.pack(side=tk.LEFT, padx=1)
        self._match_lbl = ttk.Label(search_bar, text="", width=14)
        self._match_lbl.pack(side=tk.LEFT, padx=6)

        ttk.Label(search_bar, text="(Enter = next  Shift+Enter = prev)",
                  foreground="#888888").pack(side=tk.LEFT, padx=4)

        # ── Notebook ──────────────────────────────────────────────────────
        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        # Tab 1: raw facts
        facts_tab = ttk.Frame(nb)
        nb.add(facts_tab, text="  Facts  ")
        self._text = tk.Text(facts_tab, font=self._FONT, bg=self._BG, fg=self._FG,
                             insertbackground=self._FG, wrap=tk.NONE, undo=False)
        vsb = ttk.Scrollbar(facts_tab, orient=tk.VERTICAL,   command=self._text.yview)
        hsb = ttk.Scrollbar(facts_tab, orient=tk.HORIZONTAL, command=self._text.xview)
        self._text.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        vsb.pack(side=tk.RIGHT,  fill=tk.Y)
        self._text.pack(fill=tk.BOTH, expand=True)

        # Syntax colouring tags
        self._text.tag_configure("comment",   foreground="#557766")
        self._text.tag_configure("fact_name", foreground="#88aaff")
        self._text.tag_configure("string",    foreground="#ffaa55")
        self._text.tag_configure("number",    foreground="#aaffaa")
        self._text.tag_configure("search_hl", background=self._HL,         foreground="#000000")
        self._text.tag_configure("search_cur",background=self._HL_CURRENT, foreground="#000000")

        self._insert_facts()

        # Tab 2: summary
        summary_tab = ttk.Frame(nb)
        nb.add(summary_tab, text="  Summary  ")
        self._summary_text = tk.Text(summary_tab, font=self._FONT,
                                     bg=self._BG, fg=self._FG,
                                     wrap=tk.WORD, state=tk.DISABLED)
        ssb = ttk.Scrollbar(summary_tab, orient=tk.VERTICAL,
                            command=self._summary_text.yview)
        self._summary_text.configure(yscrollcommand=ssb.set)
        ssb.pack(side=tk.RIGHT, fill=tk.Y)
        self._summary_text.pack(fill=tk.BOTH, expand=True)

        # ── Bottom buttons ────────────────────────────────────────────────
        btn_row = ttk.Frame(self, padding=(6, 4))
        btn_row.pack(side=tk.BOTTOM, fill=tk.X)
        ttk.Button(btn_row, text="Copy All", command=self._copy_all).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="Save...",  command=self._save).pack(side=tk.LEFT, padx=2)
        ttk.Label(btn_row,
                  text=f"{len(self._asp_text.splitlines())} lines  "
                       f"{len(self._asp_text):,} chars",
                  foreground="#888888").pack(side=tk.LEFT, padx=8)
        ttk.Button(btn_row, text="Close", command=self.destroy).pack(side=tk.RIGHT, padx=4)

    # ------------------------------------------------------------------ facts

    def _insert_facts(self) -> None:
        self._text.configure(state=tk.NORMAL)
        self._text.delete("1.0", tk.END)
        self._text.insert("1.0", self._asp_text)
        self._apply_syntax()
        self._text.configure(state=tk.DISABLED)

    def _apply_syntax(self) -> None:
        """Simple regex-based colouring for ASP/LP syntax."""
        content = self._asp_text
        # Comments  (% ...)
        for m in _re.finditer(r'%[^\n]*', content):
            self._tag_range("comment", m.start(), m.end())
        # Fact names  (word before '(')
        for m in _re.finditer(r'\b([a-z_][a-z0-9_]*)\s*\(', content):
            self._tag_range("fact_name", m.start(1), m.end(1))
        # Strings  ("..." or atoms starting with lowercase already covered above)
        for m in _re.finditer(r'"[^"]*"', content):
            self._tag_range("string", m.start(), m.end())
        # Numbers
        for m in _re.finditer(r'\b\d+\b', content):
            self._tag_range("number", m.start(), m.end())

    def _tag_range(self, tag: str, start_char: int, end_char: int) -> None:
        """Convert absolute character offsets to Tkinter Text indices."""
        s = f"1.0 + {start_char} chars"
        e = f"1.0 + {end_char} chars"
        self._text.tag_add(tag, s, e)

    # ------------------------------------------------------------------ summary

    def _populate_summary(self) -> None:
        lines = self._asp_text.splitlines()
        counts: dict = _collections.Counter()
        for line in lines:
            line = line.strip()
            if not line or line.startswith("%"):
                continue
            m = _re.match(r'([a-z_][a-z0-9_]*)\s*\(', line)
            if m:
                counts[m.group(1)] += 1

        model = self._model

        # Build warning list
        warnings: list[str] = []
        if counts.get("component", 0) == 0:
            warnings.append("No component() facts — nothing to solve")
        if counts.get("asset", 0) == 0:
            warnings.append("No asset() facts — security analysis may be trivial")
        if counts.get("allow_rule", 0) == 0:
            warnings.append("No allow_rule() facts — access needs not declared")
        if counts.get("cand_fw", 0) == 0:
            warnings.append("No cand_fw() facts — no firewall candidates; Phase 2 may be UNSAT")
        if counts.get("cand_ps", 0) == 0:
            warnings.append("No cand_ps() facts — no policy server candidates; Phase 2 may be UNSAT")
        if counts.get("on_path", 0) == 0:
            warnings.append("No on_path() facts — ZTA protection paths are empty")
        if counts.get("trust_anchor", 0) == 0:
            warnings.append("No trust_anchor() facts — no hardware roots of trust declared")

        out: list[str] = []
        out.append("=" * 56)
        out.append(" ASP FACT SUMMARY")
        out.append("=" * 56)
        out.append(f"  Total lines     : {len(lines)}")
        out.append(f"  Non-blank/comment: {sum(counts.values())}")
        out.append("")
        out.append("── Fact counts ──────────────────────────────────────")
        for name, cnt in sorted(counts.items(), key=lambda x: -x[1]):
            out.append(f"  {name:<28} {cnt:>4}")
        out.append("")
        if warnings:
            out.append("── Warnings ─────────────────────────────────────────")
            for w in warnings:
                out.append(f"  ⚠  {w}")
            out.append("")
        else:
            out.append("  No warnings — topology looks complete.")
            out.append("")
        out.append("── Model at a glance ────────────────────────────────")
        out.append(f"  Components : {len(getattr(model, 'components', []))}")
        out.append(f"  Links      : {len(getattr(model, 'links', []))}")
        out.append(f"  Assets     : {len(getattr(model, 'assets', []))}")
        out.append(f"  AccessNeeds: {len(getattr(model, 'access_needs', []))}")
        out.append(f"  Cand FWs   : {len(getattr(model, 'cand_fws', []))}")
        out.append(f"  Cand PSes  : {len(getattr(model, 'cand_ps', []))}")
        out.append(f"  On-paths   : {len(getattr(model, 'on_paths', []))}")
        out.append(f"  Redund grps: {len(getattr(model, 'redundancy_groups', []))}")
        out.append(f"  Services   : {len(getattr(model, 'services', []))}")
        out.append(f"  Scenarios  : {len(getattr(model, 'scenarios', []))}")
        out.append("=" * 56)

        body = "\n".join(out)
        self._summary_text.configure(state=tk.NORMAL)
        self._summary_text.delete("1.0", tk.END)
        self._summary_text.insert("1.0", body)
        # Colour warnings red
        for m in _re.finditer(r'⚠.*', body):
            s = f"1.0 + {m.start()} chars"
            e = f"1.0 + {m.end()} chars"
            self._summary_text.tag_add("warn", s, e)
        self._summary_text.tag_configure("warn", foreground="#ff6666")
        self._summary_text.configure(state=tk.DISABLED)

    # ------------------------------------------------------------------ search

    def _do_search(self) -> None:
        self._text.tag_remove("search_hl",  "1.0", tk.END)
        self._text.tag_remove("search_cur", "1.0", tk.END)
        self._search_matches = []
        self._match_idx = 0
        term = self._search_var.get()
        if not term:
            self._match_lbl.config(text="")
            return
        content = self._asp_text
        for m in _re.finditer(_re.escape(term), content, _re.IGNORECASE):
            self._search_matches.append((m.start(), m.end()))
        total = len(self._search_matches)
        if total == 0:
            self._match_lbl.config(text="no matches")
            return
        self._match_lbl.config(text=f"1 / {total}")
        self._text.configure(state=tk.NORMAL)
        for s, e in self._search_matches:
            self._text.tag_add("search_hl",
                               f"1.0 + {s} chars", f"1.0 + {e} chars")
        self._text.configure(state=tk.DISABLED)
        self._highlight_current()

    def _next_match(self, direction: int) -> None:
        if not self._search_matches:
            return
        self._match_idx = (self._match_idx + direction) % len(self._search_matches)
        self._match_lbl.config(text=f"{self._match_idx + 1} / {len(self._search_matches)}")
        self._highlight_current()

    def _highlight_current(self) -> None:
        self._text.tag_remove("search_cur", "1.0", tk.END)
        if not self._search_matches:
            return
        s, e = self._search_matches[self._match_idx]
        si = f"1.0 + {s} chars"
        ei = f"1.0 + {e} chars"
        self._text.tag_add("search_cur", si, ei)
        self._text.see(si)

    # ------------------------------------------------------------------ export

    def _copy_all(self) -> None:
        self.clipboard_clear()
        self.clipboard_append(self._asp_text)

    def _save(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Save ASP Facts",
            defaultextension=".lp",
            filetypes=[("Logic Program", "*.lp"), ("Text", "*.txt"), ("All", "*.*")],
        )
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self._asp_text)
            except OSError as exc:
                messagebox.showerror("Save Error", str(exc))
