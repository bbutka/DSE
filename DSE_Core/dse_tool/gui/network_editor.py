"""
network_editor.py
=================
Canvas-based interactive SoC network topology editor.

Supports:
- Drag-to-move nodes
- Right-click context menu (Edit, Delete, Add Link, Copy, Paste)
- Double-click to edit node properties
- Add/delete components and links
- Redundancy group highlighting
- Trust domain colour tinting
- TC9 example preload
- JSON save/load
- ASP facts export
- Access needs / services / FPGA config / mission phases / policy exceptions
- Phase 3 scenario editing
- Undo/Redo (Ctrl+Z / Ctrl+Y)
- Zoom (Ctrl+= / Ctrl+-)
- Grid snap (20 px)
- Copy/paste nodes
- Topology validation
- Analysis results overlay (risk halos, placement badges, feature labels)
"""

from __future__ import annotations

import copy
import json
import math
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from typing import Dict, List, Optional, Tuple

from ..core.asp_generator import (
    NetworkModel, Component, Asset, RedundancyGroup, Service,
    AccessNeed, ASPGenerator, make_opentitan_network, make_pixhawk6x_platform,
    make_pixhawk6x_uav_network, make_pixhawk6x_uav_dual_ps_network,
    make_tc9_network, make_reference_soc
)


# ---------------------------------------------------------------------------
# Visual constants
# ---------------------------------------------------------------------------

NODE_TYPE_STYLES: Dict[str, dict] = {
    "processor":     {"fill": "#3a7dda", "outline": "#1a5db0", "shape": "roundrect"},
    "dma":           {"fill": "#2db050", "outline": "#1a7035", "shape": "rect"},
    "ip_core":       {"fill": "#e07b00", "outline": "#a05000", "shape": "oval"},
    "bus":           {"fill": "#888888", "outline": "#555555", "shape": "rect"},
    "policy_server": {"fill": "#9040cc", "outline": "#602090", "shape": "diamond"},
    "firewall":      {"fill": "#cc3030", "outline": "#901010", "shape": "hexagon"},
}

DOMAIN_TINT = {
    "low":  "#0000cc",
    "high": "#cc0000",
}

CANVAS_BG   = "#1a1a2e"
GRID_COLOUR = "#2a2a3e"

NODE_W, NODE_H = 90, 42
BUS_W,  BUS_H  = 120, 20

PYNQ_Z2_CAPS = {
    "max_power":      15000,
    "max_luts":       53200,
    "max_ffs":       106400,
    "max_dsps":         220,
    "max_lutram":     17400,
    "max_bufgs":         32,
    "max_bram":         140,
    "max_security_risk": 50,   # multiplicative cap: non-redundant components
    "max_avail_risk":    20,   # probabilistic cap: redundant groups
    "redundancy_beta_pct": 0,  # common-cause correction: 0 = independence-only
    "max_attack_depth":   5,
}


# ---------------------------------------------------------------------------
# Node data
# ---------------------------------------------------------------------------

class NodeData:
    """In-memory representation of a single canvas node."""

    def __init__(
        self,
        name: str,
        comp_type: str = "ip_core",
        x: float = 200.0,
        y: float = 200.0,
        domain: str = "high",
        impact_read: int = 3,
        impact_write: int = 3,
        impact_avail: int = 0,
        exploitability: int = 3,
        latency_read: int = 1000,
        latency_write: int = 1000,
        has_rot: bool = False,
        has_sboot: bool = False,
        has_attest: bool = False,
        is_critical: bool = False,
        is_safety_critical: bool = False,
        direction: str = "bidirectional",
        extra_assets: Optional[List[dict]] = None,
        fw_cost: int = 150,
        ps_cost: int = 100,
    ) -> None:
        self.name          = name
        self.comp_type     = comp_type
        self.x             = x
        self.y             = y
        self.domain        = domain
        self.impact_read   = impact_read
        self.impact_write  = impact_write
        self.impact_avail  = impact_avail
        self.exploitability = exploitability
        self.latency_read  = latency_read
        self.latency_write = latency_write
        self.has_rot       = has_rot
        self.has_sboot     = has_sboot
        self.has_attest    = has_attest
        self.is_critical   = is_critical
        self.is_safety_critical = is_safety_critical
        self.direction     = direction
        self.extra_assets: List[dict] = extra_assets if extra_assets is not None else []
        self.fw_cost       = fw_cost
        self.ps_cost       = ps_cost

        # Canvas item IDs (set after draw)
        self.canvas_id: Optional[int] = None
        self.label_id:  Optional[int] = None

    def to_component(self) -> Component:
        """Convert to a core Component for ASP generation."""
        is_master    = self.comp_type in ("processor", "dma")
        is_receiver  = self.comp_type not in ("bus", "processor", "dma",
                                               "policy_server", "firewall")
        return Component(
            name=self.name,
            comp_type=self.comp_type,
            domain=self.domain,
            impact_read=self.impact_read,
            impact_write=self.impact_write,
            impact_avail=self.impact_avail,
            exploitability=self.exploitability,
            latency_read=self.latency_read,
            latency_write=self.latency_write,
            has_rot=self.has_rot,
            has_sboot=self.has_sboot,
            has_attest=self.has_attest,
            is_master=is_master,
            is_receiver=is_receiver,
            is_critical=self.is_critical,
            is_safety_critical=self.is_safety_critical,
            direction=self.direction,
        )


# ---------------------------------------------------------------------------
# Link data
# ---------------------------------------------------------------------------

class LinkData:
    """Represents a directed link between two named nodes."""

    def __init__(self, src: str, dst: str) -> None:
        self.src       = src
        self.dst       = dst
        self.canvas_id: Optional[int] = None


# ---------------------------------------------------------------------------
# Network Editor
# ---------------------------------------------------------------------------

class NetworkEditor(ttk.Frame):
    """
    Interactive canvas-based SoC network topology editor.

    Parameters
    ----------
    parent : tk.Widget
        Parent container.
    on_model_changed : callable | None
        Called whenever the topology changes.
    """

    def __init__(
        self,
        parent: tk.Widget,
        on_model_changed=None,
        **kwargs,
    ) -> None:
        super().__init__(parent, **kwargs)
        self.on_model_changed = on_model_changed

        self.nodes:       Dict[str, NodeData]   = {}
        self.links:       List[LinkData]        = []
        self.redund_groups: List[Dict]          = []
        self.access_needs:  List[AccessNeed]    = []
        self.services:      List[Service]       = []
        self.system_caps:   dict                = dict(PYNQ_Z2_CAPS)
        self.mission_phases: List[str]          = ["operational", "maintenance", "emergency"]
        self.policy_exceptions: List[dict]      = []
        self.scenarios:     List[dict]          = []

        # Undo/redo
        self._history:     List[str] = []
        self._history_pos: int       = -1

        # Zoom
        self._zoom: float = 1.0

        # Copy/paste
        self._clipboard: Optional[NodeData] = None

        # Model-level overrides (populated by _load_model / load presets)
        self._model_trust_anchors:      dict        = {}
        self._model_roles:              List[tuple] = []
        self._model_policy_exceptions:  list        = []
        self._model_capabilities:       list        = []

        # Analysis results overlay
        self._analysis_results: Optional[dict] = None
        self._last_p2  = None   # best Phase2Result, set by set_analysis_results
        self._show_overlay:    tk.BooleanVar = tk.BooleanVar(value=True)
        self._show_blast_radii: tk.BooleanVar = tk.BooleanVar(value=False)

        # Validation warning overlay: maps node_name -> list[str]
        self._warn_nodes: dict = {}

        self._drag_node:    Optional[str]      = None
        self._drag_ox:      float              = 0.0
        self._drag_oy:      float              = 0.0
        self._link_src:     Optional[str]      = None
        self._selected:     Optional[str]      = None
        self._redund_sel:   List[str]          = []

        # Rubber-band multi-select (Feature 2)
        self._selected_nodes: set = set()   # set of node names
        self._rb_start: tuple  = ()         # (canvas_x, canvas_y) of rubber-band origin
        self._rb_id:    int    = 0          # canvas item id of rubber-band rect

        # Tooltip state (Feature 3)
        self._tooltip_win:  object = None   # tk.Toplevel or None
        self._tooltip_job:  str    = ""     # after() job id
        self._tooltip_node: str    = ""     # name of node under cursor

        # Blast radius overlay (Feature 4)
        self._blast_radii: dict = {}        # component_name -> max blast radius

        self._build_ui()
        self._draw_all()
        # Save initial empty state
        self._snapshot()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Construct the canvas and sidebar."""
        # ── Sidebar ─────────────────────────────────────────────────────────
        sidebar = ttk.Frame(self, width=150)
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=4, pady=4)
        sidebar.pack_propagate(False)

        ttk.Label(sidebar, text="Network Editor", font=("Arial", 11, "bold")).pack(pady=(6, 2))
        ttk.Separator(sidebar, orient="horizontal").pack(fill=tk.X, pady=4)

        ttk.Button(sidebar, text="Add Component",
                   command=self._add_component_dialog).pack(fill=tk.X, pady=2)
        ttk.Button(sidebar, text="Add Link",
                   command=self._start_link_mode).pack(fill=tk.X, pady=2)
        ttk.Button(sidebar, text="Add Redundancy Group",
                   command=self._add_redund_group).pack(fill=tk.X, pady=2)
        ttk.Button(sidebar, text="Clear All",
                   command=self._clear_all).pack(fill=tk.X, pady=2)

        ttk.Separator(sidebar, orient="horizontal").pack(fill=tk.X, pady=4)

        ttk.Button(sidebar, text="Access Needs",
                   command=self._edit_access_needs).pack(fill=tk.X, pady=2)
        ttk.Button(sidebar, text="Services",
                   command=self._edit_services).pack(fill=tk.X, pady=2)
        ttk.Button(sidebar, text="FPGA Config",
                   command=self._edit_fpga_config).pack(fill=tk.X, pady=2)
        ttk.Button(sidebar, text="Mission Phases",
                   command=self._edit_mission_phases).pack(fill=tk.X, pady=2)
        ttk.Button(sidebar, text="Policy Exceptions",
                   command=self._edit_policy_exceptions).pack(fill=tk.X, pady=2)
        ttk.Button(sidebar, text="Phase 3 Scenarios",
                   command=self._edit_scenarios).pack(fill=tk.X, pady=2)

        ttk.Separator(sidebar, orient="horizontal").pack(fill=tk.X, pady=4)

        ttk.Button(sidebar, text="Undo",
                   command=self.undo).pack(fill=tk.X, pady=2)
        ttk.Button(sidebar, text="Redo",
                   command=self.redo).pack(fill=tk.X, pady=2)
        ttk.Button(sidebar, text="Zoom In",
                   command=self._zoom_in).pack(fill=tk.X, pady=2)
        ttk.Button(sidebar, text="Zoom Out",
                   command=self._zoom_out).pack(fill=tk.X, pady=2)

        ttk.Button(sidebar, text="Find Component...",
                   command=self._find_component).pack(fill=tk.X, pady=2)
        ttk.Button(sidebar, text="Auto Layout",
                   command=self._auto_layout).pack(fill=tk.X, pady=2)

        ttk.Separator(sidebar, orient="horizontal").pack(fill=tk.X, pady=4)

        ttk.Button(sidebar, text="Load TC9 Example",
                   command=self.load_tc9_example).pack(fill=tk.X, pady=2)
        ttk.Button(sidebar, text="Load RefSoC-16",
                   command=self.load_reference_soc).pack(fill=tk.X, pady=2)

        ttk.Separator(sidebar, orient="horizontal").pack(fill=tk.X, pady=4)

        ttk.Button(sidebar, text="Save JSON",
                   command=self._save_json).pack(fill=tk.X, pady=2)
        ttk.Button(sidebar, text="Load JSON",
                   command=self._load_json).pack(fill=tk.X, pady=2)

        ttk.Separator(sidebar, orient="horizontal").pack(fill=tk.X, pady=4)
        ttk.Checkbutton(sidebar, text="Show Overlay",
                         variable=self._show_overlay,
                         command=self._draw_all).pack(fill=tk.X, pady=2)
        ttk.Checkbutton(sidebar, text="Blast Radius",
                         variable=self._show_blast_radii,
                         command=self._draw_all).pack(fill=tk.X, pady=2)
        ttk.Button(sidebar, text="View ZTA Layout",
                   command=self._view_zta_layout).pack(fill=tk.X, pady=2)

        # ── Canvas ──────────────────────────────────────────────────────────
        canvas_frame = ttk.Frame(self)
        canvas_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._canvas = tk.Canvas(
            canvas_frame,
            bg=CANVAS_BG,
            highlightthickness=0,
        )
        h_scroll = ttk.Scrollbar(canvas_frame, orient=tk.HORIZONTAL,
                                 command=self._canvas.xview)
        v_scroll = ttk.Scrollbar(canvas_frame, orient=tk.VERTICAL,
                                 command=self._canvas.yview)
        self._canvas.configure(
            xscrollcommand=h_scroll.set,
            yscrollcommand=v_scroll.set,
            scrollregion=(0, 0, 1400, 900),
        )
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        v_scroll.pack(side=tk.RIGHT,  fill=tk.Y)
        self._canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # ── Floating legend (placed over canvas, fixed in top-right corner) ─
        self._legend_frame = self._build_legend(canvas_frame)

        # ── Grid ────────────────────────────────────────────────────────────
        self._draw_grid()

        # ── Bindings ────────────────────────────────────────────────────────
        self._canvas.bind("<ButtonPress-1>",   self._on_left_press)
        self._canvas.bind("<B1-Motion>",       self._on_drag)
        self._canvas.bind("<ButtonRelease-1>", self._on_left_release)
        self._canvas.bind("<Double-Button-1>", self._on_double_click)
        self._canvas.bind("<Button-3>",        self._on_right_click)

        # Keyboard shortcuts
        self.bind_all("<Control-z>", lambda e: self.undo())
        self.bind_all("<Control-y>", lambda e: self.redo())
        self.bind_all("<Control-equal>", lambda e: self._zoom_in())
        self.bind_all("<Control-minus>", lambda e: self._zoom_out())
        self.bind_all("<Control-c>", lambda e: self._copy_selected())
        self.bind_all("<Control-v>", lambda e: self._paste_clipboard())

        # Feature 2: Delete key for batch delete
        self._canvas.bind("<Delete>", self._delete_selected)

        # Feature 3: Hover tooltips
        self._canvas.bind("<Motion>", self._on_mouse_motion)
        self._canvas.bind("<Leave>", lambda _: self._cancel_tooltip())

        # Feature 5: Find component shortcut
        self._canvas.bind("<Control-f>", self._find_component)

    # ------------------------------------------------------------------
    # Legend
    # ------------------------------------------------------------------

    def _build_legend(self, parent: tk.Widget) -> tk.Frame:
        """
        Build a floating legend panel and place it in the top-right corner
        of the canvas frame.  Returns the frame so it can be refreshed later.
        """
        BG      = "#1e1e3a"
        FG      = "#cccccc"
        TITLE   = "#ffffff"
        PAD_X   = 8
        PAD_Y   = 4

        frm = tk.Frame(parent, bg=BG, bd=1, relief=tk.SOLID,
                       highlightbackground="#444466", highlightthickness=1)

        def section(text: str) -> None:
            tk.Label(frm, text=text, bg=BG, fg=TITLE,
                     font=("Arial", 8, "bold")).pack(anchor="w",
                                                      padx=PAD_X, pady=(PAD_Y, 0))

        def row(color: str, label: str, shape: str = "rect") -> None:
            row_frm = tk.Frame(frm, bg=BG)
            row_frm.pack(anchor="w", padx=PAD_X, pady=1)
            # Swatch canvas  (16×12)
            sw = tk.Canvas(row_frm, width=16, height=12, bg=BG,
                           highlightthickness=0)
            sw.pack(side=tk.LEFT)
            if shape == "rect":
                sw.create_rectangle(1, 1, 15, 11, fill=color, outline="#888888")
            elif shape == "oval":
                sw.create_oval(1, 1, 15, 11, fill=color, outline="#888888")
            elif shape == "diamond":
                sw.create_polygon(8, 1, 15, 6, 8, 11, 1, 6,
                                  fill=color, outline="#888888")
            elif shape == "hex":
                cx2, cy2, r2 = 8, 6, 5
                hpts = []
                for i in range(6):
                    a = math.radians(60 * i - 30)
                    hpts += [cx2 + r2 * math.cos(a), cy2 + r2 * math.sin(a)]
                sw.create_polygon(hpts, fill=color, outline="#888888")
            elif shape == "halo":
                sw.create_oval(2, 2, 14, 10, fill="", outline=color, width=2)
            tk.Label(row_frm, text=label, bg=BG, fg=FG,
                     font=("Arial", 8)).pack(side=tk.LEFT, padx=(4, 0))

        # ── Title ────────────────────────────────────────────────────────────
        tk.Label(frm, text="Legend", bg=BG, fg=TITLE,
                 font=("Arial", 9, "bold")).pack(anchor="w",
                                                  padx=PAD_X, pady=(PAD_Y, 0))
        tk.Frame(frm, bg="#444466", height=1).pack(fill=tk.X,
                                                    padx=PAD_X, pady=2)

        # ── Node types ───────────────────────────────────────────────────────
        section("Node types")
        row("#3a7dda", "Processor",     shape="rect")
        row("#2db050", "DMA",           shape="rect")
        row("#e07b00", "IP Core",       shape="oval")
        row("#888888", "Bus / NoC",     shape="rect")
        row("#9040cc", "Policy Server", shape="diamond")
        row("#cc3030", "Firewall (PEP)", shape="hex")

        tk.Frame(frm, bg="#444466", height=1).pack(fill=tk.X,
                                                    padx=PAD_X, pady=2)

        # ── Trust domain ─────────────────────────────────────────────────────
        section("Trust domain (border)")
        row("#cc0000", "high — protected asset")
        row("#0000cc", "low  — bus master / untrusted")

        tk.Frame(frm, bg="#444466", height=1).pack(fill=tk.X,
                                                    padx=PAD_X, pady=2)

        # ── ZTA policy ───────────────────────────────────────────────────────
        section("ZTA (Phase 2)")
        tk.Label(frm,
                 text="Policy Server governs\nevery placed Firewall.\nAt least 1 PS required.",
                 bg=BG, fg="#aaaaee", font=("Arial", 7, "italic"),
                 justify=tk.LEFT).pack(anchor="w", padx=PAD_X, pady=(0, 2))

        tk.Frame(frm, bg="#444466", height=1).pack(fill=tk.X,
                                                    padx=PAD_X, pady=2)

        # ── Analysis overlay ─────────────────────────────────────────────────
        section("Overlay (Show Overlay ☑)")
        row("#44ff44", "Risk < 100  (low)",    shape="halo")
        row("#ffcc00", "Risk 100–300 (medium)", shape="halo")
        row("#ff4444", "Risk > 300  (high)",   shape="halo")
        tk.Frame(frm, bg="#444466", height=1).pack(fill=tk.X, padx=PAD_X, pady=1)
        section("Blast Radius (Blast Radius ☑)")
        tk.Label(frm,
                 text="Ring colour/width = how many components\n"
                      "can be reached if this node is compromised.\n"
                      "Red/thick = high reach   Green/thin = low\n"
                      "BR:N label shown only for top 30% severity.",
                 bg=BG, fg="#ff8888", font=("Arial", 7), justify=tk.LEFT).pack(
                 anchor="w", padx=PAD_X, pady=(0, 2))
        tk.Frame(frm, bg="#444466", height=1).pack(fill=tk.X, padx=PAD_X, pady=1)
        section("Link protection (overlay on)")
        tk.Label(frm, text="── green = FW-protected IP\n- - orange = unprotected IP\n── grey  = no access need",
                 bg=BG, fg=FG, font=("Arial", 7), justify=tk.LEFT).pack(
                 anchor="w", padx=PAD_X, pady=(0, 2))
        tk.Label(frm, text="Badge: PLACED / NOT PLACED\nLabel: mac / dmt / zt",
                 bg=BG, fg=FG, font=("Arial", 7), justify=tk.LEFT).pack(
                 anchor="w", padx=PAD_X, pady=(0, PAD_Y))

        frm.place(relx=1.0, rely=0.0, anchor="ne", x=-24, y=16)
        return frm

    def _draw_grid(self) -> None:
        """Draw a subtle background grid."""
        for x in range(0, 1400, 40):
            self._canvas.create_line(x, 0, x, 900, fill=GRID_COLOUR, tags="grid")
        for y in range(0, 900, 40):
            self._canvas.create_line(0, y, 1400, y, fill=GRID_COLOUR, tags="grid")
        self._canvas.tag_lower("grid")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Example topology registry
    # ------------------------------------------------------------------

    # Maps display name -> (model_factory, positions_dict, default_bus_pos)
    EXAMPLE_TOPOLOGIES: Dict[str, dict] = {}

    @classmethod
    def _register_examples(cls) -> None:
        """Populate the EXAMPLE_TOPOLOGIES registry (called once)."""
        if cls.EXAMPLE_TOPOLOGIES:
            return  # already registered

        cls.EXAMPLE_TOPOLOGIES["Test Case 9 (TC9)"] = {
            "factory": make_tc9_network,
            "positions": {
                "sys_cpu": (120, 160),
                "dma":     (120, 320),
                "noc0":    (320, 240),
                "noc1":    (320, 400),
                "c1":      (520, 100),
                "c2":      (520, 180),
                "c3":      (520, 260),
                "c4":      (520, 340),
                "c5":      (520, 420),
                "c6":      (520, 500),
                "c7":      (520, 580),
                "c8":      (520, 660),
                "ps0":     (760, 180),
                "ps1":     (760, 340),
            },
            "default_pos": (350, 300),
        }

        cls.EXAMPLE_TOPOLOGIES["SecureSoC-16 (RefSoC)"] = {
            "factory": make_reference_soc,
            "positions": {
                # Masters (left column)
                "arm_a53":    (100, 140),
                "arm_m4":     (100, 280),
                "dma0":       (100, 420),
                # Main bus (centre)
                "axi_main":   (320, 280),
                # Secure bus segment (upper-right)
                "axi_sec":    (520, 120),
                "crypto_eng": (720, 60),
                "nvram":      (720, 180),
                # Peripheral bus (lower-right)
                "apb_periph": (520, 420),
                "sensor_a":   (720, 300),
                "sensor_b":   (720, 380),
                "sensor_c":   (720, 460),
                "actuator":   (720, 540),
                "watchdog":   (720, 620),
                "gpio":       (720, 700),
                "debug_jtag": (720, 780),
                # Comm (directly on main bus)
                "comm_eth":   (520, 280),
                # Policy servers (far right)
                "ps_main":    (920, 120),
                "ps_backup":  (920, 280),
            },
            "default_pos": (400, 400),
        }

        ot_positions = {
            "cpu": (80, 180),
            "dma": (80, 320),
            "ps_ot": (280, 80),
            "ot_bus": (280, 250),
            "pep_ot": (450, 250),
            "aes": (650, 60),
            "hmac": (650, 130),
            "kmac": (650, 200),
            "otbn": (650, 270),
            "keymgr": (650, 340),
            "otp": (650, 410),
            "lc": (650, 480),
            "flash": (650, 550),
            "sram": (650, 620),
            "rom": (650, 690),
            "uart0": (860, 130),
            "uart1": (860, 200),
            "gpio": (860, 270),
            "spi": (860, 340),
            "i2c": (860, 410),
            "timer": (860, 480),
            "alert": (860, 550),
            "entropy": (860, 620),
        }
        for profile in ("OT-A", "OT-B", "OT-C"):
            cls.EXAMPLE_TOPOLOGIES[f"OpenTitan ({profile})"] = {
                "factory": (lambda p=profile: make_opentitan_network(profile=p)),
                "positions": ot_positions,
                "default_pos": (420, 280),
            }

        pixhawk_platform_positions = {
            "fmu_h753": (120, 260),
            "io_mcu": (120, 430),
            "ps_fmu": (120, 90),
            "imu_bus_1": (320, 90),
            "imu_bus_2": (320, 160),
            "imu_bus_3": (320, 230),
            "baro_bus_1": (320, 320),
            "baro_bus_2": (320, 390),
            "mag_bus": (320, 460),
            "gps1_port": (320, 560),
            "gps2_port": (320, 630),
            "telem1_port": (320, 700),
            "telem2_port": (320, 770),
            "telem3_port": (320, 840),
            "uart4_i2c_port": (320, 910),
            "eth_port": (320, 980),
            "spi5_ext": (320, 1050),
            "can1": (320, 1120),
            "can2": (320, 1190),
            "px4io_link": (320, 1260),
            "imu_1": (560, 90),
            "imu_2": (560, 160),
            "imu_3": (560, 230),
            "baro_1": (560, 320),
            "baro_2": (560, 390),
            "mag": (560, 460),
            "se050": (560, 540),
        }
        cls.EXAMPLE_TOPOLOGIES["Pixhawk 6X Platform"] = {
            "factory": make_pixhawk6x_platform,
            "positions": pixhawk_platform_positions,
            "default_pos": (420, 320),
        }

        pixhawk_uav_positions = dict(pixhawk_platform_positions)
        pixhawk_uav_positions.update({
            "ground_station": (820, 700),
            "gps_1": (560, 630),
            "gps_2": (560, 700),
            "telem_radio": (560, 780),
            "companion": (560, 980),
            "camera": (820, 980),
            "flash_fram": (560, 1050),
            "esc_bus_1": (560, 1120),
            "esc_bus_2": (560, 1190),
            "rc_receiver": (560, 1260),
        })
        cls.EXAMPLE_TOPOLOGIES["Pixhawk 6X UAV"] = {
            "factory": make_pixhawk6x_uav_network,
            "positions": pixhawk_uav_positions,
            "default_pos": (440, 360),
        }
        pixhawk_uav_dual_ps_positions = dict(pixhawk_uav_positions)
        pixhawk_uav_dual_ps_positions.update({
            "ps_io": (300, 620),
        })
        cls.EXAMPLE_TOPOLOGIES["Pixhawk 6X UAV (Dual-PS)"] = {
            "factory": make_pixhawk6x_uav_dual_ps_network,
            "positions": pixhawk_uav_dual_ps_positions,
            "default_pos": (440, 360),
        }

    @classmethod
    def available_examples(cls) -> List[str]:
        """Return the list of registered example topology names."""
        cls._register_examples()
        return list(cls.EXAMPLE_TOPOLOGIES.keys())

    # ------------------------------------------------------------------
    # Common model loader
    # ------------------------------------------------------------------

    def _load_model(self, model: "NetworkModel", positions: dict,
                    default_pos: tuple = (400, 400)) -> None:
        """
        Common loader: populate editor state from a NetworkModel + layout positions.

        This is the single code path for all preset topologies.  It stores
        **all** model-level information so that ``get_network_model()`` can
        faithfully round-trip every field (trust anchors with key_storage /
        signed_policy, custom role names, policy exceptions, etc.).
        """
        self._clear_all(confirm=False)

        # Build NodeData from model components
        for comp in model.components:
            x, y = positions.get(comp.name, default_pos)
            nd = NodeData(
                name=comp.name,
                comp_type=comp.comp_type,
                x=x, y=y,
                domain=comp.domain,
                impact_read=comp.impact_read,
                impact_write=comp.impact_write,
                impact_avail=comp.impact_avail,
                exploitability=comp.exploitability,
                latency_read=comp.latency_read,
                latency_write=comp.latency_write,
                has_rot=comp.has_rot,
                has_sboot=comp.has_sboot,
                has_attest=comp.has_attest,
                is_critical=comp.is_critical,
                is_safety_critical=comp.is_safety_critical,
            )
            self.nodes[comp.name] = nd

        # Buses
        for bus_name in model.buses:
            if bus_name not in self.nodes:
                x, y = positions.get(bus_name, default_pos)
                nd = NodeData(name=bus_name, comp_type="bus", x=x, y=y, domain="low")
                self.nodes[bus_name] = nd

        # Links
        self.links = [LinkData(src, dst) for src, dst in model.links]

        # Redundancy groups
        self.redund_groups = [
            {"group_id": grp.group_id, "members": list(grp.members),
             "colour": "#ffaa00"}
            for grp in model.redundancy_groups
        ]

        # Access needs and services
        self.access_needs = list(model.access_needs)
        self.services     = list(model.services)

        # System caps from model
        if model.system_caps:
            self.system_caps = dict(model.system_caps)
        else:
            self.system_caps = dict(PYNQ_Z2_CAPS)

        # Mission phases
        if model.mission_phases:
            self.mission_phases = list(model.mission_phases)

        # ZTA topology — store explicitly so get_network_model() can use them
        self.cand_fws   = list(model.cand_fws)
        self.cand_ps    = list(model.cand_ps)
        self.on_paths   = list(model.on_paths)
        self.ip_locs    = list(model.ip_locs)
        self.fw_governs = list(model.fw_governs)
        self.fw_costs   = dict(model.fw_costs)
        self.ps_costs   = dict(model.ps_costs)

        # Model-level overrides that NodeData can't represent
        self._model_trust_anchors = dict(model.trust_anchors)
        self._model_roles = list(model.roles)
        self._model_policy_exceptions = (
            list(model.policy_exceptions) if model.policy_exceptions else []
        )
        self._model_capabilities = (
            list(model.capabilities) if model.capabilities else []
        )

        # Auto-generate scenarios from the loaded topology
        from ..agents.phase3_agent import generate_scenarios
        self.scenarios = generate_scenarios(model)

        self._draw_all()
        self._notify_changed()

    def load_example(self, name: str) -> None:
        """Load a named example topology from the registry."""
        self._register_examples()
        entry = self.EXAMPLE_TOPOLOGIES.get(name)
        if entry is None:
            raise ValueError(f"Unknown example topology: {name!r}")
        model = entry["factory"]()
        self._load_model(model, entry["positions"], entry.get("default_pos", (400, 400)))

    # Convenience wrappers (backwards-compatible)
    def load_tc9_example(self) -> None:
        """Pre-populate the editor with the testCase9 topology."""
        self.load_example("Test Case 9 (TC9)")

    def load_reference_soc(self) -> None:
        """Pre-populate the editor with the SecureSoC-16 reference topology."""
        self.load_example("SecureSoC-16 (RefSoC)")

    def get_network_model(self) -> NetworkModel:
        """
        Build and return a NetworkModel from the current canvas state.
        Derives all ZTA/policy facts from canvas topology — does NOT call
        make_tc9_network() as the base.
        """
        model = NetworkModel(name="canvas_network")

        # ── Components and buses ─────────────────────────────────────────────
        model.components = [
            nd.to_component() for nd in self.nodes.values()
            if nd.comp_type != "bus"
        ]
        model.buses = [
            nd.name for nd in self.nodes.values()
            if nd.comp_type == "bus"
        ]
        model.links = [(lk.src, lk.dst) for lk in self.links]
        model.redundancy_groups = [
            RedundancyGroup(grp["group_id"], grp["members"])
            for grp in self.redund_groups
        ]

        # ── 1a. Trust anchors ────────────────────────────────────────────────
        # Start from model-level stored anchors (includes key_storage,
        # signed_policy, trusted_telemetry that NodeData can't represent),
        # then merge/override with canvas NodeData properties.
        model.trust_anchors = dict(self._model_trust_anchors)
        for nd in self.nodes.values():
            props = []
            if nd.has_rot:   props.append("rot")
            if nd.has_sboot: props.append("sboot")
            if nd.has_attest: props.append("attest")
            if props:
                # Merge: keep any extra props from model-level, add canvas props
                existing = set(model.trust_anchors.get(nd.name, []))
                existing.update(props)
                model.trust_anchors[nd.name] = sorted(existing)

        # ── 1b. PEP/PS candidates ────────────────────────────────────────────
        # Use stored lists when available (populated by load_tc9_example /
        # load_reference_soc); otherwise derive from canvas node types.
        canvas_fws = [nd.name for nd in self.nodes.values()
                      if nd.comp_type == "firewall"]
        canvas_ps  = [nd.name for nd in self.nodes.values()
                      if nd.comp_type == "policy_server"]
        model.cand_fws = self.cand_fws if self.cand_fws else canvas_fws
        model.cand_ps  = self.cand_ps  if self.cand_ps  else canvas_ps

        # ── 1c. on_paths, ip_locs, pep_guards ───────────────────────────────
        if self.on_paths:
            # Use stored values from preset load — correct even when FW nodes
            # are not drawn on the canvas (TC9-style abstract FW locations).
            model.on_paths   = list(self.on_paths)
            model.ip_locs    = list(self.ip_locs)
            model.pep_guards = [(fw, ip) for ip, fw in self.ip_locs]
        else:
            # Derive from canvas topology using BFS around firewall nodes.
            adj: Dict[str, List[str]] = {n: [] for n in self.nodes}
            for lk in self.links:
                if lk.src in adj:
                    adj[lk.src].append(lk.dst)
                if lk.dst in adj:
                    adj[lk.dst].append(lk.src)

            def bfs_reachable(start: str) -> set:
                visited = {start}
                queue = [start]
                while queue:
                    cur = queue.pop(0)
                    for nb in adj.get(cur, []):
                        if nb not in visited:
                            visited.add(nb)
                            queue.append(nb)
                return visited

            master_names = {nd.name for nd in self.nodes.values()
                            if nd.comp_type in ("processor", "dma")}
            ip_names = {nd.name for nd in self.nodes.values()
                        if nd.comp_type == "ip_core"}
            fw_names = set(model.cand_fws)

            on_paths:   List[Tuple[str, str, str]] = []
            ip_locs:    List[Tuple[str, str]]      = []
            pep_guards: List[Tuple[str, str]]      = []

            for fw in fw_names:
                fw_reachable = bfs_reachable(fw)
                masters_near_fw = master_names & fw_reachable
                ips_near_fw     = ip_names & fw_reachable
                for m in masters_near_fw:
                    for ip in ips_near_fw:
                        on_paths.append((fw, m, ip))
                for ip in ips_near_fw:
                    ip_locs.append((ip, fw))
                    pep_guards.append((fw, ip))

            model.on_paths   = on_paths
            model.ip_locs    = ip_locs
            model.pep_guards = pep_guards

        # ── 1d. fw_governs and ps_governs_pep ───────────────────────────────
        if self.fw_governs:
            model.fw_governs     = list(self.fw_governs)
            model.ps_governs_pep = list(self.fw_governs)
        else:
            ps_names = set(model.cand_ps)
            fw_names = set(model.cand_fws)
            if not self.on_paths:
                # BFS was done above, reuse bfs_reachable
                fw_governs:     List[Tuple[str, str]] = []
                ps_governs_pep: List[Tuple[str, str]] = []
                for ps in ps_names:
                    ps_reachable = bfs_reachable(ps)
                    for fw in fw_names:
                        if fw in ps_reachable:
                            fw_governs.append((ps, fw))
                            ps_governs_pep.append((ps, fw))
                model.fw_governs     = fw_governs
                model.ps_governs_pep = ps_governs_pep
            else:
                model.fw_governs     = []
                model.ps_governs_pep = []

        # ── 1e. Roles ────────────────────────────────────────────────────────
        # Use model-level stored roles when available (preserves custom names
        # like app_processor, rt_controller); fall back to generic derivation.
        if self._model_roles:
            model.roles = list(self._model_roles)
        else:
            model.roles = []
            for nd in self.nodes.values():
                if nd.comp_type == "processor":
                    model.roles.append((nd.name, "processor"))
                elif nd.comp_type == "dma":
                    model.roles.append((nd.name, "data_mover"))

        # ── 1f. Filter access_needs and build allow rules ────────────────────
        dir_map: Dict[str, str] = {nd.name: nd.direction for nd in self.nodes.values()}
        has_read: set = set()
        has_write: set = set()
        for nd in self.nodes.values():
            d = nd.direction
            if d in ("input", "bidirectional"):
                has_read.add(nd.name)
            if d in ("output", "bidirectional"):
                has_write.add(nd.name)
            for ea in nd.extra_assets:
                if ea["direction"] in ("input", "bidirectional"):
                    has_read.add(nd.name)
                if ea["direction"] in ("output", "bidirectional"):
                    has_write.add(nd.name)

        filtered_needs = []
        for an in self.access_needs:
            if an.operation == "read"  and an.component not in has_read:
                continue
            if an.operation == "write" and an.component not in has_write:
                continue
            filtered_needs.append(an)
        model.access_needs = filtered_needs
        model.services     = list(self.services)

        # Allow rules in "normal" mode
        model.allow_rules = list({(an.master, an.component, "normal")
                                  for an in filtered_needs})

        # ── 1g. fw_costs and ps_costs ────────────────────────────────────────
        # Use stored values from preset (e.g. TC9) when FW/PS nodes aren't
        # drawn on the canvas.
        canvas_fw_costs = {nd.name: nd.fw_cost
                           for nd in self.nodes.values()
                           if nd.comp_type == "firewall"}
        canvas_ps_costs = {nd.name: nd.ps_cost
                           for nd in self.nodes.values()
                           if nd.comp_type == "policy_server"}
        model.fw_costs = self.fw_costs if self.fw_costs else canvas_fw_costs
        model.ps_costs = self.ps_costs if self.ps_costs else canvas_ps_costs

        # ── 1h. system_caps from NetworkEditor instance variable ─────────────
        model.system_caps = dict(self.system_caps)

        # ── Mission phases ───────────────────────────────────────────────────
        model.mission_phases = list(self.mission_phases)

        # ── Policy exceptions ────────────────────────────────────────────────
        # Canvas-edited exceptions (list of dicts)
        canvas_exceptions = [
            (exc["master"], exc["component"], exc["operation"],
             exc.get("mode", "maintenance"), exc.get("reason", ""))
            for exc in self.policy_exceptions
        ]
        # Merge with model-level stored exceptions (list of tuples)
        if self._model_policy_exceptions and not canvas_exceptions:
            model.policy_exceptions = list(self._model_policy_exceptions)
        else:
            model.policy_exceptions = canvas_exceptions

        # ── Scenarios ────────────────────────────────────────────────────────
        model.scenarios = [dict(s) for s in self.scenarios]

        # ── Capabilities ────────────────────────────────────────────────────
        if self._model_capabilities:
            model.capabilities = list(self._model_capabilities)

        # ── Build explicit asset list ────────────────────────────────────────
        SKIP = {"bus", "processor", "dma", "policy_server", "firewall"}
        explicit: List[Asset] = []
        for nd in self.nodes.values():
            if nd.comp_type in SKIP:
                continue
            explicit.append(Asset(
                asset_id=f"{nd.name}r1",
                component=nd.name,
                direction=nd.direction,
                impact_read=nd.impact_read,
                impact_write=nd.impact_write,
                impact_avail=nd.impact_avail,
                latency_read=nd.latency_read,
                latency_write=nd.latency_write,
            ))
            for ea in nd.extra_assets:
                explicit.append(Asset(
                    asset_id=ea["asset_id"],
                    component=nd.name,
                    direction=ea["direction"],
                    impact_read=ea["impact_read"],
                    impact_write=ea["impact_write"],
                    impact_avail=ea.get("impact_avail", 0),
                    latency_read=ea["latency_read"],
                    latency_write=ea["latency_write"],
                ))
        model.assets = explicit
        return model

    def generate_asp_facts(self) -> str:
        """Return an ASP facts string for the current network topology."""
        model = self.get_network_model()
        gen   = ASPGenerator(model)
        return gen.generate()

    def save_to_json(self) -> dict:
        """Serialise the current state to a JSON-compatible dict."""
        data: dict = {
            "nodes": [],
            "links": [(lk.src, lk.dst) for lk in self.links],
            "redund_groups": self.redund_groups,
            "access_needs": [
                {"master": an.master, "component": an.component,
                 "operation": an.operation}
                for an in self.access_needs
            ],
            "services": [
                {"name": sv.name, "members": sv.members, "quorum": sv.quorum}
                for sv in self.services
            ],
            "system_caps": self.system_caps,
            "mission_phases": self.mission_phases,
            "policy_exceptions": self.policy_exceptions,
            "scenarios": self.scenarios,
        }
        for name, nd in self.nodes.items():
            data["nodes"].append({
                "name": nd.name, "comp_type": nd.comp_type,
                "x": nd.x, "y": nd.y,
                "domain": nd.domain,
                "impact_read": nd.impact_read, "impact_write": nd.impact_write,
                "impact_avail": nd.impact_avail, "exploitability": nd.exploitability,
                "latency_read": nd.latency_read, "latency_write": nd.latency_write,
                "has_rot": nd.has_rot, "has_sboot": nd.has_sboot,
                "has_attest": nd.has_attest,
                "is_critical": nd.is_critical,
                "is_safety_critical": nd.is_safety_critical,
                "direction": nd.direction,
                "extra_assets": nd.extra_assets,
                "fw_cost": nd.fw_cost,
                "ps_cost": nd.ps_cost,
            })
        return data

    def load_from_json(self, data: dict) -> None:
        """Load network state from a JSON-compatible dict."""
        self._clear_all(confirm=False)
        for nd_data in data.get("nodes", []):
            # Pop canvas_id / label_id if they slipped into JSON
            nd_clean = {k: v for k, v in nd_data.items()
                        if k not in ("canvas_id", "label_id")}
            # Back-compat: old files lack impact_avail / exploitability
            nd_clean.setdefault("impact_avail",   0)
            nd_clean.setdefault("exploitability",  3)
            nd = NodeData(**nd_clean)
            self.nodes[nd.name] = nd
        for src, dst in data.get("links", []):
            self.links.append(LinkData(src, dst))
        self.redund_groups = data.get("redund_groups", [])
        self.access_needs  = [
            AccessNeed(**a) for a in data.get("access_needs", [])
        ]
        self.services = [
            Service(**s) for s in data.get("services", [])
        ]
        if "system_caps" in data:
            self.system_caps = dict(data["system_caps"])
        if "mission_phases" in data:
            self.mission_phases = list(data["mission_phases"])
        if "policy_exceptions" in data:
            self.policy_exceptions = list(data["policy_exceptions"])
        if "scenarios" in data:
            self.scenarios = list(data["scenarios"])
        self._draw_all()
        self._notify_changed()

    def validate_topology(self) -> List[str]:
        """
        Return a list of warning/error strings describing topology issues.
        An empty list means the topology looks valid.
        """
        warnings: List[str] = []
        node_names = set(self.nodes.keys())

        # At least one master and one IP core
        masters = [nd for nd in self.nodes.values() if nd.comp_type in ("processor", "dma")]
        ips     = [nd for nd in self.nodes.values() if nd.comp_type == "ip_core"]
        if not masters:
            warnings.append("No master nodes (processor/dma) in the topology.")
        if not ips:
            warnings.append("No IP core nodes in the topology.")

        # Duplicate names (shouldn't happen, but sanity check)
        seen: set = set()
        for name in self.nodes:
            if name in seen:
                warnings.append(f"Duplicate node name: {name}")
            seen.add(name)

        # Every master has at least one link
        linked = {lk.src for lk in self.links} | {lk.dst for lk in self.links}
        for nd in masters:
            if nd.name not in linked:
                warnings.append(f"Master node '{nd.name}' has no links.")
        for nd in ips:
            if nd.name not in linked:
                warnings.append(f"IP core '{nd.name}' has no links.")

        # Access need references valid nodes
        for an in self.access_needs:
            if an.master not in node_names:
                warnings.append(f"Access need master '{an.master}' not in nodes.")
            if an.component not in node_names:
                warnings.append(f"Access need component '{an.component}' not in nodes.")

        # Service members valid
        for sv in self.services:
            for m in sv.members:
                if m not in node_names:
                    warnings.append(f"Service '{sv.name}' member '{m}' not in nodes.")

        # Redundancy group members valid
        for grp in self.redund_groups:
            for m in grp.get("members", []):
                if m not in node_names:
                    warnings.append(
                        f"Redundancy group '{grp['group_id']}' member '{m}' not in nodes."
                    )
        return warnings

    def set_validation_warnings(self, warn_by_node: dict) -> None:
        """Store per-node warnings and redraw. Pass {} to clear."""
        self._warn_nodes = warn_by_node
        self._draw_all()

    def set_analysis_results(self, results: Optional[dict]) -> None:
        """
        Store analysis results dict and redraw overlays.

        Parameters
        ----------
        results : dict | None
            Keys: strategy names ('max_security', 'min_resources', 'balanced')
            Values: Phase1Result objects (or None).
            Pass None to clear overlays.
        """
        self._analysis_results = results
        # Cache the best Phase 2 result for ZTA layout and link coloring.
        self._last_p2 = None
        if results:
            for key in ("balanced", "max_security", "min_resources"):
                sol = results.get(key)
                if sol is not None and hasattr(sol, "phase2") and sol.phase2 is not None:
                    self._last_p2 = sol.phase2
                    break
        # Feature 4: accumulate blast radii across all scenarios
        self._blast_radii = {}
        if results:
            for sol in results.values():
                if sol and hasattr(sol, "scenarios"):
                    for sc in (sol.scenarios or []):
                        for comp, r in getattr(sc, "blast_radii", {}).items():
                            self._blast_radii[comp] = max(
                                self._blast_radii.get(comp, 0), r)
        self._draw_all()

    # ------------------------------------------------------------------
    # Drawing
    # ------------------------------------------------------------------

    def _draw_all(self) -> None:
        """Redraw the entire canvas."""
        self._canvas.delete("node", "link", "label", "redund", "overlay", "badge")
        self._draw_redundancy_groups()
        # Build protection sets for link coloring when overlay is active
        protected_ips:   set = set()
        unprotected_ips: set = set()
        if self._show_overlay.get() and self._last_p2 is not None:
            p2 = self._last_p2
            protected_ips   = {ip for (_, ip) in getattr(p2, "protected", [])}
            # IPs that have access needs but are NOT in protected
            all_needed_ips  = {an.component for an in self.access_needs}
            unprotected_ips = all_needed_ips - protected_ips
        self._draw_links(protected_ips, unprotected_ips)
        self._draw_nodes()
        if self._show_overlay.get() and self._analysis_results:
            self._draw_overlays()
        # Feature 2: redraw selection halos
        self._highlight_selected()

    def _draw_redundancy_groups(self) -> None:
        """Draw dashed coloured borders around redundancy groups."""
        for grp in self.redund_groups:
            members = [self.nodes[m] for m in grp["members"] if m in self.nodes]
            if len(members) < 2:
                continue
            xs = [nd.x for nd in members]
            ys = [nd.y for nd in members]
            pad = 18
            x0, y0 = min(xs) - pad, min(ys) - pad
            x1, y1 = max(xs) + pad + NODE_W, max(ys) + pad + NODE_H
            colour = grp.get("colour", "#ffaa00")
            self._canvas.create_rectangle(
                x0 * self._zoom, y0 * self._zoom,
                x1 * self._zoom, y1 * self._zoom,
                dash=(6, 4),
                outline=colour,
                fill="",
                width=2,
                tags="redund",
            )
            self._canvas.create_text(
                x0 * self._zoom + 4, y0 * self._zoom + 4,
                text=f"Group {grp['group_id']}",
                fill=colour,
                anchor="nw",
                font=("Arial", 8),
                tags="redund",
            )

    def _draw_links(self, protected_ips: set = None, unprotected_ips: set = None) -> None:
        """Draw all links as arrows, coloring by ZTA protection status when available."""
        z = self._zoom
        protected_ips   = protected_ips   or set()
        unprotected_ips = unprotected_ips or set()

        # IPs reachable from each bus — for bus-level coloring
        bus_to_ips: Dict[str, set] = {}
        for lk in self.links:
            src = self.nodes.get(lk.src)
            dst = self.nodes.get(lk.dst)
            if src and src.comp_type == "bus" and dst and dst.comp_type == "ip_core":
                bus_to_ips.setdefault(lk.src, set()).add(lk.dst)

        for lk in self.links:
            src_nd = self.nodes.get(lk.src)
            dst_nd = self.nodes.get(lk.dst)
            if src_nd is None or dst_nd is None:
                continue
            sx = (src_nd.x + NODE_W / 2) * z
            sy = (src_nd.y + NODE_H / 2) * z
            dx = (dst_nd.x + NODE_W / 2) * z
            dy = (dst_nd.y + NODE_H / 2) * z

            # Determine link color based on protection
            if dst_nd.comp_type == "ip_core":
                if dst_nd.name in protected_ips:
                    fill, width, dash = "#44cc44", 2.0, ()
                elif dst_nd.name in unprotected_ips:
                    fill, width, dash = "#cc4400", 2.0, (5, 3)
                else:
                    fill, width, dash = "#aaaaaa", 1.5, ()
            elif dst_nd.comp_type == "bus":
                bus_ips = bus_to_ips.get(lk.dst, set())
                if bus_ips & protected_ips:
                    fill, width, dash = "#44cc44", 1.5, ()
                elif bus_ips & unprotected_ips:
                    fill, width, dash = "#cc4400", 1.5, (5, 3)
                else:
                    fill, width, dash = "#aaaaaa", 1.5, ()
            else:
                fill, width, dash = "#aaaaaa", 1.5, ()

            item = self._canvas.create_line(
                sx, sy, dx, dy,
                fill=fill,
                arrow=tk.LAST,
                arrowshape=(8, 10, 4),
                width=width,
                dash=dash,
                tags="link",
            )
            lk.canvas_id = item

    def _draw_nodes(self) -> None:
        """Draw all nodes on the canvas."""
        for name, nd in self.nodes.items():
            self._draw_single_node(nd)

    def _draw_single_node(self, nd: NodeData) -> None:
        """Draw one node, applying shape based on comp_type."""
        z = self._zoom
        style  = NODE_TYPE_STYLES.get(nd.comp_type, NODE_TYPE_STYLES["ip_core"])
        fill   = style["fill"]
        outline = style["outline"]
        shape  = style["shape"]
        x, y   = nd.x * z, nd.y * z

        # Domain tint overlay
        if nd.domain == "low":
            fill = self._mix_colour(fill, "#0000cc", 0.25)
        elif nd.domain == "high":
            fill = self._mix_colour(fill, "#cc0000", 0.15)

        tag = ("node", f"node_{nd.name}")
        nw = NODE_W * z
        nh = NODE_H * z

        if shape == "roundrect":
            item = self._canvas.create_rectangle(
                x, y, x + nw, y + nh,
                fill=fill, outline=outline, width=2, tags=tag
            )
        elif shape == "oval":
            item = self._canvas.create_oval(
                x, y, x + nw, y + nh,
                fill=fill, outline=outline, width=2, tags=tag
            )
        elif shape == "diamond":
            cx, cy = x + nw / 2, y + nh / 2
            hw, hh = nw / 2, nh / 2
            pts = [cx, cy - hh, cx + hw, cy, cx, cy + hh, cx - hw, cy]
            item = self._canvas.create_polygon(
                pts, fill=fill, outline=outline, width=2, tags=tag
            )
        elif shape == "hexagon":
            cx, cy = x + nw / 2, y + nh / 2
            r = nh / 2
            pts = []
            for i in range(6):
                angle = math.radians(60 * i - 30)
                pts += [cx + r * math.cos(angle), cy + r * math.sin(angle)]
            item = self._canvas.create_polygon(
                pts, fill=fill, outline=outline, width=2, tags=tag
            )
        else:  # rect
            w = BUS_W * z if nd.comp_type == "bus" else nw
            h = BUS_H * z if nd.comp_type == "bus" else nh
            item = self._canvas.create_rectangle(
                x, y, x + w, y + h,
                fill=fill, outline=outline, width=2, tags=tag
            )

        nd.canvas_id = item

        # Label
        lbl = self._canvas.create_text(
            x + nw / 2, y + nh / 2,
            text=nd.name,
            fill="white",
            font=("Arial", max(6, int(8 * z)), "bold"),
            tags=("label", f"label_{nd.name}"),
        )
        nd.label_id = lbl

        # Validation warning badge
        if nd.name in self._warn_nodes:
            r = (NODE_H / 2) * z
            self._canvas.create_text(
                x + nw + r, y - r,
                text="⚠",
                fill="#ff3333",
                font=("Arial", 8, "bold"),
                tags=("label", f"warn_{nd.name}"),
            )

    def _draw_overlays(self) -> None:
        """Draw risk halos, placement badges, and feature labels."""
        results = self._analysis_results
        if not results:
            return

        # results values may be SolutionResult or Phase1Result objects.
        # Extract p1 (Phase1Result) from whichever is provided.
        def _extract_p1(obj):
            if obj is None:
                return None
            # SolutionResult has a .phase1 attribute
            if hasattr(obj, "phase1"):
                return obj.phase1
            # Otherwise assume it IS a Phase1Result
            return obj

        # Prefer "balanced" strategy for risk coloring
        p1 = None
        for key in ("balanced", "max_security", "min_resources"):
            if key in results and results[key] is not None:
                p1 = _extract_p1(results[key])
                if p1 is not None:
                    break
        if p1 is None:
            return

        # Build risk-per-component from new_risk list
        risk_map: Dict[str, int] = {}
        for entry in getattr(p1, "new_risk", []):
            comp = entry[0]
            risk_map[comp] = risk_map.get(comp, 0) + entry[3]

        z = self._zoom
        for name, nd in self.nodes.items():
            if name not in risk_map:
                continue
            risk = risk_map[name]
            if risk < 100:
                halo_color = "#00cc00"
            elif risk <= 300:
                halo_color = "#cccc00"
            else:
                halo_color = "#cc0000"

            pad = 6 * z
            x, y = nd.x * z, nd.y * z
            nw, nh = NODE_W * z, NODE_H * z
            self._canvas.create_rectangle(
                x - pad, y - pad, x + nw + pad, y + nh + pad,
                outline=halo_color, fill="", width=3, dash=(4, 3),
                tags="overlay"
            )

        # Phase 2 placement badges on firewall/policy_server nodes
        p2_any = None
        for key in ("balanced", "max_security", "min_resources"):
            sol = results.get(key)
            if sol is not None and hasattr(sol, "phase2") and sol.phase2 is not None:
                p2_any = sol.phase2
                break

        if p2_any is not None:
            placed_fws = set(getattr(p2_any, "placed_fws", []))
            placed_ps  = set(getattr(p2_any, "placed_ps",  []))
            for name, nd in self.nodes.items():
                if nd.comp_type not in ("firewall", "policy_server"):
                    continue
                if name in placed_fws or name in placed_ps:
                    badge_text = "PLACED"
                    badge_color = "#00cc44"
                else:
                    badge_text = "NOT PLACED"
                    badge_color = "#cc4400"
                x, y = nd.x * z, nd.y * z
                nw = NODE_W * z
                self._canvas.create_text(
                    x + nw / 2, y - 8 * z,
                    text=badge_text,
                    fill=badge_color,
                    font=("Arial", max(6, int(7 * z)), "bold"),
                    tags="badge"
                )

        # Security feature labels on IP core nodes
        security_map: Dict[str, str] = getattr(p1, "security", {}) or {}
        ABBREV = {
            "zero_trust":   "zt",
            "dynamic_mac":  "dmt",
            "mac":          "mac",
            "no_security":  "",
        }
        for name, nd in self.nodes.items():
            if nd.comp_type != "ip_core":
                continue
            feat = security_map.get(name, "")
            abbr = ABBREV.get(feat, feat[:3] if feat else "")
            if not abbr:
                continue
            x, y = nd.x * z, nd.y * z
            nw, nh = NODE_W * z, NODE_H * z
            self._canvas.create_text(
                x + nw / 2, y + nh + 8 * z,
                text=abbr,
                fill="#ffff88",
                font=("Arial", max(6, int(7 * z)), "bold"),
                tags="badge"
            )

        # Blast radius rings — only when toggle is on
        if self._show_blast_radii.get() and self._blast_radii:
            max_r = max(self._blast_radii.values(), default=1) or 1
            NODE_R = 22 * z   # approximate node radius used for the ring
            for name, br in self._blast_radii.items():
                nd = self.nodes.get(name)
                if nd is None:
                    continue
                intensity = br / max_r          # 0.0 – 1.0
                x, y = nd.x * z, nd.y * z
                # Ring sits just outside the node shape; width encodes severity
                ring_r = NODE_R + 4 * z
                red   = int(0x66 + intensity * (0xff - 0x66))
                green = int(0x22 * (1 - intensity))
                colour = f"#{red:02x}{green:02x}22"
                ring_w = max(2, int(intensity * 6))
                self._canvas.create_oval(x - ring_r, y - ring_r,
                                         x + ring_r, y + ring_r,
                                         outline=colour, width=ring_w,
                                         tags=("overlay",))
                # Label only for the highest-risk nodes (top 30%)
                if intensity >= 0.7:
                    self._canvas.create_text(x, y - ring_r - 8,
                                             text=f"BR:{br}",
                                             fill=colour, font=("Arial", 7, "bold"),
                                             tags=("overlay",))

    # ------------------------------------------------------------------
    # Undo / Redo
    # ------------------------------------------------------------------

    def _snapshot(self) -> None:
        """Save current state as a JSON snapshot for undo/redo."""
        snapshot = json.dumps(self.save_to_json())
        # Truncate forward history
        if self._history_pos < len(self._history) - 1:
            self._history = self._history[:self._history_pos + 1]
        self._history.append(snapshot)
        self._history_pos = len(self._history) - 1
        # Limit history depth
        if len(self._history) > 50:
            self._history = self._history[-50:]
            self._history_pos = len(self._history) - 1

    def undo(self) -> None:
        """Restore the previous topology snapshot."""
        if self._history_pos > 0:
            self._history_pos -= 1
            data = json.loads(self._history[self._history_pos])
            self._restore_snapshot(data)

    def redo(self) -> None:
        """Restore the next topology snapshot."""
        if self._history_pos < len(self._history) - 1:
            self._history_pos += 1
            data = json.loads(self._history[self._history_pos])
            self._restore_snapshot(data)

    def _restore_snapshot(self, data: dict) -> None:
        """Restore state from a JSON dict without pushing a new snapshot."""
        # Temporarily disable snapshot saving during restore
        old_on = self.on_model_changed
        self.on_model_changed = None
        self.load_from_json(data)
        self.on_model_changed = old_on

    # ------------------------------------------------------------------
    # Zoom
    # ------------------------------------------------------------------

    def _zoom_in(self) -> None:
        self._zoom = min(3.0, self._zoom * 1.2)
        self._update_scrollregion()
        self._draw_all()

    def _zoom_out(self) -> None:
        self._zoom = max(0.2, self._zoom / 1.2)
        self._update_scrollregion()
        self._draw_all()

    def _update_scrollregion(self) -> None:
        z = self._zoom
        self._canvas.configure(scrollregion=(0, 0, int(1400 * z), int(900 * z)))

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _on_left_press(self, event: tk.Event) -> None:
        """Handle left mouse button press — begin drag or link placement."""
        cx = self._canvas.canvasx(event.x)
        cy = self._canvas.canvasy(event.y)
        name = self._hit_test(cx, cy)

        if self._link_src is not None:
            if name and name != self._link_src:
                self.links.append(LinkData(self._link_src, name))
                self._draw_all()
                self._notify_changed()
            self._link_src = None
            self._canvas.configure(cursor="")
            return

        # Ctrl-click: toggle node in multi-select set
        if event.state & 0x0004:
            if name:
                if name in self._selected_nodes:
                    self._selected_nodes.discard(name)
                else:
                    self._selected_nodes.add(name)
                self._highlight_selected()
            return

        if name:
            self._drag_node = name
            nd = self.nodes[name]
            self._drag_ox = cx - nd.x * self._zoom
            self._drag_oy = cy - nd.y * self._zoom
            self._selected = name
            self._selected_nodes.clear()
        else:
            # Start rubber-band selection
            self._drag_node = None
            self._rb_start = (cx, cy)

    def _on_drag(self, event: tk.Event) -> None:
        """Handle drag motion."""
        if self._rb_start:
            # Draw/update rubber-band rectangle
            cx = self._canvas.canvasx(event.x)
            cy = self._canvas.canvasy(event.y)
            if self._rb_id:
                self._canvas.delete(self._rb_id)
            x0, y0 = self._rb_start
            self._rb_id = self._canvas.create_rectangle(
                x0, y0, cx, cy,
                outline="#44aaff", dash=(4, 4), tags="rubberband"
            )
            return
        if self._drag_node is None:
            return
        cx = self._canvas.canvasx(event.x)
        cy = self._canvas.canvasy(event.y)
        nd = self.nodes[self._drag_node]
        nd.x = (cx - self._drag_ox) / self._zoom
        nd.y = (cy - self._drag_oy) / self._zoom
        self._draw_all()

    def _on_left_release(self, event: tk.Event) -> None:
        """Handle drag end — apply grid snap then notify."""
        if self._rb_start:
            # Finish rubber-band selection
            if self._rb_id:
                self._canvas.delete(self._rb_id)
                self._rb_id = 0
            cx = self._canvas.canvasx(event.x)
            cy = self._canvas.canvasy(event.y)
            x0, y0 = self._rb_start
            x1, y1 = cx, cy
            # Normalise
            if x0 > x1:
                x0, x1 = x1, x0
            if y0 > y1:
                y0, y1 = y1, y0
            z = self._zoom
            for name, nd in self.nodes.items():
                nx, ny = nd.x * z, nd.y * z
                if x0 <= nx <= x1 and y0 <= ny <= y1:
                    self._selected_nodes.add(name)
            self._rb_start = ()
            self._highlight_selected()
            return
        if self._drag_node:
            nd = self.nodes[self._drag_node]
            # Grid snap to 20px
            nd.x = round(nd.x / 20) * 20
            nd.y = round(nd.y / 20) * 20
            self._draw_all()
            self._notify_changed()
        self._drag_node = None

    # ------------------------------------------------------------------
    # Feature 2: Multi-select helpers
    # ------------------------------------------------------------------

    def _highlight_selected(self) -> None:
        """Draw cyan outline halos around all selected nodes."""
        self._canvas.delete("sel_halo")
        z = self._zoom
        r = 24 * z
        for name in self._selected_nodes:
            nd = self.nodes.get(name)
            if nd is None:
                continue
            x, y = nd.x * z, nd.y * z
            self._canvas.create_oval(x - r, y - r, x + r, y + r,
                                     outline="#44aaff", width=2, dash=(4, 2),
                                     tags=("sel_halo",))

    def _delete_selected(self, _event=None) -> None:
        to_delete = set(self._selected_nodes)
        if self._selected:
            to_delete.add(self._selected)
        if not to_delete:
            return
        for name in to_delete:
            self.nodes.pop(name, None)
            self.links = [lk for lk in self.links
                          if lk.src != name and lk.dst != name]
        self._selected_nodes.clear()
        self._selected = None
        self._draw_all()
        self._notify_changed()

    # ------------------------------------------------------------------
    # Feature 3: Hover tooltips
    # ------------------------------------------------------------------

    def _on_mouse_motion(self, event) -> None:
        cx = self._canvas.canvasx(event.x)
        cy = self._canvas.canvasy(event.y)
        hit = self._hit_test(cx, cy)
        if hit != self._tooltip_node:
            self._cancel_tooltip()
            self._tooltip_node = hit or ""
            if hit:
                self._tooltip_job = self._canvas.after(
                    600, lambda: self._show_tooltip(event.x_root, event.y_root, hit))

    def _cancel_tooltip(self) -> None:
        if self._tooltip_job:
            self._canvas.after_cancel(self._tooltip_job)
            self._tooltip_job = ""
        if self._tooltip_win and hasattr(self._tooltip_win, "winfo_exists"):
            try:
                if self._tooltip_win.winfo_exists():
                    self._tooltip_win.destroy()
            except Exception:
                pass
        self._tooltip_win = None

    def _show_tooltip(self, rx: int, ry: int, name: str) -> None:
        nd = self.nodes.get(name)
        if not nd:
            return
        tw = tk.Toplevel(self)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{rx+12}+{ry+12}")
        lines = [
            f"Name   : {nd.name}",
            f"Type   : {nd.comp_type}",
            f"Domain : {nd.domain}",
            f"Impact C/I/A: {nd.impact_read}/{nd.impact_write}/{nd.impact_avail}",
            f"Exploitability: {nd.exploitability}",
            f"Latency R/W: {nd.latency_read}/{nd.latency_write}",
        ]
        if nd.has_rot:    lines.append("Has RoT")
        if nd.has_sboot:  lines.append("Has Secure Boot")
        if nd.has_attest: lines.append("Has Attestation")
        tk.Label(tw, text="\n".join(lines), justify=tk.LEFT,
                 background="#222244", foreground="#ccccee",
                 font=("Courier New", 8), relief="solid",
                 borderwidth=1, padx=6, pady=4).pack()
        self._tooltip_win = tw

    # ------------------------------------------------------------------
    # Feature 5: Find component / jump
    # ------------------------------------------------------------------

    def _find_component(self, _event=None) -> None:
        _FindComponentDialog(self, self.nodes, self._jump_to_node)

    def _jump_to_node(self, name: str) -> None:
        nd = self.nodes.get(name)
        if not nd:
            return
        # Pan canvas to centre on node
        z = self._zoom
        cx, cy = nd.x * z, nd.y * z
        cw = self._canvas.winfo_width()
        ch = self._canvas.winfo_height()
        sr_raw = self._canvas.cget("scrollregion")
        sr = sr_raw.split() if sr_raw else ["0", "0", "1400", "900"]
        sw = float(sr[2]) - float(sr[0])
        sh = float(sr[3]) - float(sr[1])
        xfrac = max(0.0, min(1.0, (cx - cw / 2) / sw)) if sw > 0 else 0.0
        yfrac = max(0.0, min(1.0, (cy - ch / 2) / sh)) if sh > 0 else 0.0
        self._canvas.xview_moveto(xfrac)
        self._canvas.yview_moveto(yfrac)
        # Select the node
        self._selected = name
        self._draw_all()

    # ------------------------------------------------------------------
    # Feature 1: Auto layout
    # ------------------------------------------------------------------

    def _auto_layout(self) -> None:
        """Arrange nodes into a left-to-right hierarchical layout."""
        COLS = {
            "processor": 120, "dma": 120,
            "bus": 320,
            "firewall": 480, "policy_server": 480,
            "ip_core": 680,
        }
        Y_START, Y_GAP = 80, 90
        from collections import defaultdict
        col_nodes = defaultdict(list)
        for nd in self.nodes.values():
            col = COLS.get(nd.comp_type, 680)
            col_nodes[col].append(nd)
        # Sort within column by current y so relative order is preserved
        for col, nds in col_nodes.items():
            nds.sort(key=lambda n: n.y)
            for i, nd in enumerate(nds):
                nd.x = float(col)
                nd.y = float(Y_START + i * Y_GAP)
        self._draw_all()
        self._notify_changed()

    def _on_double_click(self, event: tk.Event) -> None:
        """Open property editor for the clicked node."""
        cx = self._canvas.canvasx(event.x)
        cy = self._canvas.canvasy(event.y)
        name = self._hit_test(cx, cy)
        if name:
            self._edit_node_dialog(name)

    def _on_right_click(self, event: tk.Event) -> None:
        """Show context menu for the clicked node."""
        cx = self._canvas.canvasx(event.x)
        cy = self._canvas.canvasy(event.y)
        name = self._hit_test(cx, cy)
        if name is None:
            return
        self._selected = name
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Edit Properties",
                         command=lambda: self._edit_node_dialog(name))
        menu.add_command(label="Add Link from here",
                         command=lambda: self._start_link_from(name))
        menu.add_command(label="Copy",
                         command=lambda: self._copy_node(name))
        menu.add_command(label="Paste",
                         command=self._paste_clipboard)
        menu.add_separator()
        menu.add_command(label="Delete Node",
                         command=lambda: self._delete_node(name))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    # ------------------------------------------------------------------
    # Interaction helpers
    # ------------------------------------------------------------------

    def _hit_test(self, cx: float, cy: float) -> Optional[str]:
        """Return the name of the node under canvas coordinates, or None."""
        z = self._zoom
        for name, nd in self.nodes.items():
            w = BUS_W if nd.comp_type == "bus" else NODE_W
            h = BUS_H if nd.comp_type == "bus" else NODE_H
            if nd.x * z <= cx <= (nd.x + w) * z and nd.y * z <= cy <= (nd.y + h) * z:
                return name
        return None

    def _start_link_mode(self) -> None:
        """Enter link-placement mode (click source, then destination)."""
        messagebox.showinfo(
            "Add Link",
            "Click the SOURCE node first, then the DESTINATION node on the canvas.",
        )
        self._canvas.configure(cursor="crosshair")
        self._link_src = "__select_src__"
        self._canvas.bind("<ButtonPress-1>", self._on_link_src_select)

    def _on_link_src_select(self, event: tk.Event) -> None:
        cx = self._canvas.canvasx(event.x)
        cy = self._canvas.canvasy(event.y)
        name = self._hit_test(cx, cy)
        if name:
            self._link_src = name
            self._canvas.bind("<ButtonPress-1>", self._on_left_press)
        else:
            self._link_src = None
            self._canvas.configure(cursor="")
            self._canvas.bind("<ButtonPress-1>", self._on_left_press)

    def _start_link_from(self, name: str) -> None:
        """Start link placement from a specific node."""
        self._link_src = name
        self._canvas.configure(cursor="crosshair")

    def _add_component_dialog(self) -> None:
        """Open a dialog to add a new component."""
        base = "new_comp"
        n = 1
        while f"{base}_{n}" in self.nodes:
            n += 1
        default_name = f"{base}_{n}"

        dlg = _NodeEditDialog(self, title="Add Component", node=None, default_name=default_name)
        if dlg.result:
            nd = NodeData(**dlg.result)
            nd.x = 300 + len(self.nodes) * 20 % 400
            nd.y = 200 + (len(self.nodes) // 10) * 60
            self.nodes[nd.name] = nd
            self._draw_all()
            self._notify_changed()

    def _edit_node_dialog(self, name: str) -> None:
        """Open property editor for an existing node."""
        nd  = self.nodes[name]
        dlg = _NodeEditDialog(self, title=f"Edit: {name}", node=nd)
        if dlg.result:
            old_name = nd.name
            for k, v in dlg.result.items():
                setattr(nd, k, v)
            if nd.name != old_name:
                self.nodes.pop(old_name)
                self.nodes[nd.name] = nd
                for lk in self.links:
                    if lk.src == old_name:
                        lk.src = nd.name
                    if lk.dst == old_name:
                        lk.dst = nd.name
                for grp in self.redund_groups:
                    if old_name in grp["members"]:
                        grp["members"].remove(old_name)
                        grp["members"].append(nd.name)
            self._draw_all()
            self._notify_changed()

    def _delete_node(self, name: str) -> None:
        """Delete a node and its links."""
        if name in self.nodes:
            del self.nodes[name]
        self.links = [lk for lk in self.links
                      if lk.src != name and lk.dst != name]
        for grp in self.redund_groups:
            if name in grp["members"]:
                grp["members"].remove(name)
        self._draw_all()
        self._notify_changed()

    def _add_redund_group(self) -> None:
        """Open dialog to define a redundancy group from selected nodes."""
        dlg = _RedundGroupDialog(self, list(self.nodes.keys()))
        if dlg.result:
            self.redund_groups.append(dlg.result)
            self._draw_all()
            self._notify_changed()

    def _clear_all(self, confirm: bool = True) -> None:
        """Clear all nodes and links from the canvas."""
        if confirm:
            if not messagebox.askyesno("Clear All", "Remove all nodes and links?"):
                return
        self.nodes         = {}
        self.links         = []
        self.redund_groups = []
        self.access_needs  = []
        self.services      = []
        self.system_caps   = dict(PYNQ_Z2_CAPS)
        self.mission_phases = ["operational", "maintenance", "emergency"]
        self.policy_exceptions = []
        self.scenarios     = []
        # ZTA topology overrides (populated by load_tc9_example / load_reference_soc)
        self.cand_fws   = []
        self.cand_ps    = []
        self.on_paths   = []
        self.ip_locs    = []
        self.fw_governs = []
        self.fw_costs   = {}
        self.ps_costs   = {}
        # Model-level overrides
        self._model_trust_anchors     = {}
        self._model_roles             = []
        self._model_policy_exceptions = []
        self._model_capabilities      = []
        self._canvas.delete("node", "link", "label", "redund", "overlay", "badge")
        self._notify_changed()

    def _save_json(self) -> None:
        """Save the current network to a JSON file."""
        from tkinter.filedialog import asksaveasfilename
        path = asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Save Network",
        )
        if not path:
            return
        data = self.save_to_json()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        messagebox.showinfo("Save", f"Network saved to:\n{path}")

    def _load_json(self) -> None:
        """Load a network from a JSON file."""
        from tkinter.filedialog import askopenfilename
        path = askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Load Network",
        )
        if not path:
            return
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        self.load_from_json(data)
        messagebox.showinfo("Load", f"Network loaded from:\n{path}")

    # ------------------------------------------------------------------
    # Copy / paste
    # ------------------------------------------------------------------

    def _copy_selected(self) -> None:
        if self._selected and self._selected in self.nodes:
            self._copy_node(self._selected)

    def _copy_node(self, name: str) -> None:
        nd = self.nodes.get(name)
        if nd:
            self._clipboard = copy.deepcopy(nd)

    def _paste_clipboard(self) -> None:
        if self._clipboard is None:
            return
        new_nd = copy.deepcopy(self._clipboard)
        base = new_nd.name + "_copy"
        n = 1
        candidate = base
        while candidate in self.nodes:
            candidate = f"{base}{n}"
            n += 1
        new_nd.name = candidate
        new_nd.x += 30
        new_nd.y += 30
        new_nd.canvas_id = None
        new_nd.label_id  = None
        self.nodes[new_nd.name] = new_nd
        self._draw_all()
        self._notify_changed()

    # ------------------------------------------------------------------
    # Sidebar dialog launchers (Group 2)
    # ------------------------------------------------------------------

    def _view_zta_layout(self) -> None:
        """Open the ZTA firewall placement diagram."""
        if self._last_p2 is None:
            messagebox.showinfo(
                "ZTA Layout",
                "No analysis results yet.\nRun analysis first, then click View ZTA Layout."
            )
            return
        model = self.get_network_model()
        _ZTALayoutDialog(self, model, self._last_p2)

    def _edit_access_needs(self) -> None:
        dlg = _AccessNeedsDialog(self, self.access_needs, self.nodes)
        if dlg.result is not None:
            self.access_needs = dlg.result
            self._notify_changed()

    def _edit_services(self) -> None:
        dlg = _ServicesDialog(self, self.services, self.nodes)
        if dlg.result is not None:
            self.services = dlg.result
            self._notify_changed()

    def _edit_fpga_config(self) -> None:
        dlg = _FPGAConfigDialog(self, self.system_caps)
        if dlg.result is not None:
            self.system_caps = dlg.result
            self._notify_changed()

    def _edit_mission_phases(self) -> None:
        dlg = _MissionPhasesDialog(self, self.mission_phases)
        if dlg.result is not None:
            self.mission_phases = dlg.result
            self._notify_changed()

    def _edit_policy_exceptions(self) -> None:
        dlg = _PolicyExceptionsDialog(self, self.policy_exceptions)
        if dlg.result is not None:
            self.policy_exceptions = dlg.result
            self._notify_changed()

    def _edit_scenarios(self) -> None:
        dlg = _ScenariosDialog(self, self.scenarios)
        if dlg.result is not None:
            self.scenarios = dlg.result
            self._notify_changed()

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def _notify_changed(self) -> None:
        self._snapshot()
        if callable(self.on_model_changed):
            self.on_model_changed()

    @staticmethod
    def _mix_colour(hex1: str, hex2: str, t: float) -> str:
        """Linear interpolation between two hex colours."""
        def parse(h: str) -> Tuple[int, int, int]:
            h = h.lstrip("#")
            return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
        r1, g1, b1 = parse(hex1)
        r2, g2, b2 = parse(hex2)
        r = int(r1 + (r2 - r1) * t)
        g = int(g1 + (g2 - g1) * t)
        b = int(b1 + (b2 - b1) * t)
        return f"#{r:02x}{g:02x}{b:02x}"


# ---------------------------------------------------------------------------
# Feature 5: Find Component dialog
# ---------------------------------------------------------------------------

class _FindComponentDialog(tk.Toplevel):
    def __init__(self, parent, nodes: dict, on_select) -> None:
        super().__init__(parent)
        self.transient(parent)
        self.title("Find Component")
        self.resizable(False, False)
        self.grab_set()
        self._nodes  = nodes
        self._on_sel = on_select

        ttk.Label(self, text="Search:").pack(anchor=tk.W, padx=8, pady=(8, 0))
        self._var = tk.StringVar()
        self._var.trace_add("write", lambda *_: self._filter())
        entry = ttk.Entry(self, textvariable=self._var, width=30)
        entry.pack(padx=8, pady=4)
        entry.focus_set()

        self._lb = tk.Listbox(self, height=12, font=("Courier New", 9))
        self._lb.pack(fill=tk.BOTH, expand=True, padx=8)
        self._lb.bind("<Double-Button-1>", self._pick)
        self._lb.bind("<Return>",          self._pick)

        ttk.Button(self, text="Go",    command=self._pick).pack(side=tk.LEFT, padx=8, pady=8)
        ttk.Button(self, text="Close", command=self.destroy).pack(side=tk.LEFT, pady=8)

        self._all_names = sorted(nodes.keys())
        self._filter()
        self.wait_window()

    def _filter(self) -> None:
        term = self._var.get().lower()
        self._lb.delete(0, tk.END)
        for name in self._all_names:
            nd = self._nodes[name]
            line = f"{name}  [{nd.comp_type}, {nd.domain}]"
            if term in name.lower() or term in nd.comp_type:
                self._lb.insert(tk.END, line)
        if self._lb.size() > 0:
            self._lb.selection_set(0)

    def _pick(self, _event=None) -> None:
        sel = self._lb.curselection()
        if not sel:
            return
        line = self._lb.get(sel[0])
        name = line.split("  [")[0]
        self._on_sel(name)
        self.destroy()


# ---------------------------------------------------------------------------
# ZTA Layout dialog
# ---------------------------------------------------------------------------

class _ZTALayoutDialog(tk.Toplevel):
    """
    Dedicated ZTA firewall placement diagram.

    Shows:
    - Masters (left)   →   FW/PEP candidates (centre)   →   IP cores (right)
    - Policy Servers between FWs and IPs
    - Green solid paths = placed FW protects this master→IP route
    - Grey dashed paths = candidate FW not placed
    - Red dashed line  = master→IP route with NO firewall candidate at all
    - Purple arrows    = PS governs FW (control plane)
    """

    _W, _H = 960, 560
    _NR    = 22     # node radius
    _FONT  = ("Arial", 8)
    _BFONT = ("Arial", 8, "bold")

    # x positions for each column
    _XM  = 90    # masters
    _XFW = 290   # firewalls
    _XPS = 500   # policy servers
    _XII = 720   # IP cores

    def __init__(self, parent: tk.Widget, model, p2) -> None:
        super().__init__(parent)
        self.transient(parent)
        self.title("ZTA Firewall Placement")
        self.resizable(True, True)

        self._p2    = p2
        self._model = model

        W, H = self._W, self._H

        frm = ttk.Frame(self)
        frm.pack(fill=tk.BOTH, expand=True)

        self._c = tk.Canvas(frm, bg="#0d0d1a", width=W, height=H,
                            highlightthickness=0)
        vsb = ttk.Scrollbar(frm, orient=tk.VERTICAL,   command=self._c.yview)
        hsb = ttk.Scrollbar(frm, orient=tk.HORIZONTAL, command=self._c.xview)
        self._c.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        vsb.pack(side=tk.RIGHT,  fill=tk.Y)
        self._c.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        btn_row = ttk.Frame(self)
        btn_row.pack(fill=tk.X, padx=6, pady=(0, 4))
        ttk.Button(btn_row, text="Cross-check vs Canvas",
                   command=self._crosscheck).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="Close", command=self.destroy).pack(side=tk.RIGHT, padx=4)

        self._draw(model, p2)

    # ------------------------------------------------------------------

    def _pos_list(self, items: list, x: int, margin: int = 60) -> Dict[str, Tuple[int,int]]:
        """Return {name: (x, y)} for evenly-spaced items in column x."""
        n = len(items)
        if n == 0:
            return {}
        avail = self._H - 2 * margin
        step  = avail / max(n - 1, 1)
        return {items[i]: (x, int(margin + i * step)) for i in range(n)}

    def _draw_arrow(self, x1, y1, x2, y2, color, dash=(), width=1.5, r=None) -> None:
        r = r or self._NR
        # shorten line by node radius at each end
        dx, dy = x2 - x1, y2 - y1
        dist = math.hypot(dx, dy) or 1
        ux, uy = dx / dist, dy / dist
        sx, sy = x1 + ux * r, y1 + uy * r
        ex, ey = x2 - ux * r, y2 - uy * r
        self._c.create_line(sx, sy, ex, ey, fill=color, dash=dash,
                            width=width, arrow=tk.LAST, arrowshape=(8, 10, 4))

    def _draw_node(self, x, y, label, color, shape="circle",
                   outline="#ffffff", badge: str = "") -> None:
        r = self._NR
        c = self._c
        if shape == "hex":
            pts = []
            for i in range(6):
                a = math.radians(60 * i - 30)
                pts += [x + r * math.cos(a), y + r * math.sin(a)]
            c.create_polygon(pts, fill=color, outline=outline, width=2)
        elif shape == "diamond":
            c.create_polygon(x, y - r, x + r, y, x, y + r, x - r, y,
                             fill=color, outline=outline, width=2)
        elif shape == "rect":
            c.create_rectangle(x - r, y - r * 0.6, x + r, y + r * 0.6,
                               fill=color, outline=outline, width=2)
        else:
            c.create_oval(x - r, y - r, x + r, y + r,
                          fill=color, outline=outline, width=2)
        c.create_text(x, y + r + 10, text=label, fill="#cccccc", font=self._FONT)
        if badge:
            c.create_text(x, y, text=badge, fill="#ffffff", font=self._BFONT)

    def _draw(self, model, p2) -> None:
        c    = self._c
        W, H = self._W, self._H

        placed_fws = set(getattr(p2, "placed_fws", []))
        placed_ps  = set(getattr(p2, "placed_ps",  []))
        # protected: list of (master, ip) tuples
        protected_pairs = set(tuple(x) for x in getattr(p2, "protected", []))
        # governs: (ps, fw) pairs — use model.fw_governs
        governs = set(tuple(x) for x in getattr(model, "fw_governs", []))

        # Collect unique nodes per role
        masters  = [c2.name for c2 in model.components if c2.is_master]
        ip_cores = [c2.name for c2 in model.components
                    if c2.is_receiver and c2.comp_type not in
                    ("policy_server", "firewall", "bus")]
        # Include placed FWs/PSes from p2 even if not canvas nodes (e.g. TC9)
        fws = sorted(placed_fws | set(getattr(model, "cand_fws", [])))
        pss = sorted(placed_ps  | set(getattr(model, "cand_ps",  [])))

        # Positions
        m_pos  = self._pos_list(masters,  self._XM)
        fw_pos = self._pos_list(fws,      self._XFW)
        ps_pos = self._pos_list(pss,      self._XPS)
        ip_pos = self._pos_list(ip_cores, self._XII)

        # ── Column headers ───────────────────────────────────────────────
        for label, x in [("Masters",    self._XM),
                          ("Firewalls",  self._XFW),
                          ("Policy Servers", self._XPS),
                          ("IP Cores",   self._XII)]:
            c.create_text(x, 24, text=label, fill="#8888ee",
                          font=("Arial", 9, "bold"))
            c.create_line(x - 60, 34, x + 60, 34, fill="#333366", width=1)

        on_paths = getattr(model, "on_paths", [])
        if on_paths:
            # ── Detailed routing: master → FW → IP ───────────────────────
            drawn_mfw: set = set()
            drawn_fwip: set = set()
            for fw, master, ip in on_paths:
                mxy = m_pos.get(master)
                fxy = fw_pos.get(fw)
                ixy = ip_pos.get(ip)
                if not (mxy and fxy and ixy):
                    continue
                placed = fw in placed_fws
                color  = "#44cc44" if placed else "#445544"
                dash   = ()        if placed else (4, 4)
                w      = 1.8       if placed else 1.0
                if (master, fw) not in drawn_mfw:
                    self._draw_arrow(*mxy, *fxy, color, dash, w)
                    drawn_mfw.add((master, fw))
                if (fw, ip) not in drawn_fwip:
                    self._draw_arrow(*fxy, *ixy, color, dash, w)
                    drawn_fwip.add((fw, ip))
            # Unprotected: access needs not on any path
            all_path_ips = {ip for (fw, master, ip) in on_paths}
            for need in getattr(model, "access_needs", []):
                master_n = need if isinstance(need, str) else getattr(need, "master", str(need))
                ip_n     = need if isinstance(need, str) else getattr(need, "component", str(need))
                if ip_n not in all_path_ips:
                    mxy = m_pos.get(master_n)
                    ixy = ip_pos.get(ip_n)
                    if mxy and ixy:
                        self._draw_arrow(*mxy, *ixy, "#cc4400", (5, 3), 1.2)
        else:
            # ── Synthesise from p2.protected (no on_path data, e.g. TC9) ──
            # Protected master→IP pairs: draw direct green arrows
            for master, ip in protected_pairs:
                mxy = m_pos.get(master)
                ixy = ip_pos.get(ip)
                if mxy and ixy:
                    self._draw_arrow(*mxy, *ixy, "#44cc44", (), 1.8)
            # Unprotected: access needs whose IP is not in protected set
            prot_ips = {ip for (_, ip) in protected_pairs}
            for need in getattr(model, "access_needs", []):
                if hasattr(need, "master"):
                    master_n, ip_n = need.master, need.component
                elif isinstance(need, (list, tuple)) and len(need) == 2:
                    master_n, ip_n = str(need[0]), str(need[1])
                else:
                    continue
                if ip_n not in prot_ips:
                    mxy = m_pos.get(master_n)
                    ixy = ip_pos.get(ip_n)
                    if mxy and ixy:
                        self._draw_arrow(*mxy, *ixy, "#cc4400", (5, 3), 1.2)

        # ── PS governance ────────────────────────────────────────────────
        if governs:
            # model.fw_governs available: PS → FW arrows
            for ps, fw in governs:
                pxy = ps_pos.get(ps)
                fxy = fw_pos.get(fw)
                if pxy and fxy:
                    placed = ps in placed_ps
                    col = "#9040cc" if placed else "#442255"
                    self._draw_arrow(*pxy, *fxy, col, (6, 3), 1.2)
        else:
            # Fallback: p2.governs_ip gives (ps, ip) pairs
            for ps, ip in getattr(p2, "governs_ip", []):
                pxy = ps_pos.get(ps)
                ixy = ip_pos.get(ip)
                if pxy and ixy:
                    placed = ps in placed_ps
                    col = "#9040cc" if placed else "#442255"
                    self._draw_arrow(*pxy, *ixy, col, (6, 3), 1.2)

        # ── Master nodes ─────────────────────────────────────────────────
        for name, (x, y) in m_pos.items():
            comp = next((c2 for c2 in model.components if c2.name == name), None)
            col  = "#3a7dda" if (comp and comp.comp_type == "processor") else "#2db050"
            self._draw_node(x, y, name, col, shape="rect")

        # ── Firewall nodes ───────────────────────────────────────────────
        for name, (x, y) in fw_pos.items():
            placed = name in placed_fws
            col    = "#cc3030" if placed else "#442222"
            badge  = "PLC" if placed else "---"
            outl   = "#ff6666" if placed else "#666666"
            self._draw_node(x, y, name, col, shape="hex", outline=outl, badge=badge)

        # ── PS nodes ─────────────────────────────────────────────────────
        for name, (x, y) in ps_pos.items():
            placed = name in placed_ps
            col    = "#9040cc" if placed else "#331144"
            badge  = "PLC" if placed else "---"
            outl   = "#cc88ff" if placed else "#666666"
            self._draw_node(x, y, name, col, shape="diamond", outline=outl, badge=badge)

        # ── IP core nodes ────────────────────────────────────────────────
        for name, (x, y) in ip_pos.items():
            guarded = name in {ip for (_, ip) in protected_pairs}
            col     = "#e07b00" if not guarded else "#229922"
            outl    = "#44ff44" if guarded     else "#aa5500"
            self._draw_node(x, y, name, col, shape="circle", outline=outl)

        # ── Legend ───────────────────────────────────────────────────────
        lx, ly = 10, H - 95
        c.create_rectangle(lx, ly, lx + 210, H - 5,
                           fill="#111122", outline="#333366")
        c.create_text(lx + 6, ly + 8, anchor="nw",
                      text="Legend", fill="#aaaaee",
                      font=("Arial", 8, "bold"))
        items = [
            ("#44cc44", "─────",  "Protected path / placed FW"),
            ("#445544", "- - -",  "Candidate FW not placed"),
            ("#cc4400", "- - -",  "Unguarded master→IP path"),
            ("#9040cc", "· · ·",  "PS governs FW"),
            ("#229922", "●",       "Protected IP core"),
            ("#e07b00", "●",       "Unprotected IP core"),
        ]
        for i, (col, sym, txt) in enumerate(items):
            c.create_text(lx + 8, ly + 22 + i * 12, anchor="nw",
                          text=f"{sym}  {txt}", fill=col,
                          font=("Arial", 7))

        # ── Summary bar ──────────────────────────────────────────────────
        protected_count = len({ip for (_, ip) in protected_pairs})
        total_ips       = len(ip_cores)
        summary = (f"Placed FWs: {', '.join(sorted(placed_fws)) or '—'}  │  "
                   f"Placed PSes: {', '.join(sorted(placed_ps)) or '—'}  │  "
                   f"Protected IPs: {protected_count}/{total_ips}")
        c.create_rectangle(0, H - 22, W, H, fill="#111133", outline="")
        c.create_text(W // 2, H - 11, text=summary,
                      fill="#88ffaa", font=("Arial", 8))

        # Expand scroll region to fit content
        self._c.configure(scrollregion=self._c.bbox("all") or (0, 0, W, H))

    def _crosscheck(self) -> None:
        """Compare p2.protected with canvas-level link coloring."""
        from tkinter import messagebox
        p2     = self._p2
        model  = self._model
        protected_pairs = set(tuple(x) for x in getattr(p2, "protected", []))
        # IPs the model considers reachable by masters via access_needs
        access_ips: dict = {}  # master -> set of ips
        for need in getattr(model, "access_needs", []):
            if hasattr(need, "master"):
                access_ips.setdefault(need.master, set()).add(need.component)
        issues = []
        # Every access need should be either protected or explicitly noted
        for master, ips in access_ips.items():
            for ip in ips:
                if (master, ip) not in protected_pairs:
                    issues.append(f"  UNPROTECTED: {master} → {ip}")
        # Every protected pair should correspond to a real access need
        all_access = {(need.master, need.component)
                      for need in getattr(model, "access_needs", [])
                      if hasattr(need, "master")}
        for master, ip in sorted(protected_pairs):
            if (master, ip) not in all_access:
                issues.append(f"  SPURIOUS protection: {master} → {ip} (no access need declared)")
        if issues:
            msg = f"Cross-check found {len(issues)} issue(s):\n\n" + "\n".join(issues[:20])
            if len(issues) > 20:
                msg += f"\n  ... and {len(issues)-20} more"
            messagebox.showwarning("ZTA Cross-check", msg, parent=self)
        else:
            n_prot = len(protected_pairs)
            n_total = sum(len(v) for v in access_ips.values())
            messagebox.showinfo(
                "ZTA Cross-check",
                f"All checks passed.\n\n"
                f"  Protected pairs : {n_prot}\n"
                f"  Total access needs: {n_total}\n"
                f"  Unprotected     : {n_total - n_prot}",
                parent=self
            )


# ---------------------------------------------------------------------------
# Property editor dialog
# ---------------------------------------------------------------------------

class _NodeEditDialog(tk.Toplevel):
    """Modal dialog for editing node properties."""

    COMP_TYPES = ["processor", "dma", "ip_core", "bus",
                  "policy_server", "firewall"]
    DIRECTIONS = ["bidirectional", "input", "output"]
    DOMAINS    = ["untrusted", "low", "normal", "privileged", "high", "root"]

    def __init__(
        self,
        parent: tk.Widget,
        title: str,
        node: Optional[NodeData],
        default_name: str = "new_comp",
    ) -> None:
        super().__init__(parent)
        self.transient(parent)
        self.title(title)
        self.resizable(False, False)
        self.grab_set()
        self.result: Optional[dict] = None

        # Defaults
        name = node.name if node else default_name
        comp_type  = node.comp_type    if node else "ip_core"
        domain     = node.domain       if node else "high"
        ir         = node.impact_read  if node else 3
        iw         = node.impact_write if node else 3
        ia         = node.impact_avail if node else 0
        expl       = node.exploitability if node else 3
        lr         = node.latency_read  if node else 1000
        lw         = node.latency_write if node else 1000
        rot        = node.has_rot    if node else False
        sboot      = node.has_sboot  if node else False
        attest     = node.has_attest if node else False
        crit       = node.is_critical  if node else False
        safety     = node.is_safety_critical if node else False
        direction  = node.direction  if node else "bidirectional"
        fw_cost    = node.fw_cost    if node else 150
        ps_cost    = node.ps_cost    if node else 100
        self._extra_assets: List[dict] = list(node.extra_assets) if node else []

        frm = ttk.Frame(self, padding=12)
        frm.grid(row=0, column=0, sticky="nsew")

        def row_entry(label: str, default: str, r: int) -> ttk.Entry:
            ttk.Label(frm, text=label).grid(row=r, column=0, sticky="e", pady=2)
            e = ttk.Entry(frm, width=22)
            e.insert(0, str(default))
            e.grid(row=r, column=1, sticky="w", padx=4)
            return e

        def row_combo(label: str, values: list, default: str, r: int) -> ttk.Combobox:
            ttk.Label(frm, text=label).grid(row=r, column=0, sticky="e", pady=2)
            cb = ttk.Combobox(frm, values=values, width=20, state="readonly")
            cb.set(default)
            cb.grid(row=r, column=1, sticky="w", padx=4)
            return cb

        def row_check(label: str, default: bool, r: int) -> tk.BooleanVar:
            var = tk.BooleanVar(value=default)
            ttk.Label(frm, text=label).grid(row=r, column=0, sticky="e", pady=2)
            ttk.Checkbutton(frm, variable=var).grid(row=r, column=1, sticky="w", padx=4)
            return var

        self._name_e   = row_entry("Name:",                name,      0)
        self._type_cb  = row_combo("Type:",   self.COMP_TYPES, comp_type, 1)
        self._dom_cb   = row_combo("Domain:", self.DOMAINS,    domain,    2)
        self._dir_cb   = row_combo("I/O Direction:", self.DIRECTIONS, direction, 3)
        # CIA impact scale: 1=negligible, 2=minor, 3=moderate, 4=serious, 5=catastrophic
        self._ir_e     = row_entry("Impact Read  C (1-5):",   ir,   4)
        self._iw_e     = row_entry("Impact Write I (1-5):",   iw,   5)
        self._ia_e     = row_entry("Impact Avail A (0=off, 1-5):", ia, 6)
        self._expl_e   = row_entry("Exploitability (1=hard..5=trivial):", expl, 7)
        self._lr_e     = row_entry("Latency Read (cycles):",  lr,   8)
        self._lw_e     = row_entry("Latency Write (cycles):", lw,   9)
        self._rot_v    = row_check("Has Hardware RoT:",       rot,  10)
        self._sboot_v  = row_check("Has Secure Boot:",        sboot, 11)
        self._attest_v = row_check("Has Attestation:",        attest, 12)
        self._crit_v   = row_check("Is Critical IP:",         crit,  13)
        self._safety_v = row_check("Is Safety-Critical:",     safety, 14)

        # fw_cost / ps_cost — only shown for firewall/policy_server
        self._fw_cost_lbl = ttk.Label(frm, text="FW Cost:")
        self._fw_cost_e   = ttk.Entry(frm, width=22)
        self._fw_cost_e.insert(0, str(fw_cost))
        self._ps_cost_lbl = ttk.Label(frm, text="PS Cost:")
        self._ps_cost_e   = ttk.Entry(frm, width=22)
        self._ps_cost_e.insert(0, str(ps_cost))
        self._fw_cost_lbl.grid(row=15, column=0, sticky="e", pady=2)
        self._fw_cost_e.grid(row=15, column=1, sticky="w", padx=4)
        self._ps_cost_lbl.grid(row=16, column=0, sticky="e", pady=2)
        self._ps_cost_e.grid(row=16, column=1, sticky="w", padx=4)
        self._update_cost_visibility(comp_type)
        self._type_cb.bind("<<ComboboxSelected>>",
                           lambda e: self._update_cost_visibility(self._type_cb.get()))

        # Extra assets button
        self._asset_btn_lbl = ttk.Label(frm, text="Extra Assets:")
        self._asset_btn_lbl.grid(row=17, column=0, sticky="e", pady=2)
        self._asset_btn = ttk.Button(frm, text=self._asset_btn_label(),
                                     command=self._manage_assets)
        self._asset_btn.grid(row=17, column=1, sticky="w", padx=4)

        btn_frm = ttk.Frame(frm)
        btn_frm.grid(row=18, column=0, columnspan=2, pady=(8, 0))
        ttk.Button(btn_frm, text="OK",     command=self._ok).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frm, text="Cancel", command=self.destroy).pack(side=tk.LEFT)

        self.wait_window()

    def _update_cost_visibility(self, comp_type: str) -> None:
        if comp_type in ("firewall", "policy_server"):
            self._fw_cost_lbl.grid()
            self._fw_cost_e.grid()
            self._ps_cost_lbl.grid()
            self._ps_cost_e.grid()
        else:
            self._fw_cost_lbl.grid_remove()
            self._fw_cost_e.grid_remove()
            self._ps_cost_lbl.grid_remove()
            self._ps_cost_e.grid_remove()

    def _asset_btn_label(self) -> str:
        n = len(self._extra_assets)
        return f"{n} extra asset(s)  [Edit...]"

    def _manage_assets(self) -> None:
        dlg = _AssetListDialog(self, self._extra_assets,
                               base_name=self._name_e.get().strip() or "comp")
        self._extra_assets = dlg.result
        self._asset_btn.config(text=self._asset_btn_label())

    def _ok(self) -> None:
        try:
            ct = self._type_cb.get()
            fw_cost_val = 150
            ps_cost_val = 100
            if ct in ("firewall", "policy_server"):
                fw_cost_val = int(self._fw_cost_e.get())
                ps_cost_val = int(self._ps_cost_e.get())
            self.result = {
                "name":           self._name_e.get().strip(),
                "comp_type":      ct,
                "domain":         self._dom_cb.get(),
                "direction":      self._dir_cb.get(),
                "impact_read":    int(self._ir_e.get()),
                "impact_write":   int(self._iw_e.get()),
                "impact_avail":   int(self._ia_e.get()),
                "exploitability": int(self._expl_e.get()),
                "latency_read":   int(self._lr_e.get()),
                "latency_write":  int(self._lw_e.get()),
                "has_rot":        self._rot_v.get(),
                "has_sboot":      self._sboot_v.get(),
                "has_attest":     self._attest_v.get(),
                "is_critical":    self._crit_v.get(),
                "is_safety_critical": self._safety_v.get(),
                "extra_assets":   list(self._extra_assets),
                "fw_cost":        fw_cost_val,
                "ps_cost":        ps_cost_val,
            }
        except ValueError as exc:
            messagebox.showerror("Validation Error", str(exc))
            return
        self.destroy()


# ---------------------------------------------------------------------------
# Extra-asset list dialog
# ---------------------------------------------------------------------------

class _AssetListDialog(tk.Toplevel):
    """Modal dialog for managing multiple named assets on one component."""

    DIRECTIONS = ["bidirectional", "input", "output"]

    def __init__(self, parent: tk.Widget, assets: List[dict], base_name: str = "comp") -> None:
        super().__init__(parent)
        self.transient(parent)
        self.title("Manage Assets")
        self.resizable(False, False)
        self.grab_set()
        self._base  = base_name
        self.result: List[dict] = list(assets)

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frm, text="Extra assets (beyond the primary auto-generated one):").grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 4))

        self._lb = tk.Listbox(frm, width=55, height=8, selectmode=tk.SINGLE)
        self._lb.grid(row=1, column=0, columnspan=2, sticky="nsew")
        sb = ttk.Scrollbar(frm, orient=tk.VERTICAL, command=self._lb.yview)
        sb.grid(row=1, column=2, sticky="ns")
        self._lb.configure(yscrollcommand=sb.set)

        btn_col = ttk.Frame(frm)
        btn_col.grid(row=1, column=3, sticky="n", padx=(6, 0))
        ttk.Button(btn_col, text="Add",    command=self._add).pack(fill=tk.X, pady=2)
        ttk.Button(btn_col, text="Edit",   command=self._edit).pack(fill=tk.X, pady=2)
        ttk.Button(btn_col, text="Remove", command=self._remove).pack(fill=tk.X, pady=2)

        ttk.Button(frm, text="Done", command=self.destroy).grid(
            row=2, column=0, columnspan=4, pady=(8, 0))

        self._refresh()
        self.wait_window()

    def _refresh(self) -> None:
        self._lb.delete(0, tk.END)
        for a in self.result:
            self._lb.insert(tk.END,
                f"{a['asset_id']}  [{a['direction']}]  "
                f"imp r={a['impact_read']} w={a['impact_write']}  "
                f"lat r={a['latency_read']} w={a['latency_write']}")

    def _add(self) -> None:
        n = len(self.result) + 2
        default = {"asset_id": f"{self._base}r{n}", "direction": "bidirectional",
                   "impact_read": 3, "impact_write": 3,
                   "latency_read": 1000, "latency_write": 1000}
        dlg = _SingleAssetDialog(self, default)
        if dlg.result:
            self.result.append(dlg.result)
            self._refresh()

    def _edit(self) -> None:
        sel = self._lb.curselection()
        if not sel:
            return
        idx = sel[0]
        dlg = _SingleAssetDialog(self, self.result[idx])
        if dlg.result:
            self.result[idx] = dlg.result
            self._refresh()

    def _remove(self) -> None:
        sel = self._lb.curselection()
        if not sel:
            return
        del self.result[sel[0]]
        self._refresh()


class _SingleAssetDialog(tk.Toplevel):
    """Modal dialog for editing one asset entry."""

    DIRECTIONS = ["bidirectional", "input", "output"]

    def __init__(self, parent: tk.Widget, asset: dict) -> None:
        super().__init__(parent)
        self.transient(parent)
        self.title("Edit Asset")
        self.resizable(False, False)
        self.grab_set()
        self.result: Optional[dict] = None

        frm = ttk.Frame(self, padding=12)
        frm.pack()

        def row_entry(label, default, r):
            ttk.Label(frm, text=label).grid(row=r, column=0, sticky="e", pady=2)
            e = ttk.Entry(frm, width=22)
            e.insert(0, str(default))
            e.grid(row=r, column=1, sticky="w", padx=4)
            return e

        def row_combo(label, values, default, r):
            ttk.Label(frm, text=label).grid(row=r, column=0, sticky="e", pady=2)
            cb = ttk.Combobox(frm, values=values, width=20, state="readonly")
            cb.set(default)
            cb.grid(row=r, column=1, sticky="w", padx=4)
            return cb

        self._id_e   = row_entry("Asset ID:",             asset["asset_id"],    0)
        self._dir_cb = row_combo("Direction:", self.DIRECTIONS, asset["direction"], 1)
        self._ir_e   = row_entry("Impact Read (1-5):",    asset["impact_read"], 2)
        self._iw_e   = row_entry("Impact Write (1-5):",   asset["impact_write"],3)
        self._lr_e   = row_entry("Latency Read (cycles):", asset["latency_read"], 4)
        self._lw_e   = row_entry("Latency Write (cycles):", asset["latency_write"], 5)

        btn_frm = ttk.Frame(frm)
        btn_frm.grid(row=6, column=0, columnspan=2, pady=(8, 0))
        ttk.Button(btn_frm, text="OK",     command=self._ok).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frm, text="Cancel", command=self.destroy).pack(side=tk.LEFT)

        self.wait_window()

    def _ok(self) -> None:
        try:
            self.result = {
                "asset_id":     self._id_e.get().strip(),
                "direction":    self._dir_cb.get(),
                "impact_read":  int(self._ir_e.get()),
                "impact_write": int(self._iw_e.get()),
                "latency_read": int(self._lr_e.get()),
                "latency_write": int(self._lw_e.get()),
            }
        except ValueError as exc:
            messagebox.showerror("Validation Error", str(exc))
            return
        self.destroy()


# ---------------------------------------------------------------------------
# Redundancy group dialog
# ---------------------------------------------------------------------------

class _RedundGroupDialog(tk.Toplevel):
    """Modal dialog to define a redundancy group."""

    def __init__(self, parent: tk.Widget, node_names: List[str]) -> None:
        super().__init__(parent)
        self.transient(parent)
        self.title("Add Redundancy Group")
        self.resizable(False, False)
        self.grab_set()
        self.result: Optional[dict] = None

        frm = ttk.Frame(self, padding=12)
        frm.pack()

        ttk.Label(frm, text="Group ID:").grid(row=0, column=0, sticky="e")
        self._id_e = ttk.Entry(frm, width=12)
        self._id_e.insert(0, "g1")
        self._id_e.grid(row=0, column=1, sticky="w", padx=4)

        ttk.Label(frm, text="Select members:").grid(row=1, column=0, sticky="ne", pady=4)
        self._lb = tk.Listbox(frm, selectmode=tk.MULTIPLE, height=8, width=22)
        for n in sorted(node_names):
            self._lb.insert(tk.END, n)
        self._lb.grid(row=1, column=1, sticky="w")

        ttk.Label(frm, text="Colour:").grid(row=2, column=0, sticky="e")
        self._col_e = ttk.Entry(frm, width=12)
        self._col_e.insert(0, "#ffaa00")
        self._col_e.grid(row=2, column=1, sticky="w", padx=4)

        btn_frm = ttk.Frame(frm)
        btn_frm.grid(row=3, column=0, columnspan=2, pady=(8, 0))
        ttk.Button(btn_frm, text="OK",     command=self._ok).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frm, text="Cancel", command=self.destroy).pack(side=tk.LEFT)

        self.wait_window()

    def _ok(self) -> None:
        sel   = self._lb.curselection()
        names = [self._lb.get(i) for i in sel]
        if len(names) < 2:
            messagebox.showerror("Error", "Select at least 2 members.")
            return
        self.result = {
            "group_id": self._id_e.get().strip() or "g1",
            "members":  names,
            "colour":   self._col_e.get().strip() or "#ffaa00",
        }
        self.destroy()


# ---------------------------------------------------------------------------
# Access Needs dialog (Group 2a)
# ---------------------------------------------------------------------------

class _AccessNeedsDialog(tk.Toplevel):
    """Modal dialog for editing access needs."""

    def __init__(self, parent: tk.Widget,
                 needs: List[AccessNeed],
                 nodes: Dict[str, NodeData]) -> None:
        super().__init__(parent)
        self.transient(parent)
        self.title("Edit Access Needs")
        self.grab_set()
        self.result: Optional[List[AccessNeed]] = None
        self._needs: List[AccessNeed] = list(needs)
        self._nodes = nodes

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frm, text="Access Needs (master -> component [operation]):").pack(anchor="w")

        lb_frame = ttk.Frame(frm)
        lb_frame.pack(fill=tk.BOTH, expand=True, pady=4)
        self._lb = tk.Listbox(lb_frame, width=50, height=10)
        sb = ttk.Scrollbar(lb_frame, orient=tk.VERTICAL, command=self._lb.yview)
        self._lb.configure(yscrollcommand=sb.set)
        self._lb.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        btn_row = ttk.Frame(frm)
        btn_row.pack(fill=tk.X, pady=4)
        ttk.Button(btn_row, text="Add",    command=self._add).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="Remove", command=self._remove).pack(side=tk.LEFT, padx=2)

        ok_row = ttk.Frame(frm)
        ok_row.pack(fill=tk.X)
        ttk.Button(ok_row, text="OK",     command=self._ok).pack(side=tk.LEFT, padx=2)
        ttk.Button(ok_row, text="Cancel", command=self.destroy).pack(side=tk.LEFT)

        self._refresh()
        self.wait_window()

    def _refresh(self) -> None:
        self._lb.delete(0, tk.END)
        for an in self._needs:
            self._lb.insert(tk.END, f"{an.master} -> {an.component} ({an.operation})")

    def _add(self) -> None:
        masters = sorted(nd.name for nd in self._nodes.values()
                         if nd.comp_type in ("processor", "dma"))
        ips     = sorted(nd.name for nd in self._nodes.values()
                         if nd.comp_type == "ip_core")
        dlg = _AddAccessNeedDialog(self, masters, ips)
        if dlg.result:
            self._needs.append(AccessNeed(**dlg.result))
            self._refresh()

    def _remove(self) -> None:
        sel = self._lb.curselection()
        if not sel:
            return
        del self._needs[sel[0]]
        self._refresh()

    def _ok(self) -> None:
        self.result = list(self._needs)
        self.destroy()


class _AddAccessNeedDialog(tk.Toplevel):
    def __init__(self, parent: tk.Widget,
                 masters: List[str], ips: List[str]) -> None:
        super().__init__(parent)
        self.transient(parent)
        self.title("Add Access Need")
        self.resizable(False, False)
        self.grab_set()
        self.result: Optional[dict] = None

        frm = ttk.Frame(self, padding=12)
        frm.pack()

        ttk.Label(frm, text="Master:").grid(row=0, column=0, sticky="e", pady=2)
        self._master_cb = ttk.Combobox(frm, values=masters, width=20, state="readonly")
        if masters:
            self._master_cb.current(0)
        self._master_cb.grid(row=0, column=1, padx=4)

        ttk.Label(frm, text="Component:").grid(row=1, column=0, sticky="e", pady=2)
        self._comp_cb = ttk.Combobox(frm, values=ips, width=20, state="readonly")
        if ips:
            self._comp_cb.current(0)
        self._comp_cb.grid(row=1, column=1, padx=4)

        ttk.Label(frm, text="Operation:").grid(row=2, column=0, sticky="e", pady=2)
        self._op_cb = ttk.Combobox(frm, values=["read", "write"], width=20, state="readonly")
        self._op_cb.current(0)
        self._op_cb.grid(row=2, column=1, padx=4)

        btn_row = ttk.Frame(frm)
        btn_row.grid(row=3, column=0, columnspan=2, pady=(8, 0))
        ttk.Button(btn_row, text="OK",     command=self._ok).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="Cancel", command=self.destroy).pack(side=tk.LEFT)
        self.wait_window()

    def _ok(self) -> None:
        self.result = {
            "master":    self._master_cb.get(),
            "component": self._comp_cb.get(),
            "operation": self._op_cb.get(),
        }
        self.destroy()


# ---------------------------------------------------------------------------
# Services dialog (Group 2b)
# ---------------------------------------------------------------------------

class _ServicesDialog(tk.Toplevel):
    def __init__(self, parent: tk.Widget,
                 services: List[Service],
                 nodes: Dict[str, NodeData]) -> None:
        super().__init__(parent)
        self.transient(parent)
        self.title("Edit Services")
        self.grab_set()
        self.result: Optional[List[Service]] = None
        self._services: List[Service] = [Service(s.name, list(s.members), s.quorum)
                                          for s in services]
        self._nodes = nodes

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frm, text="Services:").pack(anchor="w")

        lb_frame = ttk.Frame(frm)
        lb_frame.pack(fill=tk.BOTH, expand=True, pady=4)
        self._lb = tk.Listbox(lb_frame, width=55, height=8)
        sb = ttk.Scrollbar(lb_frame, orient=tk.VERTICAL, command=self._lb.yview)
        self._lb.configure(yscrollcommand=sb.set)
        self._lb.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        btn_row = ttk.Frame(frm)
        btn_row.pack(fill=tk.X, pady=4)
        ttk.Button(btn_row, text="Add",    command=self._add).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="Edit",   command=self._edit).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="Remove", command=self._remove).pack(side=tk.LEFT, padx=2)

        ok_row = ttk.Frame(frm)
        ok_row.pack(fill=tk.X)
        ttk.Button(ok_row, text="OK",     command=self._ok).pack(side=tk.LEFT, padx=2)
        ttk.Button(ok_row, text="Cancel", command=self.destroy).pack(side=tk.LEFT)

        self._refresh()
        self.wait_window()

    def _refresh(self) -> None:
        self._lb.delete(0, tk.END)
        for sv in self._services:
            self._lb.insert(
                tk.END,
                f"{sv.name}: {', '.join(sv.members)} (quorum={sv.quorum})"
            )

    def _ip_names(self) -> List[str]:
        return sorted(nd.name for nd in self._nodes.values()
                      if nd.comp_type == "ip_core")

    def _add(self) -> None:
        dlg = _EditServiceDialog(self, None, self._ip_names())
        if dlg.result:
            self._services.append(Service(**dlg.result))
            self._refresh()

    def _edit(self) -> None:
        sel = self._lb.curselection()
        if not sel:
            return
        sv = self._services[sel[0]]
        dlg = _EditServiceDialog(self, sv, self._ip_names())
        if dlg.result:
            self._services[sel[0]] = Service(**dlg.result)
            self._refresh()

    def _remove(self) -> None:
        sel = self._lb.curselection()
        if not sel:
            return
        del self._services[sel[0]]
        self._refresh()

    def _ok(self) -> None:
        self.result = list(self._services)
        self.destroy()


class _EditServiceDialog(tk.Toplevel):
    def __init__(self, parent: tk.Widget,
                 service: Optional[Service],
                 ip_names: List[str]) -> None:
        super().__init__(parent)
        self.transient(parent)
        self.title("Edit Service")
        self.resizable(False, False)
        self.grab_set()
        self.result: Optional[dict] = None

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frm, text="Name:").grid(row=0, column=0, sticky="e", pady=2)
        self._name_e = ttk.Entry(frm, width=22)
        self._name_e.insert(0, service.name if service else "new_svc")
        self._name_e.grid(row=0, column=1, padx=4)

        ttk.Label(frm, text="Members (multi-select):").grid(row=1, column=0, sticky="ne", pady=2)
        lb_frame = ttk.Frame(frm)
        lb_frame.grid(row=1, column=1, padx=4, pady=2)
        self._member_lb = tk.Listbox(lb_frame, selectmode=tk.MULTIPLE,
                                      height=8, width=22, exportselection=False)
        sb = ttk.Scrollbar(lb_frame, orient=tk.VERTICAL, command=self._member_lb.yview)
        self._member_lb.configure(yscrollcommand=sb.set)
        self._member_lb.pack(side=tk.LEFT)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        for n in ip_names:
            self._member_lb.insert(tk.END, n)
        # Pre-select existing members
        if service:
            for i, n in enumerate(ip_names):
                if n in service.members:
                    self._member_lb.selection_set(i)

        ttk.Label(frm, text="Quorum:").grid(row=2, column=0, sticky="e", pady=2)
        self._quorum_sb = ttk.Spinbox(frm, from_=1, to=len(ip_names) or 1, width=8)
        self._quorum_sb.set(service.quorum if service else 1)
        self._quorum_sb.grid(row=2, column=1, sticky="w", padx=4)

        btn_row = ttk.Frame(frm)
        btn_row.grid(row=3, column=0, columnspan=2, pady=(8, 0))
        ttk.Button(btn_row, text="OK",     command=self._ok).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="Cancel", command=self.destroy).pack(side=tk.LEFT)
        self.wait_window()

    def _ok(self) -> None:
        sel = self._member_lb.curselection()
        members = [self._member_lb.get(i) for i in sel]
        try:
            quorum = int(self._quorum_sb.get())
        except ValueError:
            quorum = 1
        self.result = {
            "name":    self._name_e.get().strip() or "svc",
            "members": members,
            "quorum":  quorum,
        }
        self.destroy()


# ---------------------------------------------------------------------------
# FPGA Config dialog (Group 2c)
# ---------------------------------------------------------------------------

class _FPGAConfigDialog(tk.Toplevel):
    _CAP_LABELS = [
        ("max_luts",       "Max LUTs"),
        ("max_ffs",        "Max FFs"),
        ("max_dsps",       "Max DSPs"),
        ("max_lutram",     "Max LUTRAM"),
        ("max_bram",       "Max BRAMs"),
        ("max_bufgs",      "Max BUFGs"),
        ("max_power",        "Max Power (mW)"),
        ("max_security_risk", "Max Security Risk"),
        ("max_avail_risk",    "Max Avail Risk"),
        ("redundancy_beta_pct", "Redundancy Beta (%)"),
        ("max_attack_depth",  "Attack Depth"),
    ]

    def __init__(self, parent: tk.Widget, caps: dict) -> None:
        super().__init__(parent)
        self.transient(parent)
        self.title("FPGA Configuration")
        self.resizable(False, False)
        self.grab_set()
        self.result: Optional[dict] = None
        self._caps = dict(caps)
        self._entries: Dict[str, ttk.Entry] = {}

        frm = ttk.Frame(self, padding=12)
        frm.pack()

        for r, (key, label) in enumerate(self._CAP_LABELS):
            ttk.Label(frm, text=f"{label}:").grid(row=r, column=0, sticky="e", pady=2)
            e = ttk.Entry(frm, width=16)
            e.insert(0, str(self._caps.get(key, "")))
            e.grid(row=r, column=1, sticky="w", padx=4)
            self._entries[key] = e

        btn_row = ttk.Frame(frm)
        btn_row.grid(row=len(self._CAP_LABELS), column=0, columnspan=2, pady=(8, 0))
        ttk.Button(btn_row, text="OK",     command=self._ok).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="Cancel", command=self.destroy).pack(side=tk.LEFT)
        self.wait_window()

    def _ok(self) -> None:
        new_caps = dict(self._caps)
        try:
            for key, _ in self._CAP_LABELS:
                val_str = self._entries[key].get().strip()
                if val_str:
                    new_caps[key] = int(val_str)
        except ValueError as exc:
            messagebox.showerror("Validation Error", str(exc))
            return
        self.result = new_caps
        self.destroy()


# ---------------------------------------------------------------------------
# Mission Phases dialog (Group 2d)
# ---------------------------------------------------------------------------

class _MissionPhasesDialog(tk.Toplevel):
    def __init__(self, parent: tk.Widget, phases: List[str]) -> None:
        super().__init__(parent)
        self.transient(parent)
        self.title("Mission Phases")
        self.grab_set()
        self.result: Optional[List[str]] = None
        self._phases: List[str] = list(phases)

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frm, text="Mission phases:").pack(anchor="w")

        lb_frame = ttk.Frame(frm)
        lb_frame.pack(fill=tk.BOTH, expand=True, pady=4)
        self._lb = tk.Listbox(lb_frame, width=30, height=8)
        sb = ttk.Scrollbar(lb_frame, orient=tk.VERTICAL, command=self._lb.yview)
        self._lb.configure(yscrollcommand=sb.set)
        self._lb.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        btn_row = ttk.Frame(frm)
        btn_row.pack(fill=tk.X, pady=4)
        ttk.Button(btn_row, text="Add",    command=self._add).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="Remove", command=self._remove).pack(side=tk.LEFT, padx=2)

        ok_row = ttk.Frame(frm)
        ok_row.pack(fill=tk.X)
        ttk.Button(ok_row, text="OK",     command=self._ok).pack(side=tk.LEFT, padx=2)
        ttk.Button(ok_row, text="Cancel", command=self.destroy).pack(side=tk.LEFT)

        self._refresh()
        self.wait_window()

    def _refresh(self) -> None:
        self._lb.delete(0, tk.END)
        for p in self._phases:
            self._lb.insert(tk.END, p)

    def _add(self) -> None:
        name = simpledialog.askstring("Add Phase", "Phase name:", parent=self)
        if name and name.strip():
            self._phases.append(name.strip())
            self._refresh()

    def _remove(self) -> None:
        sel = self._lb.curselection()
        if not sel:
            return
        del self._phases[sel[0]]
        self._refresh()

    def _ok(self) -> None:
        self.result = list(self._phases)
        self.destroy()


# ---------------------------------------------------------------------------
# Policy Exceptions dialog (Group 2e)
# ---------------------------------------------------------------------------

class _PolicyExceptionsDialog(tk.Toplevel):
    def __init__(self, parent: tk.Widget, exceptions: List[dict]) -> None:
        super().__init__(parent)
        self.transient(parent)
        self.title("Policy Exceptions")
        self.grab_set()
        self.result: Optional[List[dict]] = None
        self._exceptions: List[dict] = list(exceptions)

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frm, text="Policy exceptions:").pack(anchor="w")

        lb_frame = ttk.Frame(frm)
        lb_frame.pack(fill=tk.BOTH, expand=True, pady=4)
        self._lb = tk.Listbox(lb_frame, width=60, height=8)
        sb = ttk.Scrollbar(lb_frame, orient=tk.VERTICAL, command=self._lb.yview)
        self._lb.configure(yscrollcommand=sb.set)
        self._lb.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        btn_row = ttk.Frame(frm)
        btn_row.pack(fill=tk.X, pady=4)
        ttk.Button(btn_row, text="Add",    command=self._add).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="Remove", command=self._remove).pack(side=tk.LEFT, padx=2)

        ok_row = ttk.Frame(frm)
        ok_row.pack(fill=tk.X)
        ttk.Button(ok_row, text="OK",     command=self._ok).pack(side=tk.LEFT, padx=2)
        ttk.Button(ok_row, text="Cancel", command=self.destroy).pack(side=tk.LEFT)

        self._refresh()
        self.wait_window()

    def _refresh(self) -> None:
        self._lb.delete(0, tk.END)
        for exc in self._exceptions:
            self._lb.insert(tk.END,
                f"{exc['master']},{exc['component']},{exc['operation']},"
                f"{exc.get('mode','maintenance')}: {exc.get('reason','')}")

    def _add(self) -> None:
        dlg = _EditExceptionDialog(self)
        if dlg.result:
            self._exceptions.append(dlg.result)
            self._refresh()

    def _remove(self) -> None:
        sel = self._lb.curselection()
        if not sel:
            return
        del self._exceptions[sel[0]]
        self._refresh()

    def _ok(self) -> None:
        self.result = list(self._exceptions)
        self.destroy()


class _EditExceptionDialog(tk.Toplevel):
    def __init__(self, parent: tk.Widget) -> None:
        super().__init__(parent)
        self.transient(parent)
        self.title("Add Policy Exception")
        self.resizable(False, False)
        self.grab_set()
        self.result: Optional[dict] = None

        frm = ttk.Frame(self, padding=12)
        frm.pack()

        def row_entry(label, default, r):
            ttk.Label(frm, text=label).grid(row=r, column=0, sticky="e", pady=2)
            e = ttk.Entry(frm, width=22)
            e.insert(0, str(default))
            e.grid(row=r, column=1, padx=4)
            return e

        self._master_e    = row_entry("Master:",    "",            0)
        self._comp_e      = row_entry("Component:", "",            1)

        ttk.Label(frm, text="Operation:").grid(row=2, column=0, sticky="e", pady=2)
        self._op_cb = ttk.Combobox(frm, values=["read", "write"], width=20, state="readonly")
        self._op_cb.current(0)
        self._op_cb.grid(row=2, column=1, padx=4)

        self._mode_e   = row_entry("Mode:",   "maintenance", 3)
        self._reason_e = row_entry("Reason:", "",            4)

        btn_row = ttk.Frame(frm)
        btn_row.grid(row=5, column=0, columnspan=2, pady=(8, 0))
        ttk.Button(btn_row, text="OK",     command=self._ok).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="Cancel", command=self.destroy).pack(side=tk.LEFT)
        self.wait_window()

    def _ok(self) -> None:
        self.result = {
            "master":    self._master_e.get().strip(),
            "component": self._comp_e.get().strip(),
            "operation": self._op_cb.get(),
            "mode":      self._mode_e.get().strip() or "maintenance",
            "reason":    self._reason_e.get().strip(),
        }
        self.destroy()


# ---------------------------------------------------------------------------
# Phase 3 Scenarios dialog (Group 3a)
# ---------------------------------------------------------------------------

class _ScenariosDialog(tk.Toplevel):
    def __init__(self, parent: tk.Widget, scenarios: List[dict]) -> None:
        super().__init__(parent)
        self.transient(parent)
        self.title("Phase 3 Scenarios")
        self.grab_set()
        self.result: Optional[List[dict]] = None

        # Load defaults from CORE_SCENARIOS if empty
        if scenarios:
            self._scenarios: List[dict] = [dict(s) for s in scenarios]
        else:
            from ..agents.phase3_agent import CORE_SCENARIOS
            self._scenarios = [dict(s) for s in CORE_SCENARIOS]

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frm, text="Scenarios (name | compromised | failed):").pack(anchor="w")

        lb_frame = ttk.Frame(frm)
        lb_frame.pack(fill=tk.BOTH, expand=True, pady=4)
        self._lb = tk.Listbox(lb_frame, width=70, height=10)
        sb = ttk.Scrollbar(lb_frame, orient=tk.VERTICAL, command=self._lb.yview)
        self._lb.configure(yscrollcommand=sb.set)
        self._lb.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        btn_row = ttk.Frame(frm)
        btn_row.pack(fill=tk.X, pady=4)
        ttk.Button(btn_row, text="Add",    command=self._add).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="Edit",   command=self._edit).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="Remove", command=self._remove).pack(side=tk.LEFT, padx=2)

        ok_row = ttk.Frame(frm)
        ok_row.pack(fill=tk.X)
        ttk.Button(ok_row, text="OK",     command=self._ok).pack(side=tk.LEFT, padx=2)
        ttk.Button(ok_row, text="Cancel", command=self.destroy).pack(side=tk.LEFT)

        self._refresh()
        self.wait_window()

    def _refresh(self) -> None:
        self._lb.delete(0, tk.END)
        for sc in self._scenarios:
            comp_str = ", ".join(sc.get("compromised", [])) or "—"
            fail_str = ", ".join(sc.get("failed", []))      or "—"
            self._lb.insert(
                tk.END,
                f"{sc['name']}  |  comp: {comp_str}  |  failed: {fail_str}"
            )

    def _add(self) -> None:
        dlg = _EditScenarioDialog(self, None)
        if dlg.result:
            self._scenarios.append(dlg.result)
            self._refresh()

    def _edit(self) -> None:
        sel = self._lb.curselection()
        if not sel:
            return
        dlg = _EditScenarioDialog(self, self._scenarios[sel[0]])
        if dlg.result:
            self._scenarios[sel[0]] = dlg.result
            self._refresh()

    def _remove(self) -> None:
        sel = self._lb.curselection()
        if not sel:
            return
        del self._scenarios[sel[0]]
        self._refresh()

    def _ok(self) -> None:
        self.result = list(self._scenarios)
        self.destroy()


class _EditScenarioDialog(tk.Toplevel):
    def __init__(self, parent: tk.Widget,
                 scenario: Optional[dict]) -> None:
        super().__init__(parent)
        self.transient(parent)
        self.title("Edit Scenario")
        self.resizable(False, False)
        self.grab_set()
        self.result: Optional[dict] = None

        frm = ttk.Frame(self, padding=12)
        frm.pack()

        ttk.Label(frm, text="Name:").grid(row=0, column=0, sticky="e", pady=2)
        self._name_e = ttk.Entry(frm, width=30)
        self._name_e.insert(0, scenario["name"] if scenario else "new_scenario")
        self._name_e.grid(row=0, column=1, padx=4)

        ttk.Label(frm, text="Compromised\n(comma-sep):").grid(row=1, column=0, sticky="e", pady=2)
        self._comp_e = ttk.Entry(frm, width=30)
        if scenario:
            self._comp_e.insert(0, ", ".join(scenario.get("compromised", [])))
        self._comp_e.grid(row=1, column=1, padx=4)

        ttk.Label(frm, text="Failed\n(comma-sep):").grid(row=2, column=0, sticky="e", pady=2)
        self._fail_e = ttk.Entry(frm, width=30)
        if scenario:
            self._fail_e.insert(0, ", ".join(scenario.get("failed", [])))
        self._fail_e.grid(row=2, column=1, padx=4)

        btn_row = ttk.Frame(frm)
        btn_row.grid(row=3, column=0, columnspan=2, pady=(8, 0))
        ttk.Button(btn_row, text="OK",     command=self._ok).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="Cancel", command=self.destroy).pack(side=tk.LEFT)
        self.wait_window()

    def _ok(self) -> None:
        comp_raw = self._comp_e.get().strip()
        fail_raw = self._fail_e.get().strip()
        self.result = {
            "name":        self._name_e.get().strip() or "scenario",
            "compromised": [x.strip() for x in comp_raw.split(",") if x.strip()],
            "failed":      [x.strip() for x in fail_raw.split(",") if x.strip()],
        }
        self.destroy()
