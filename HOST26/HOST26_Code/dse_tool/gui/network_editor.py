"""
network_editor.py
=================
Canvas-based interactive SoC network topology editor.

Supports:
- Drag-to-move nodes
- Right-click context menu (Edit, Delete, Add Link)
- Double-click to edit node properties
- Add/delete components and links
- Redundancy group highlighting
- Trust domain colour tinting
- TC9 example preload
- JSON save/load
- ASP facts export
"""

from __future__ import annotations

import json
import math
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from typing import Dict, List, Optional, Tuple

from ..core.asp_generator import (
    NetworkModel, Component, RedundancyGroup, Service,
    AccessNeed, ASPGenerator, make_tc9_network
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
    "low":  "#0000cc",  # blue overlay (bus master, less trusted)
    "high": "#cc0000",  # red overlay  (protected IP)
}

CANVAS_BG   = "#1a1a2e"
GRID_COLOUR = "#2a2a3e"

NODE_W, NODE_H = 90, 42   # default node bounding box
BUS_W,  BUS_H  = 120, 20  # bus bar dimensions


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
        latency_read: int = 1000,
        latency_write: int = 1000,
        has_rot: bool = False,
        has_sboot: bool = False,
        has_attest: bool = False,
    ) -> None:
        self.name         = name
        self.comp_type    = comp_type
        self.x            = x
        self.y            = y
        self.domain       = domain
        self.impact_read  = impact_read
        self.impact_write = impact_write
        self.latency_read = latency_read
        self.latency_write = latency_write
        self.has_rot      = has_rot
        self.has_sboot    = has_sboot
        self.has_attest   = has_attest

        # Canvas item IDs (set after draw)
        self.canvas_id: Optional[int] = None
        self.label_id:  Optional[int] = None

    def to_component(self) -> Component:
        """Convert to a core Component for ASP generation."""
        is_master    = self.comp_type in ("processor", "dma")
        is_receiver  = self.comp_type not in ("bus", "processor", "dma",
                                               "policy_server", "firewall")
        is_critical  = self.domain == "high" and is_receiver
        return Component(
            name=self.name,
            comp_type=self.comp_type,
            domain=self.domain,
            impact_read=self.impact_read,
            impact_write=self.impact_write,
            latency_read=self.latency_read,
            latency_write=self.latency_write,
            has_rot=self.has_rot,
            has_sboot=self.has_sboot,
            has_attest=self.has_attest,
            is_master=is_master,
            is_receiver=is_receiver,
            is_critical=is_critical,
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

        self._drag_node:    Optional[str]      = None
        self._drag_ox:      float              = 0.0
        self._drag_oy:      float              = 0.0
        self._link_src:     Optional[str]      = None
        self._selected:     Optional[str]      = None
        self._redund_sel:   List[str]          = []

        self._build_ui()
        self._draw_all()

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

        ttk.Button(sidebar, text="Load TC9 Example",
                   command=self.load_tc9_example).pack(fill=tk.X, pady=2)

        ttk.Separator(sidebar, orient="horizontal").pack(fill=tk.X, pady=4)

        ttk.Button(sidebar, text="Save JSON",
                   command=self._save_json).pack(fill=tk.X, pady=2)
        ttk.Button(sidebar, text="Load JSON",
                   command=self._load_json).pack(fill=tk.X, pady=2)

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

        # ── Grid ────────────────────────────────────────────────────────────
        self._draw_grid()

        # ── Bindings ────────────────────────────────────────────────────────
        self._canvas.bind("<ButtonPress-1>",   self._on_left_press)
        self._canvas.bind("<B1-Motion>",       self._on_drag)
        self._canvas.bind("<ButtonRelease-1>", self._on_left_release)
        self._canvas.bind("<Double-Button-1>", self._on_double_click)
        self._canvas.bind("<Button-3>",        self._on_right_click)

        # Tooltip variable
        self._tooltip_win: Optional[tk.Toplevel] = None

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

    def load_tc9_example(self) -> None:
        """Pre-populate the editor with the testCase9 topology."""
        self._clear_all(confirm=False)
        model = make_tc9_network()

        # Node positions (hand-tuned for TC9 layout)
        positions = {
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
        }

        # Build NodeData from model components + buses
        all_names = {c.name for c in model.components}
        for comp in model.components:
            x, y = positions.get(comp.name, (300, 300))
            nd = NodeData(
                name=comp.name,
                comp_type=comp.comp_type,
                x=x, y=y,
                domain=comp.domain,
                impact_read=comp.impact_read,
                impact_write=comp.impact_write,
                latency_read=comp.latency_read,
                latency_write=comp.latency_write,
                has_rot=comp.has_rot,
                has_sboot=comp.has_sboot,
                has_attest=comp.has_attest,
            )
            self.nodes[comp.name] = nd

        # Buses
        for bus_name in model.buses:
            if bus_name not in self.nodes:
                x, y = positions.get(bus_name, (350, 300))
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

        self._draw_all()
        self._notify_changed()

    def get_network_model(self) -> NetworkModel:
        """
        Build and return a NetworkModel from the current canvas state.
        """
        model = make_tc9_network()  # Use TC9 as base for ZTA/policy facts

        # Override components with canvas nodes
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
        model.access_needs = list(self.access_needs)
        model.services     = list(self.services)
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
        }
        for name, nd in self.nodes.items():
            data["nodes"].append({
                "name": nd.name, "comp_type": nd.comp_type,
                "x": nd.x, "y": nd.y,
                "domain": nd.domain,
                "impact_read": nd.impact_read, "impact_write": nd.impact_write,
                "latency_read": nd.latency_read, "latency_write": nd.latency_write,
                "has_rot": nd.has_rot, "has_sboot": nd.has_sboot,
                "has_attest": nd.has_attest,
            })
        return data

    def load_from_json(self, data: dict) -> None:
        """Load network state from a JSON-compatible dict."""
        self._clear_all(confirm=False)
        for nd_data in data.get("nodes", []):
            nd = NodeData(**{k: v for k, v in nd_data.items()})
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
        self._draw_all()
        self._notify_changed()

    # ------------------------------------------------------------------
    # Drawing
    # ------------------------------------------------------------------

    def _draw_all(self) -> None:
        """Redraw the entire canvas."""
        self._canvas.delete("node", "link", "label", "redund")
        self._draw_redundancy_groups()
        self._draw_links()
        self._draw_nodes()

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
                x0, y0, x1, y1,
                dash=(6, 4),
                outline=colour,
                fill="",
                width=2,
                tags="redund",
            )
            self._canvas.create_text(
                x0 + 4, y0 + 4,
                text=f"Group {grp['group_id']}",
                fill=colour,
                anchor="nw",
                font=("Arial", 8),
                tags="redund",
            )

    def _draw_links(self) -> None:
        """Draw all links as arrows."""
        for lk in self.links:
            src_nd = self.nodes.get(lk.src)
            dst_nd = self.nodes.get(lk.dst)
            if src_nd is None or dst_nd is None:
                continue
            sx, sy = src_nd.x + NODE_W / 2, src_nd.y + NODE_H / 2
            dx, dy = dst_nd.x + NODE_W / 2, dst_nd.y + NODE_H / 2
            item = self._canvas.create_line(
                sx, sy, dx, dy,
                fill="#aaaaaa",
                arrow=tk.LAST,
                arrowshape=(8, 10, 4),
                width=1.5,
                tags="link",
            )
            lk.canvas_id = item

    def _draw_nodes(self) -> None:
        """Draw all nodes on the canvas."""
        for name, nd in self.nodes.items():
            self._draw_single_node(nd)

    def _draw_single_node(self, nd: NodeData) -> None:
        """Draw one node, applying shape based on comp_type."""
        style  = NODE_TYPE_STYLES.get(nd.comp_type, NODE_TYPE_STYLES["ip_core"])
        fill   = style["fill"]
        outline = style["outline"]
        shape  = style["shape"]
        x, y   = nd.x, nd.y

        # Domain tint overlay (slightly transparent via colour mixing)
        if nd.domain == "low":
            fill = self._mix_colour(fill, "#0000cc", 0.25)
        elif nd.domain == "high":
            fill = self._mix_colour(fill, "#cc0000", 0.15)

        tag = ("node", f"node_{nd.name}")

        if shape == "roundrect":
            item = self._canvas.create_rectangle(
                x, y, x + NODE_W, y + NODE_H,
                fill=fill, outline=outline, width=2, tags=tag
            )
        elif shape == "oval":
            item = self._canvas.create_oval(
                x, y, x + NODE_W, y + NODE_H,
                fill=fill, outline=outline, width=2, tags=tag
            )
        elif shape == "diamond":
            cx, cy = x + NODE_W / 2, y + NODE_H / 2
            hw, hh = NODE_W / 2, NODE_H / 2
            pts = [cx, cy - hh, cx + hw, cy, cx, cy + hh, cx - hw, cy]
            item = self._canvas.create_polygon(
                pts, fill=fill, outline=outline, width=2, tags=tag
            )
        elif shape == "hexagon":
            cx, cy = x + NODE_W / 2, y + NODE_H / 2
            r = NODE_H / 2
            pts = []
            for i in range(6):
                angle = math.radians(60 * i - 30)
                pts += [cx + r * math.cos(angle), cy + r * math.sin(angle)]
            item = self._canvas.create_polygon(
                pts, fill=fill, outline=outline, width=2, tags=tag
            )
        else:  # rect
            w = BUS_W if nd.comp_type == "bus" else NODE_W
            h = BUS_H if nd.comp_type == "bus" else NODE_H
            item = self._canvas.create_rectangle(
                x, y, x + w, y + h,
                fill=fill, outline=outline, width=2, tags=tag
            )

        nd.canvas_id = item

        # Label
        lbl = self._canvas.create_text(
            x + NODE_W / 2, y + NODE_H / 2,
            text=nd.name,
            fill="white",
            font=("Arial", 8, "bold"),
            tags=("label", f"label_{nd.name}"),
        )
        nd.label_id = lbl

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _on_left_press(self, event: tk.Event) -> None:
        """Handle left mouse button press — begin drag or link placement."""
        cx = self._canvas.canvasx(event.x)
        cy = self._canvas.canvasy(event.y)
        name = self._hit_test(cx, cy)

        if self._link_src is not None:
            # We're in link-placement mode
            if name and name != self._link_src:
                self.links.append(LinkData(self._link_src, name))
                self._draw_all()
                self._notify_changed()
            self._link_src = None
            self._canvas.configure(cursor="")
            return

        if name:
            self._drag_node = name
            nd = self.nodes[name]
            self._drag_ox = cx - nd.x
            self._drag_oy = cy - nd.y
            self._selected = name

    def _on_drag(self, event: tk.Event) -> None:
        """Handle drag motion."""
        if self._drag_node is None:
            return
        cx = self._canvas.canvasx(event.x)
        cy = self._canvas.canvasy(event.y)
        nd = self.nodes[self._drag_node]
        nd.x = cx - self._drag_ox
        nd.y = cy - self._drag_oy
        self._draw_all()

    def _on_left_release(self, event: tk.Event) -> None:
        """Handle drag end."""
        if self._drag_node:
            self._notify_changed()
        self._drag_node = None

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
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Edit Properties",
                         command=lambda: self._edit_node_dialog(name))
        menu.add_command(label="Add Link from here",
                         command=lambda: self._start_link_from(name))
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
        for name, nd in self.nodes.items():
            w = BUS_W if nd.comp_type == "bus" else NODE_W
            h = BUS_H if nd.comp_type == "bus" else NODE_H
            if nd.x <= cx <= nd.x + w and nd.y <= cy <= nd.y + h:
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
        # Override: next left-click selects source
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
        dlg = _NodeEditDialog(self, title="Add Component", node=None)
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
            # Rename if needed
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
        self._canvas.delete("node", "link", "label", "redund")
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
    # Utilities
    # ------------------------------------------------------------------

    def _notify_changed(self) -> None:
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
# Property editor dialog
# ---------------------------------------------------------------------------

class _NodeEditDialog(tk.Toplevel):
    """Modal dialog for editing node properties."""

    COMP_TYPES = ["processor", "dma", "ip_core", "bus",
                  "policy_server", "firewall"]
    DOMAINS    = ["low", "high"]

    def __init__(self, parent: tk.Widget, title: str, node: Optional[NodeData]) -> None:
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.grab_set()
        self.result: Optional[dict] = None

        # Defaults
        name       = node.name       if node else "new_comp"
        comp_type  = node.comp_type  if node else "ip_core"
        domain     = node.domain     if node else "high"
        ir         = node.impact_read  if node else 3
        iw         = node.impact_write if node else 3
        lr         = node.latency_read  if node else 1000
        lw         = node.latency_write if node else 1000
        rot        = node.has_rot    if node else False
        sboot      = node.has_sboot  if node else False
        attest     = node.has_attest if node else False

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
        self._ir_e     = row_entry("Impact Read (1-5):",    ir,        3)
        self._iw_e     = row_entry("Impact Write (1-5):",   iw,        4)
        self._lr_e     = row_entry("Latency Read (cycles):", lr,       5)
        self._lw_e     = row_entry("Latency Write (cycles):",lw,       6)
        self._rot_v    = row_check("Has Hardware RoT:",     rot,       7)
        self._sboot_v  = row_check("Has Secure Boot:",      sboot,     8)
        self._attest_v = row_check("Has Attestation:",      attest,    9)

        btn_frm = ttk.Frame(frm)
        btn_frm.grid(row=10, column=0, columnspan=2, pady=(8, 0))
        ttk.Button(btn_frm, text="OK",     command=self._ok).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frm, text="Cancel", command=self.destroy).pack(side=tk.LEFT)

        self.wait_window()

    def _ok(self) -> None:
        try:
            self.result = {
                "name":          self._name_e.get().strip(),
                "comp_type":     self._type_cb.get(),
                "domain":        self._dom_cb.get(),
                "impact_read":   int(self._ir_e.get()),
                "impact_write":  int(self._iw_e.get()),
                "latency_read":  int(self._lr_e.get()),
                "latency_write": int(self._lw_e.get()),
                "has_rot":       self._rot_v.get(),
                "has_sboot":     self._sboot_v.get(),
                "has_attest":    self._attest_v.get(),
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
