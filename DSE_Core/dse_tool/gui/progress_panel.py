"""
progress_panel.py
=================
Live agent progress log panel.

Thread-safe: messages are posted to a queue.Queue and polled on the main
Tkinter thread via root.after().
"""

from __future__ import annotations

import queue
import tkinter as tk
from tkinter import ttk
from typing import Optional


# Colour scheme for log levels
LEVEL_COLOURS = {
    "INFO":    "#e0e0e0",   # near-white
    "SUCCESS": "#66ff66",   # green
    "WARNING": "#ffcc00",   # yellow
    "ERROR":   "#ff5555",   # red
    "PHASE":   "#00ccff",   # cyan (used for phase headers — bold)
    "DEBUG":   "#aaaaaa",   # grey
}

# Phase indicator colours
INDICATOR_GREY   = "#555555"
INDICATOR_YELLOW = "#ffcc00"
INDICATOR_GREEN  = "#44ff44"
INDICATOR_RED    = "#ff4444"


class ProgressPanel(ttk.Frame):
    """
    Scrolling log panel with coloured output and phase status indicators.

    Parameters
    ----------
    parent : tk.Widget
        Parent widget.
    progress_queue : queue.Queue
        Queue of (level, message) tuples posted by agent threads.
    poll_interval_ms : int
        How often (ms) to poll the queue for new messages.
    """

    def __init__(
        self,
        parent: tk.Widget,
        progress_queue: queue.Queue,
        poll_interval_ms: int = 100,
        **kwargs,
    ) -> None:
        super().__init__(parent, **kwargs)
        self.progress_queue   = progress_queue
        self.poll_interval_ms = poll_interval_ms

        self._build_ui()
        self._poll()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Build the log text area, phase indicators, and control buttons."""
        # ── Phase indicators row ────────────────────────────────────────────
        indicator_frame = ttk.Frame(self)
        indicator_frame.pack(side=tk.TOP, fill=tk.X, padx=4, pady=4)

        ttk.Label(indicator_frame, text="Phase Status:").pack(side=tk.LEFT, padx=(0, 8))

        self._phase_canvases: list = []
        self._phase_ovals:    list = []
        for phase_num in range(1, 4):
            fr = ttk.Frame(indicator_frame)
            fr.pack(side=tk.LEFT, padx=4)
            cv = tk.Canvas(fr, width=18, height=18, bg="#2b2b2b", highlightthickness=0)
            cv.pack(side=tk.LEFT)
            oval = cv.create_oval(2, 2, 16, 16, fill=INDICATOR_GREY, outline="")
            self._phase_canvases.append(cv)
            self._phase_ovals.append(oval)
            ttk.Label(fr, text=f" Phase {phase_num}").pack(side=tk.LEFT)

        # ── Timer ───────────────────────────────────────────────────────────
        self._timer_var = tk.StringVar(value="00:00")
        ttk.Label(indicator_frame, textvariable=self._timer_var,
                  font=("Courier", 10)).pack(side=tk.RIGHT, padx=8)
        ttk.Label(indicator_frame, text="Elapsed:").pack(side=tk.RIGHT)

        # ── Log text widget ─────────────────────────────────────────────────
        log_frame = ttk.Frame(self)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))

        self._log_text = tk.Text(
            log_frame,
            state=tk.DISABLED,
            bg="#1e1e1e",
            fg="#e0e0e0",
            font=("Courier New", 9),
            wrap=tk.WORD,
            relief=tk.FLAT,
        )
        scrollbar = ttk.Scrollbar(log_frame, command=self._log_text.yview)
        self._log_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self._log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Configure text tags for each level
        for level, colour in LEVEL_COLOURS.items():
            font = ("Courier New", 9, "bold") if level == "PHASE" else ("Courier New", 9)
            self._log_text.tag_configure(level, foreground=colour, font=font)

        # ── Clear button ────────────────────────────────────────────────────
        btn_frame = ttk.Frame(self)
        btn_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=4, pady=2)
        ttk.Button(btn_frame, text="Clear Log", command=self.clear_log).pack(
            side=tk.RIGHT
        )

        # Elapsed timer state
        self._elapsed_s: int  = 0
        self._timer_running   = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def post(self, level: str, message: str) -> None:
        """
        Append a message to the log (call from any thread — not directly
        from a non-GUI thread: use the queue instead).
        """
        self._append_line(level, message)

    def clear_log(self) -> None:
        """Clear all log content."""
        self._log_text.configure(state=tk.NORMAL)
        self._log_text.delete("1.0", tk.END)
        self._log_text.configure(state=tk.DISABLED)

    def set_phase_state(self, phase: int, state: str) -> None:
        """
        Update a phase indicator circle.

        Parameters
        ----------
        phase : int
            1, 2, or 3.
        state : str
            "waiting" | "running" | "done" | "error"
        """
        colour_map = {
            "waiting": INDICATOR_GREY,
            "running": INDICATOR_YELLOW,
            "done":    INDICATOR_GREEN,
            "error":   INDICATOR_RED,
        }
        idx = phase - 1
        if 0 <= idx < len(self._phase_canvases):
            colour = colour_map.get(state, INDICATOR_GREY)
            self._phase_canvases[idx].itemconfig(self._phase_ovals[idx], fill=colour)

    def start_timer(self) -> None:
        """Start the elapsed time counter."""
        self._elapsed_s     = 0
        self._timer_running = True
        self._tick()

    def stop_timer(self) -> None:
        """Stop the elapsed time counter."""
        self._timer_running = False

    def reset_indicators(self) -> None:
        """Reset all phase indicators to waiting (grey)."""
        for phase in range(1, 4):
            self.set_phase_state(phase, "waiting")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _poll(self) -> None:
        """Poll the queue for new messages and schedule next poll."""
        try:
            while True:
                level, msg = self.progress_queue.get_nowait()
                self._append_line(level, msg)
                # Update phase indicators from message content
                self._update_indicator_from_msg(level, msg)
        except queue.Empty:
            pass
        self.after(self.poll_interval_ms, self._poll)

    def _append_line(self, level: str, message: str) -> None:
        """Append one line to the text widget with the appropriate colour tag."""
        tag = level if level in LEVEL_COLOURS else "INFO"
        self._log_text.configure(state=tk.NORMAL)
        self._log_text.insert(tk.END, message + "\n", tag)
        self._log_text.see(tk.END)
        self._log_text.configure(state=tk.DISABLED)

    def _update_indicator_from_msg(self, level: str, msg: str) -> None:
        """Heuristically update phase indicators from progress message content."""
        lower = msg.lower()
        for phase_num in range(1, 4):
            tag = f"phase {phase_num}"
            if tag in lower or f"[phase {phase_num}" in lower:
                if "starting" in lower or "solving" in lower or "running" in lower:
                    self.set_phase_state(phase_num, "running")
                elif "done" in lower or "complete" in lower:
                    self.set_phase_state(phase_num, "done")
                elif "error" in lower or "unsat" in lower or "timeout" in lower:
                    self.set_phase_state(phase_num, "error")

    def _tick(self) -> None:
        """Update the elapsed timer every second."""
        if not self._timer_running:
            return
        self._elapsed_s += 1
        mins = self._elapsed_s // 60
        secs = self._elapsed_s % 60
        self._timer_var.set(f"{mins:02d}:{secs:02d}")
        self.after(1000, self._tick)
