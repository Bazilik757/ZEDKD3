import tkinter as tk
from tkinter import ttk
from typing import Any, Dict, List


class RowEditorDialog(tk.Toplevel):
    def __init__(self, parent, title: str, columns: List[str], initial: Dict[str, Any] | None = None):
        super().__init__(parent)
        self.title(title)
        self.resizable(True, True)
        self.result: Dict[str, Any] | None = None
        self.columns = columns
        self.initial = initial or {}

        self.geometry("760x520")

        container = ttk.Frame(self, padding=10)
        container.pack(fill="both", expand=True)

        canvas = tk.Canvas(container)
        scroll_y = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        frame = ttk.Frame(canvas)

        frame.bind("<Configure>", lambda event: canvas.configure(scrollregion=canvas.bbox("all")))

        canvas.create_window((0, 0), window=frame, anchor="nw")
        canvas.configure(yscrollcommand=scroll_y.set)

        canvas.pack(side="left", fill="both", expand=True)
        scroll_y.pack(side="right", fill="y")

        self._canvas = canvas
        self._bind_scroll_events()

        self.vars: Dict[str, tk.StringVar] = {}
        for idx, column in enumerate(columns):
            ttk.Label(frame, text=column).grid(row=idx, column=0, sticky="w", padx=5, pady=4)
            var = tk.StringVar(value=self.initial.get(column, ""))
            self.vars[column] = var
            entry = ttk.Entry(frame, textvariable=var, width=60)
            entry.grid(row=idx, column=1, sticky="we", padx=5, pady=4)

        frame.grid_columnconfigure(1, weight=1)

        btns = ttk.Frame(self, padding=10)
        btns.pack(fill="x")

        ttk.Button(btns, text="ОК", command=self.on_ok).pack(side="right", padx=6)
        ttk.Button(btns, text="Отмена", command=self.on_cancel).pack(side="right")

    def _bind_scroll_events(self) -> None:
        self._canvas.bind("<Enter>", self._enable_wheel_scroll)
        self._canvas.bind("<Leave>", self._disable_wheel_scroll)
        self._canvas.bind("<ButtonPress-2>", self._start_drag_scroll)
        self._canvas.bind("<B2-Motion>", self._drag_scroll)

    def _enable_wheel_scroll(self, _event) -> None:
        self.bind_all("<MouseWheel>", self._on_mousewheel)
        self.bind_all("<Button-4>", self._on_mousewheel)
        self.bind_all("<Button-5>", self._on_mousewheel)

    def _disable_wheel_scroll(self, _event) -> None:
        self.unbind_all("<MouseWheel>")
        self.unbind_all("<Button-4>")
        self.unbind_all("<Button-5>")

    def _start_drag_scroll(self, event) -> None:
        self._canvas.scan_mark(event.x, event.y)

    def _drag_scroll(self, event) -> None:
        self._canvas.scan_dragto(event.x, event.y, gain=1)

    def _on_mousewheel(self, event) -> None:
        if event.num == 4:
            delta = -1
        elif event.num == 5:
            delta = 1
        else:
            delta = int(-1 * (event.delta / 120))

        self._canvas.yview_scroll(delta, "units")

    def on_ok(self):
        self.result = {c: v.get().strip() for c, v in self.vars.items()}
        self.destroy()

    def on_cancel(self):
        self.result = None
        self.destroy()
