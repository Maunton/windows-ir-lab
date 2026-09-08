"""Desktop entry point; evidence stays in the selected local output folder."""
from __future__ import annotations

import contextlib
import datetime as dt
import os
import math
from pathlib import Path
import queue
import tempfile
import threading
import traceback
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import windows_ir_reporter as reporter


def validate_options(days, max_events):
    try:
        days, max_events = int(days), int(max_events)
    except (TypeError, ValueError):
        raise ValueError("Days and event limit must be whole numbers.") from None
    if not 1 <= days <= 365:
        raise ValueError("Days must be between 1 and 365.")
    if not 1 <= max_events <= 100000:
        raise ValueError("Event limit must be between 1 and 100000.")
    return days, max_events


def create_run_folder(parent):
    parent = Path(parent).expanduser().resolve()
    parent.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=dt.datetime.now().strftime("run-%Y%m%d-%H%M%S-"), dir=parent))


class HoppingBunny(tk.Canvas):
    """Small vector bunny; animation runs only on Tk's event loop."""
    def __init__(self, parent):
        super().__init__(parent, height=88, background="#eef7ee", highlightthickness=0)
        self.tick = 0
        self.active = False
        self.timer = None
        self.bind("<Configure>", lambda event: self.draw())
        self.draw()

    def draw(self):
        self.delete("all")
        width = max(self.winfo_width(), 200)
        phase = self.tick / 9
        x = 48 + (width - 96) * (0.5 - 0.5 * math.cos(self.tick / 65)) if self.active else 48
        hop = abs(math.sin(phase)) * 10 if self.active else 0
        y = 57 - hop
        self.create_line(14, 76, width - 14, 76, fill="#bad9b9", width=2)
        self.create_oval(x - 19 + hop / 4, 72, x + 22 - hop / 4, 79, fill="#ccdfc9", outline="")
        for gx in range(24, width - 10, 77):
            self.create_line(gx, 75, gx - 3, 70, fill="#8eb68a", width=2)
            self.create_line(gx, 75, gx + 4, 68, fill="#8eb68a", width=2)
        # Tail, body, feet, ears and face; all drawn locally, no image dependencies.
        self.create_oval(x - 28, y - 3, x - 11, y + 13, fill="white", outline="#d9d5db")
        self.create_oval(x - 20, y - 11, x + 18, y + 16, fill="#fffafd", outline="#d9d5db", width=2)
        self.create_oval(x - 12, y + 9, x + 3, y + 19, fill="white", outline="#d9d5db")
        self.create_oval(x + 5, y + 10, x + 23, y + 19, fill="white", outline="#d9d5db")
        self.create_oval(x + 1, y - 43, x + 12, y - 9, fill="white", outline="#d9d5db", width=2)
        self.create_oval(x + 14, y - 46, x + 25, y - 11, fill="white", outline="#d9d5db", width=2)
        self.create_oval(x + 5, y - 38, x + 9, y - 17, fill="#f3b9cd", outline="")
        self.create_oval(x + 18, y - 41, x + 22, y - 17, fill="#f3b9cd", outline="")
        self.create_oval(x - 2, y - 21, x + 31, y + 9, fill="white", outline="#d9d5db", width=2)
        for eye in (8, 23):
            self.create_oval(x + eye, y - 10, x + eye + 3, y - 6, fill="#403846", outline="")
        for cheek in (3, 25):
            self.create_oval(x + cheek, y - 4, x + cheek + 6, y, fill="#f8d1df", outline="")
        self.create_polygon(x + 15, y - 3, x + 20, y - 3, x + 17.5, y, fill="#d984a3", outline="")
        self.create_line(x + 17.5, y, x + 15, y + 3, fill="#8e6b7e", smooth=True)
        self.create_line(x + 17.5, y, x + 20, y + 3, fill="#8e6b7e", smooth=True)
        if not self.active:
            self.create_text(94, 46, text="Ready when you are", anchor="w", fill="#567453", font=("Segoe UI", 10))

    def animate(self):
        self.timer = None
        if self.active:
            self.tick += 1
            self.draw()
            self.timer = self.after(40, self.animate)

    def start(self):
        if not self.active:
            self.active = True
            self.tick = 0
            self.animate()

    def stop(self):
        self.active = False
        if self.timer is not None:
            self.after_cancel(self.timer)
            self.timer = None
        self.draw()


class App:
    def __init__(self, root):
        self.root = root
        self.running = False
        self.output = None
        self.events = queue.Queue()
        root.title("Windows IR Lab 0.2.1-preview | Sec Ops Syndicate")
        root.geometry("720x650")
        root.minsize(640, 650)
        frame = ttk.Frame(root, padding=24)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Windows IR Lab", font=("Segoe UI", 24, "bold")).pack(anchor="w")
        ttk.Label(frame, text="Collect evidence. Review findings. Build your investigation.").pack(anchor="w", pady=(0, 16))
        self.days = tk.StringVar(value="3")
        self.limit = tk.StringVar(value="400")
        self.folder = tk.StringVar(value=str(Path.home() / "Windows-IR-Lab-Reports"))
        self.browser = tk.BooleanVar(value=False)
        for label, var in (("Days to review (1–365)", self.days), ("Maximum events per query (Sysmon: three separate groups)", self.limit)):
            ttk.Label(frame, text=label).pack(anchor="w")
            ttk.Entry(frame, textvariable=var).pack(fill="x", pady=(3, 8))
        ttk.Label(frame, text="Save reports in").pack(anchor="w")
        row = ttk.Frame(frame)
        row.pack(fill="x", pady=(3, 8))
        ttk.Entry(row, textvariable=self.folder).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Browse…", command=self.browse).pack(side="right", padx=(8, 0))
        ttk.Checkbutton(frame, text="Include this Windows user's browser history (URLs and downloads)", variable=self.browser).pack(anchor="w")
        admin = "Administrator access available." if reporter.is_admin() else "Limited access: protected logs may require Run as administrator."
        ttk.Label(frame, text=admin, wraplength=650).pack(anchor="w", pady=(12, 4))
        ttk.Label(frame, text="Reports may contain usernames, command lines, paths and other sensitive data.\nReview before sharing. Missing logs or no detections do not prove a PC is clean.", wraplength=650).pack(anchor="w", pady=(0, 12))
        self.start_button = ttk.Button(frame, text="Generate reports", command=self.start)
        self.start_button.pack(anchor="w")
        self.progress = HoppingBunny(frame)
        self.progress.pack(fill="x", pady=12)
        self.status = tk.StringVar(value="Ready. Sysmon is optional; logging settings affect coverage.")
        ttk.Label(frame, textvariable=self.status, wraplength=650).pack(anchor="w")
        self.open_button = ttk.Button(frame, text="Open report folder", command=self.open_folder, state="disabled")
        self.open_button.pack(anchor="w", pady=12)
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.after(150, self.poll)

    def browse(self):
        folder = filedialog.askdirectory(parent=self.root)
        if folder:
            self.folder.set(folder)

    def start(self):
        if self.running:
            return
        if not reporter.is_admin() and not messagebox.askyesno(
            "Administrator access recommended",
            "This app is not running as administrator. Security and Sysmon collection may fail.\n\n"
            "Choose No, close the app, then right-click the EXE and select Run as administrator.\n\n"
            "Continue with limited access?", parent=self.root):
            return
        try:
            days, limit = validate_options(self.days.get(), self.limit.get())
            if not self.folder.get().strip():
                raise ValueError("Choose an output folder.")
            output = create_run_folder(self.folder.get())
        except (ValueError, OSError) as exc:
            messagebox.showerror("Check settings", str(exc), parent=self.root)
            return
        argv = ["--days", str(days), "--max-events", str(limit), "--outdir", str(output)]
        if not self.browser.get():
            argv.append("--skip-browser-history")
        self.output = output
        self.running = True
        self.start_button.configure(state="disabled")
        self.open_button.configure(state="disabled")
        self.status.set("Collecting evidence and generating reports. This can take several minutes…")
        self.progress.start()
        threading.Thread(target=self.worker, args=(argv, output), daemon=True).start()

    def worker(self, argv, output):
        try:
            with (output / "collection.log").open("w", encoding="utf-8") as log:
                with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
                    try:
                        code = reporter.main(argv)
                    except Exception:
                        traceback.print_exc()
                        raise
            if code:
                raise RuntimeError("Collection failed. See collection.log in the report folder.")
            self.events.put((True, "Reports saved. Review telemetry coverage and collection errors in the reports."))
        except Exception as exc:
            self.events.put((False, f"Collection failed: {exc}. See collection.log if available."))

    def poll(self):
        try:
            success, message = self.events.get_nowait()
        except queue.Empty:
            pass
        else:
            self.running = False
            self.progress.stop()
            self.start_button.configure(state="normal")
            self.open_button.configure(state="normal")
            self.status.set(message)
            if not success:
                messagebox.showerror("Collection error", message, parent=self.root)
        self.root.after(150, self.poll)

    def open_folder(self):
        if self.output:
            try:
                os.startfile(str(self.output))
            except OSError as exc:
                messagebox.showerror("Cannot open folder", str(exc), parent=self.root)

    def close(self):
        if self.running:
            messagebox.showinfo("Collection in progress", "Wait for collection to finish before closing the app.", parent=self.root)
            return
        self.root.destroy()


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
