"""Desktop entry point; evidence stays in the selected local output folder."""
from __future__ import annotations

import contextlib
import datetime as dt
import os
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


class App:
    def __init__(self, root):
        self.root = root
        self.running = False
        self.output = None
        self.events = queue.Queue()
        root.title("Windows IR Lab | Sec Ops Syndicate")
        root.geometry("720x560")
        root.minsize(640, 520)
        frame = ttk.Frame(root, padding=24)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Windows IR Lab", font=("Segoe UI", 24, "bold")).pack(anchor="w")
        ttk.Label(frame, text="Collect evidence. Review findings. Build your investigation.").pack(anchor="w", pady=(0, 16))
        self.days = tk.StringVar(value="3")
        self.limit = tk.StringVar(value="400")
        self.folder = tk.StringVar(value=str(Path.home() / "Windows-IR-Lab-Reports"))
        self.browser = tk.BooleanVar(value=False)
        for label, var in (("Days to review (1–365)", self.days), ("Maximum events per log (1–100000)", self.limit)):
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
        self.progress = ttk.Progressbar(frame, mode="indeterminate")
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
