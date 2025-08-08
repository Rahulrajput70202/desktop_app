"""
Privacy Leak Analyzer — Professional Desktop (main.py)
- Modern UI using ttkbootstrap (if available)
- Threaded analysis using androguard (analyzer.py)
- PDF/JSON export using report_generator.py
Run: python main.py
"""
import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
try:
    import ttkbootstrap as tb
    from ttkbootstrap.constants import *
except Exception:
    tb = None
    print("ttkbootstrap not installed — UI will use plain tkinter ttk styles.")

from src.analyzer import analyze_apk
from src.report_generator import generate_pdf_report, save_json_report

APP_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(APP_DIR, "uploads") if os.path.isdir(os.path.join(APP_DIR, "uploads")) else os.path.join(APP_DIR, "reports")
REPORTS_DIR = os.path.join(APP_DIR, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Privacy Leak Analyzer — Pro")
        self.root.geometry("900x620")
        if tb:
            self.style = tb.Style("litera")
        else:
            import tkinter.ttk as ttk
            self.style = ttk.Style()

        self.selected_apk = ""
        self.result = None
        self._build_ui()

    def _build_ui(self):
        # Top toolbar
        top = tk.Frame(self.root, pady=8)
        top.pack(fill="x")

        self.lbl_file = tk.Label(top, text="No APK selected", anchor="w")
        self.lbl_file.pack(side="left", padx=12)

        btn_browse = tk.Button(top, text="Browse APK", command=self.browse_apk)
        btn_browse.pack(side="right", padx=8)
        btn_export_pdf = tk.Button(top, text="Export PDF", command=self.export_pdf)
        btn_export_pdf.pack(side="right", padx=8)
        btn_export_json = tk.Button(top, text="Export JSON", command=self.export_json)
        btn_export_json.pack(side="right", padx=8)
        btn_analyze = tk.Button(top, text="Analyze", command=self.start_analysis)
        btn_analyze.pack(side="right", padx=8)

        # Middle split: left (summary + progress + log) right (tables)
        middle = tk.Frame(self.root)
        middle.pack(fill="both", expand=True, padx=12, pady=6)

        left = tk.Frame(middle)
        left.pack(side="left", fill="y", padx=(0,8))

        summary_frame = tk.LabelFrame(left, text="Summary", padx=8, pady=8)
        summary_frame.pack(fill="x", pady=(0,8))
        self.lbl_app = tk.Label(summary_frame, text="App: -")
        self.lbl_app.pack(anchor="w")
        self.lbl_pkg = tk.Label(summary_frame, text="Package: -")
        self.lbl_pkg.pack(anchor="w")
        self.lbl_score = tk.Label(summary_frame, text="Risk Score: -")
        self.lbl_score.pack(anchor="w")

        prog_frame = tk.LabelFrame(left, text="Progress", padx=8, pady=8)
        prog_frame.pack(fill="x", pady=(0,8))
        import tkinter.ttk as ttk
        self.progress = ttk.Progressbar(prog_frame, orient="horizontal", length=200, mode="determinate")
        self.progress.pack(fill="x", padx=4, pady=4)

        log_frame = tk.LabelFrame(left, text="Analysis Log", padx=8, pady=8)
        log_frame.pack(fill="both", expand=True)
        self.txt_log = tk.Text(log_frame, height=12, state="disabled", wrap="word")
        self.txt_log.pack(fill="both", expand=True)

        right = tk.Frame(middle)
        right.pack(side="right", fill="both", expand=True)

        # Permissions list
        perms_frame = tk.LabelFrame(right, text="Permissions", padx=6, pady=6)
        perms_frame.pack(fill="both", expand=True, pady=(0,8))
        self.lst_perms = tk.Listbox(perms_frame)
        self.lst_perms.pack(fill="both", expand=True, padx=4, pady=4)

        risky_frame = tk.LabelFrame(right, text="Risky Permissions", padx=6, pady=6)
        risky_frame.pack(fill="x", pady=(0,8))
        self.lst_risky = tk.Listbox(risky_frame, height=6)
        self.lst_risky.pack(fill="x", padx=4, pady=4)

        apis_frame = tk.LabelFrame(right, text="Insecure APIs", padx=6, pady=6)
        apis_frame.pack(fill="both", expand=False)
        self.lst_apis = tk.Listbox(apis_frame, height=6)
        self.lst_apis.pack(fill="both", padx=4, pady=4)

    def browse_apk(self):
        path = filedialog.askopenfilename(filetypes=[("APK files", "*.apk")])
        if path:
            self.selected_apk = path
            self.lbl_file.config(text=path)
            self.log(f"Selected: {path}")

    def log(self, text):
        self.txt_log.config(state="normal")
        self.txt_log.insert("end", text + "\n")
        self.txt_log.see("end")
        self.txt_log.config(state="disabled")

    def start_analysis(self):
        if not self.selected_apk:
            messagebox.showwarning("No APK", "Please select an APK file first.")
            return
        # disable UI
        self.log("Starting analysis...")
        t = threading.Thread(target=self._analyze_thread, args=(self.selected_apk,), daemon=True)
        t.start()

    def _analyze_thread(self, apk_path):
        def progress_cb(pct, message=None):
            import time
            self.root.after(0, lambda: self.progress.config(value=pct))
            if message:
                self.root.after(0, lambda: self.log(message))

        try:
            result = analyze_apk(apk_path, progress_callback=progress_cb)
            self.result = result
            # update UI on main thread
            self.root.after(0, lambda: self._show_result(result))
            self.log("Analysis completed.")
        except Exception as e:
            self.log(f"Error: {e}")
            messagebox.showerror("Analysis Error", str(e))

    def _show_result(self, res):
        self.lbl_app.config(text=f"App: {res.get('app_name','-')}")
        self.lbl_pkg.config(text=f"Package: {res.get('package','-')}")
        self.lbl_score.config(text=f"Risk Score: {res.get('risk_score',0)} ({res.get('risk_level','-')})")

        self.lst_perms.delete(0, 'end')
        for p in res.get("permissions", []):
            self.lst_perms.insert('end', p)

        self.lst_risky.delete(0, 'end')
        for p in res.get("risky_permissions", []):
            self.lst_risky.insert('end', p)

        self.lst_apis.delete(0, 'end')
        for a in res.get("insecure_apis", []):
            self.lst_apis.insert('end', a)

    def export_pdf(self):
        if not self.result:
            messagebox.showinfo("No result", "Run an analysis first.")
            return
        try:
            path = generate_pdf_report(self.result, REPORTS_DIR)
            messagebox.showinfo("PDF Saved", f"Saved to: {path}")
            self.log(f"PDF exported: {path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def export_json(self):
        if not self.result:
            messagebox.showinfo("No result", "Run an analysis first.")
            return
        path = save_json_report(self.result, REPORTS_DIR)
        messagebox.showinfo("JSON Saved", f"Saved to: {path}")
        self.log(f"JSON exported: {path}")

def main():
    if tb:
        root = tb.Window(themename="litera")
    else:
        import tkinter as tk
        root = tk.Tk()
    app = App(root)
    root.mainloop()

if __name__ == '__main__':
    main()
