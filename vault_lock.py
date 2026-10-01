"""
VaultLock — Native Format Password Protection for Windows
─────────────────────────────────────────────────────────
• PDF              → native PDF AES-256 password  (opens in Chrome/Acrobat/Edge — asks password)
• Office/Other/Media → AES-256 encrypted ZIP      (opens in 7-Zip/WinRAR — asks password)

No extra storage — files are modified in-place.
Requires:  pip install pikepdf pyzipper
"""

import os
import io
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from typing import List

# ── Dependency checks ─────────────────────────────────────────────────────────
missing = []
try:
    import pikepdf
except ImportError:
    missing.append("pikepdf")

try:
    import pyzipper
except ImportError:
    missing.append("pyzipper")

if missing:
    import tkinter as _tk
    _r = _tk.Tk(); _r.withdraw()
    messagebox.showerror(
        "Missing Dependencies",
        "Please install missing packages:\n\n"
        f"  pip install {' '.join(missing)}\n\nThen restart VaultLock."
    )
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# File-type routing
# ─────────────────────────────────────────────────────────────────────────────

PDF_EXTS         = {".pdf"}
PROTECTED_MARKER = ".vlkzip"   # extension appended to all non-PDF files when protected


def get_strategy(path: str) -> str:
    """Return 'pdf' or 'zip'."""
    if Path(path).suffix.lower() in PDF_EXTS:
        return "pdf"
    return "zip"


# ─────────────────────────────────────────────────────────────────────────────
# PDF — native pikepdf AES-256 encryption (no extension change)
# Chrome / Acrobat / Edge will ask for the password to open.
# ─────────────────────────────────────────────────────────────────────────────

def protect_pdf(path: str, password: str) -> str:
    """Apply AES-256 user+owner password to a PDF in-place. Returns unchanged path."""
    p = Path(path)
    with pikepdf.open(str(p)) as pdf:
        if pdf.is_encrypted:
            raise ValueError("PDF is already password-protected.")
        buf = io.BytesIO()
        pdf.save(
            buf,
            encryption=pikepdf.Encryption(
                user=password,
                owner=password,
                aes=True,
                R=6,   # PDF 2.0 / AES-256
            )
        )
    p.write_bytes(buf.getvalue())
    return str(p)


def unprotect_pdf(path: str, password: str) -> str:
    """Remove password protection from a PDF in-place. Returns unchanged path."""
    p = Path(path)
    try:
        with pikepdf.open(str(p), password=password) as pdf:
            buf = io.BytesIO()
            pdf.save(buf)
    except pikepdf.PasswordError as e:
        raise ValueError("Wrong password.") from e
    p.write_bytes(buf.getvalue())
    return str(p)


# ─────────────────────────────────────────────────────────────────────────────
# AES-256 ZIP — for Office docs, videos, images, and everything else.
# Uses pyzipper for true AES-256 (not weak ZipCrypto).
# 7-Zip / WinRAR asks for password when opening.
# File gets .vlkzip extension; original is removed.
# ─────────────────────────────────────────────────────────────────────────────

def protect_zip(path: str, password: str) -> str:
    """
    Wrap any file in an AES-256 encrypted ZIP in-place.
    Original file is replaced by <filename.ext>.vlkzip
    Returns the new .vlkzip path.
    """
    p = Path(path)
    if path.endswith(PROTECTED_MARKER):
        raise ValueError("File is already protected.")

    data = p.read_bytes()
    new_path = p.with_name(p.name + PROTECTED_MARKER)

    with pyzipper.AESZipFile(str(new_path), "w",
                             compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password.encode())
        zf.writestr(p.name, data)

    p.unlink()   # remove original only after zip is successfully written
    return str(new_path)


def unprotect_zip(path: str, password: str) -> str:
    """
    Extract and restore the original file from a .vlkzip archive.
    Returns the restored file path.
    """
    p = Path(path)
    if not path.endswith(PROTECTED_MARKER):
        raise ValueError("Not a VaultLock ZIP file.")

    with pyzipper.AESZipFile(str(p), "r") as zf:
        zf.setpassword(password.encode())
        names = zf.namelist()
        if not names:
            raise ValueError("Archive is empty.")
        orig_name = names[0]
        try:
            data = zf.read(orig_name)
        except RuntimeError as e:
            raise ValueError("Wrong password or corrupted archive.") from e

    orig_path = p.parent / orig_name
    if orig_path.exists():
        orig_path = p.parent / ("restored_" + orig_name)

    p.unlink()   # remove zip after extracting
    orig_path.write_bytes(data)
    return str(orig_path)


# ─────────────────────────────────────────────────────────────────────────────
# Unified entry points
# ─────────────────────────────────────────────────────────────────────────────

def protect_file(path: str, password: str) -> str:
    if get_strategy(path) == "pdf":
        return protect_pdf(path, password)
    return protect_zip(path, password)


def unprotect_file(path: str, password: str) -> str:
    if path.endswith(PROTECTED_MARKER):
        return unprotect_zip(path, password)
    if get_strategy(path) == "pdf":
        return unprotect_pdf(path, password)
    raise ValueError("Cannot determine file type. Is this file already unlocked?")


def collect_files(paths: List[str]) -> List[str]:
    result = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for f in files:
                    result.append(os.path.join(root, f))
        elif os.path.isfile(p):
            result.append(p)
    return result


def describe_strategy(path: str) -> str:
    if path.endswith(PROTECTED_MARKER):
        return "AES-256 ZIP (locked)"
    s = get_strategy(path)
    return "PDF (native)" if s == "pdf" else "AES-256 ZIP wrap"


# ─────────────────────────────────────────────────────────────────────────────
# GUI
# ─────────────────────────────────────────────────────────────────────────────

class VaultLockApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("VaultLock — Native Format Protection")
        self.geometry("800x580")
        self.resizable(True, True)
        self.configure(bg="#1e1e2e")
        self._setup_styles()
        self._build_ui()
        self.file_list: List[str] = []

    def _setup_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        BG   = "#1e1e2e"; SURF = "#2a2a3e"; ACC = "#7c5cd8"
        FG   = "#cdd6f4"; MUT  = "#6c7086"; GRN = "#a6e3a1"; RED = "#f38ba8"
        YEL  = "#f9e2af"
        style.configure(".",           background=BG,   foreground=FG,   font=("Segoe UI", 10))
        style.configure("TFrame",      background=BG)
        style.configure("Card.TFrame", background=SURF)
        style.configure("TLabel",      background=BG,   foreground=FG,   font=("Segoe UI", 10))
        style.configure("Head.TLabel", background=BG,   foreground=FG,   font=("Segoe UI", 17, "bold"))
        style.configure("Sub.TLabel",  background=BG,   foreground=MUT,  font=("Segoe UI", 9))
        style.configure("TButton",     background=ACC,  foreground="#fff",font=("Segoe UI", 10, "bold"),
                        padding=(12, 6), relief="flat", borderwidth=0)
        style.map("TButton",
                  background=[("active", "#6a4ec0"), ("disabled", MUT)],
                  foreground=[("disabled", BG)])
        style.configure("Danger.TButton", background=RED, foreground=BG)
        style.map("Danger.TButton", background=[("active", "#e07090")])
        style.configure("Green.TButton",  background=GRN, foreground=BG)
        style.map("Green.TButton",  background=[("active", "#8fd49b")])
        style.configure("TEntry",     fieldbackground=SURF, foreground=FG,
                        insertcolor=FG, relief="flat", borderwidth=0, padding=6)
        style.configure("TProgressbar", troughcolor=SURF, background=ACC, thickness=8)
        style.configure("Treeview",   background=SURF, foreground=FG,
                        fieldbackground=SURF, rowheight=26, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", background=BG, foreground=MUT,
                        font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", ACC)])
        self.colors = dict(BG=BG, SURF=SURF, ACC=ACC, FG=FG, MUT=MUT,
                           GRN=GRN, RED=RED, YEL=YEL)

    def _build_ui(self):
        c = self.colors
        pad = ttk.Frame(self, style="TFrame", padding=(20, 16))
        pad.pack(fill="both", expand=True)

        # Title
        ttk.Label(pad, text="VaultLock", style="Head.TLabel").pack(anchor="w")
        ttk.Label(pad,
                  text="Password-protect files without changing how they open  "
                       "|  PDF stays PDF (Chrome asks password)  "
                       "|  Others become AES-256 ZIP (7-Zip asks password)",
                  style="Sub.TLabel").pack(anchor="w", pady=(0, 14))

        # Legend row
        leg = ttk.Frame(pad, style="TFrame")
        leg.pack(fill="x", pady=(0, 10))
        for label, color in [
            ("PDF (.pdf)  → no extension change, opens in Chrome/Acrobat", "#3b82d4"),
            ("All others  → .vlkzip, opens in 7-Zip/WinRAR", "#f9e2af"),
        ]:
            dot = tk.Label(leg, text="●", fg=color, bg=c["BG"], font=("Segoe UI", 11))
            dot.pack(side="left", padx=(0, 2))
            tk.Label(leg, text=label, fg=c["MUT"], bg=c["BG"],
                     font=("Segoe UI", 9)).pack(side="left", padx=(0, 24))

        # Password row
        pw_frame = ttk.Frame(pad, style="TFrame")
        pw_frame.pack(fill="x", pady=(0, 10))
        ttk.Label(pw_frame, text="Password:").pack(side="left")
        self.pw_var = tk.StringVar()
        self.pw_entry = ttk.Entry(pw_frame, textvariable=self.pw_var, show="*", width=32)
        self.pw_entry.pack(side="left", padx=(8, 10))
        self.show_pw = tk.BooleanVar(value=False)
        tk.Checkbutton(pw_frame, text="Show", variable=self.show_pw,
                       command=lambda: self.pw_entry.config(
                           show="" if self.show_pw.get() else "*"),
                       bg=c["BG"], fg=c["MUT"], selectcolor=c["SURF"],
                       activebackground=c["BG"], relief="flat", borderwidth=0).pack(side="left")

        # Toolbar
        tb = ttk.Frame(pad, style="TFrame")
        tb.pack(fill="x", pady=(0, 8))
        ttk.Button(tb, text="Add Files",       command=self._add_files).pack(side="left", padx=(0, 8))
        ttk.Button(tb, text="Add Folder",      command=self._add_folder).pack(side="left", padx=(0, 8))
        ttk.Button(tb, text="Remove Selected", command=self._remove_selected).pack(side="left", padx=(0, 8))
        ttk.Button(tb, text="Clear All",       command=self._clear_list,
                   style="Danger.TButton").pack(side="left")

        # File list
        tree_wrap = ttk.Frame(pad, style="Card.TFrame")
        tree_wrap.pack(fill="both", expand=True, pady=(0, 10))

        cols = ("file", "type", "size", "status")
        self.tree = ttk.Treeview(tree_wrap, columns=cols, show="headings", selectmode="extended")
        self.tree.heading("file",   text="File Path")
        self.tree.heading("type",   text="Method")
        self.tree.heading("size",   text="Size")
        self.tree.heading("status", text="Status")
        self.tree.column("file",   stretch=True, minwidth=280)
        self.tree.column("type",   width=160, anchor="center")
        self.tree.column("size",   width=80,  anchor="e")
        self.tree.column("status", width=140, anchor="center")

        vsb = ttk.Scrollbar(tree_wrap, orient="vertical",   command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_wrap, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_wrap.rowconfigure(0, weight=1)
        tree_wrap.columnconfigure(0, weight=1)

        # Progress + status
        self.progress = ttk.Progressbar(pad, mode="determinate")
        self.progress.pack(fill="x", pady=(0, 4))
        self.status_var = tk.StringVar(value="Ready — add files or a folder above.")
        ttk.Label(pad, textvariable=self.status_var, style="Sub.TLabel").pack(anchor="w", pady=(0, 10))

        # Action buttons
        act = ttk.Frame(pad, style="TFrame")
        act.pack(fill="x")
        self.lock_btn = ttk.Button(act, text="Lock / Protect",
                                   command=lambda: self._run("protect"), style="TButton")
        self.lock_btn.pack(side="left", padx=(0, 10))
        self.unlock_btn = ttk.Button(act, text="Unlock / Remove Protection",
                                     command=lambda: self._run("unprotect"), style="Green.TButton")
        self.unlock_btn.pack(side="left")
        ttk.Label(act,
                  text="  PDF: opens in Chrome/Acrobat — asks password.  "
                       "Others: opens in 7-Zip — asks password.",
                  style="Sub.TLabel").pack(side="left", padx=(16, 0))

    # ── File management ───────────────────────────────────────────────────────
    def _fmt_size(self, path: str) -> str:
        try:
            s = os.path.getsize(path)
            for u in ("B", "KB", "MB", "GB"):
                if s < 1024: return f"{s:.1f} {u}"
                s /= 1024
            return f"{s:.1f} TB"
        except Exception:
            return "—"

    def _add_files(self):
        files = filedialog.askopenfilenames(title="Select files")
        self._append_paths(list(files))

    def _add_folder(self):
        folder = filedialog.askdirectory(title="Select folder")
        if folder:
            self._append_paths(collect_files([folder]))

    def _append_paths(self, paths: List[str]):
        existing = set(self.file_list)
        for p in paths:
            if p not in existing:
                self.file_list.append(p)
                existing.add(p)
                self.tree.insert("", "end", iid=p,
                                 values=(p, describe_strategy(p),
                                         self._fmt_size(p), "Pending"))
        self.status_var.set(f"{len(self.file_list)} file(s) in queue.")

    def _clear_list(self):
        self.file_list.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.status_var.set("List cleared.")
        self.progress["value"] = 0

    def _remove_selected(self):
        for iid in self.tree.selection():
            self.tree.delete(iid)
            if iid in self.file_list:
                self.file_list.remove(iid)
        self.status_var.set(f"{len(self.file_list)} file(s) in queue.")

    # ── Runner ────────────────────────────────────────────────────────────────
    def _run(self, mode: str):
        if not self.file_list:
            messagebox.showwarning("No Files", "Add files or a folder first.")
            return
        password = self.pw_var.get()
        if not password:
            messagebox.showwarning("No Password", "Enter a password first.")
            return
        if mode == "protect" and len(self.file_list) > 3:
            if not messagebox.askyesno("Confirm",
                    f"Protect {len(self.file_list)} file(s) in-place?\n"
                    "Make sure you remember the password — it cannot be recovered.\n\nContinue?"):
                return
        self._set_buttons(False)
        self.progress["value"] = 0
        threading.Thread(target=self._worker, args=(mode, password), daemon=True).start()

    def _worker(self, mode: str, password: str):
        files  = list(self.file_list)
        total  = len(files)
        errors = []

        for i, fpath in enumerate(files, 1):
            try:
                if mode == "protect":
                    new_path = protect_file(fpath, password)
                else:
                    new_path = unprotect_file(fpath, password)
                label = "Locked" if mode == "protect" else "Unlocked"
                self._update_row(fpath, new_path, label)
                if new_path != fpath:
                    idx = self.file_list.index(fpath)
                    self.file_list[idx] = new_path
            except Exception as e:
                errors.append(f"{os.path.basename(fpath)}: {e}")
                self._update_row(fpath, fpath, "Error")

            pct = int(i / total * 100)
            self.after(0, lambda v=pct: self.progress.configure(value=v))

        verb = "protected" if mode == "protect" else "unlocked"
        summary = f"Done — {total - len(errors)}/{total} file(s) {verb}."
        if errors:
            summary += f"  {len(errors)} error(s)."
        self.after(0, lambda: self.status_var.set(summary))
        self.after(0, lambda: self._set_buttons(True))
        if errors:
            self.after(0, lambda: messagebox.showerror(
                "Errors", "\n".join(errors[:10]) + ("\n…" if len(errors) > 10 else "")))

    def _update_row(self, old_iid: str, new_path: str, status: str):
        def _do():
            if self.tree.exists(old_iid):
                self.tree.item(old_iid,
                               values=(new_path, describe_strategy(new_path),
                                       self._fmt_size(new_path), status))
        self.after(0, _do)

    def _set_buttons(self, enabled: bool):
        s = "normal" if enabled else "disabled"
        self.lock_btn.config(state=s)
        self.unlock_btn.config(state=s)


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = VaultLockApp()
    app.mainloop()
