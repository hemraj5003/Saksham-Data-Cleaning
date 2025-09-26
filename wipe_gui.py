import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path

# Import your wipe engine
import pk

# Default output directory
OUTDIR = Path("./out")
OUTDIR.mkdir(parents=True, exist_ok=True)

def select_file():
    path = filedialog.askopenfilename(title="Select a file to wipe")
    if path:
        entry_target.delete(0, tk.END)
        entry_target.insert(0, path)

def select_folder():
    path = filedialog.askdirectory(title="Select a folder to wipe")
    if path:
        entry_target.delete(0, tk.END)
        entry_target.insert(0, path)

def run_wipe():
    target = entry_target.get().strip()
    mode = combo_mode.get()
    alg = combo_alg.get().lower()
    dry_run = dry_var.get()
    passes = int(entry_passes.get())

    if not target:
        messagebox.showwarning("Warning", "Please select a target")
        return

    try:
        private_key, public_key = pk.generate_rsa_keypair()  # ephemeral keys
        if mode == "File":
            pk.wipe_single_file_flow(Path(target), alg, passes, dry_run, OUTDIR, private_key, no_pdf=False)
        elif mode == "Directory":
            pk.wipe_directory_flow(Path(target), alg, passes, dry_run, OUTDIR, private_key, no_pdf=False)
        elif mode == "Freespace":
            pk.wipe_freespace_flow(target, alg, passes, dry_run, OUTDIR, private_key, no_pdf=False)
        else:
            messagebox.showinfo("Not Implemented", f"Mode {mode} is not available in GUI yet.")
            return
        messagebox.showinfo("Success", f"Wipe completed for {target}")
    except Exception as e:
        messagebox.showerror("Error", f"Wipe failed: {e}")

# ---------- GUI ----------
root = tk.Tk()
root.title("Saksham - GUI")
root.geometry("500x300")

tk.Label(root, text="Select Target (file/folder):", font=("Arial", 12)).pack(pady=10)

frame_target = tk.Frame(root)
frame_target.pack()
entry_target = tk.Entry(frame_target, width=40)
entry_target.pack(side=tk.LEFT, padx=5)
tk.Button(frame_target, text="File", command=select_file).pack(side=tk.LEFT, padx=5)
tk.Button(frame_target, text="Folder", command=select_folder).pack(side=tk.LEFT, padx=5)

frame_opts = tk.Frame(root)
frame_opts.pack(pady=15)

tk.Label(frame_opts, text="Mode:").grid(row=0, column=0, padx=5)
combo_mode = ttk.Combobox(frame_opts, values=["File", "Directory", "Freespace"], state="readonly")
combo_mode.current(0)
combo_mode.grid(row=0, column=1, padx=5)

tk.Label(frame_opts, text="Algorithm:").grid(row=1, column=0, padx=5)
combo_alg = ttk.Combobox(frame_opts, values=["nist", "dod", "gutmann", "zero", "random"], state="readonly")
combo_alg.current(0)
combo_alg.grid(row=1, column=1, padx=5)

tk.Label(frame_opts, text="Passes:").grid(row=2, column=0, padx=5)
entry_passes = tk.Entry(frame_opts, width=5)
entry_passes.insert(0, "1")
entry_passes.grid(row=2, column=1, padx=5, sticky="w")

dry_var = tk.BooleanVar()
tk.Checkbutton(frame_opts, text="Dry Run", variable=dry_var).grid(row=3, column=0, columnspan=2, pady=5)

tk.Button(root, text="Run Wipe", bg="red", fg="white", command=run_wipe).pack(pady=20)

root.mainloop()
