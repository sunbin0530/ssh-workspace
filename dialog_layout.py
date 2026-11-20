"""Reserve a bottom action row before allocating space to long text."""
import tkinter as tk
from tkinter import scrolledtext


def review_layout(parent, title, instructions, content, editable=False):
    dialog = tk.Toplevel(parent)
    dialog.title(title)
    width = min(850, max(400, dialog.winfo_screenwidth() - 100))
    height = min(500, max(260, dialog.winfo_screenheight() - 120))
    dialog.geometry(f'{width}x{height}')
    dialog.minsize(min(600, width), min(280, height))
    dialog.columnconfigure(0, weight=1)
    dialog.rowconfigure(1, weight=1, minsize=40)
    tk.Label(dialog, text=instructions, anchor='w', justify='left', wraplength=width - 30).grid(
        row=0, column=0, sticky='ew', padx=10, pady=(8, 4))
    preview = scrolledtext.ScrolledText(dialog, wrap='word', height=6, width=30, font=('Consolas', 11))
    preview.grid(row=1, column=0, sticky='nsew', padx=10, pady=4)
    preview.insert('1.0', content)
    if not editable:
        preview.configure(state='disabled')
    actions = tk.Frame(dialog)
    actions.grid(row=2, column=0, sticky='ew', padx=10, pady=(6, 10))
    actions.columnconfigure(0, weight=1)
    actions.columnconfigure(1, weight=1)
    dialog.bind('<Escape>', lambda _event: dialog.destroy())
    return dialog, preview, actions
