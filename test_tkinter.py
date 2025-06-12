import tkinter as tk
from tkinter import messagebox

root = tk.Tk()
root.withdraw() # Hide main window
messagebox.showinfo("Test", "Tkinter is working!")
root.destroy()
print("Tkinter test finished.")