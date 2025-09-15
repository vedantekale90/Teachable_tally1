import requests
import xmltodict
import json
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext


def send_data_to_tally(url, request_xml):
    """
    Sends an XML request to Tally to save/import data.
    Returns parsed dictionary response from Tally.
    """
    try:
        headers = {'Content-Type': 'text/xml;charset=utf-8'}
        response = requests.post(url, data=request_xml, headers=headers, timeout=10)
        response.raise_for_status()
        return xmltodict.parse(response.text)
    except requests.exceptions.RequestException as e:
        return {"error": f"HTTP request failed: {e}"}
    except Exception as e:
        return {"error": f"An error occurred: {e}"}


def browse_file():
    """Let user choose XML file."""
    file_path = filedialog.askopenfilename(
        filetypes=[("XML Files", "*.xml"), ("All Files", "*.*")]
    )
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)


def send_file():
    """Send selected XML file to Tally."""
    file_path = file_entry.get().strip()
    tally_url = url_entry.get().strip()

    if not file_path:
        messagebox.showerror("Error", "Please select an XML file.")
        return
    if not tally_url:
        messagebox.showerror("Error", "Please enter Tally URL.")
        return

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            request_xml = f.read()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read file: {e}")
        return

    response_dict = send_data_to_tally(tally_url, request_xml)

    # Show response
    response_box.delete("1.0", tk.END)
    response_box.insert(tk.END, json.dumps(response_dict, indent=4))


# ------------------- UI -------------------
root = tk.Tk()
root.title("Tally XML Import Tool")
root.geometry("700x500")

# Tally URL input
tk.Label(root, text="Tally Server URL:").pack(anchor="w", padx=10, pady=5)
url_entry = tk.Entry(root, width=60)
url_entry.pack(padx=10, pady=5)
url_entry.insert(0, "http://localhost:9000")  # default

# File input
tk.Label(root, text="XML File:").pack(anchor="w", padx=10, pady=5)
file_frame = tk.Frame(root)
file_frame.pack(padx=10, pady=5, fill="x")

file_entry = tk.Entry(file_frame, width=50)
file_entry.pack(side="left", fill="x", expand=True)

browse_btn = tk.Button(file_frame, text="Browse", command=browse_file)
browse_btn.pack(side="left", padx=5)

# Send button
send_btn = tk.Button(root, text="Send to Tally", command=send_file, bg="green", fg="white")
send_btn.pack(pady=10)

# Response box
tk.Label(root, text="Tally Response:").pack(anchor="w", padx=10, pady=5)
response_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=15)
response_box.pack(padx=10, pady=5, fill="both", expand=True)

root.mainloop()
