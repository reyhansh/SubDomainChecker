import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import threading
import socket

# ---------------------------------------------------------
# Write output safely to GUI
# ---------------------------------------------------------
def write_output(msg):
    output_box.insert(tk.END, msg + "\n")
    output_box.see(tk.END)

# ---------------------------------------------------------
# Load wordlist file
# ---------------------------------------------------------
def load_wordlist():
    global wordlist
    path = filedialog.askopenfilename(
        title="Select Wordlist",
        filetypes=[("Text Files", "*.txt")]
    )

    if not path:
        return

    with open(path, "r") as f:
        wordlist = [line.strip() for line in f]

    write_output(f"[+] Loaded {len(wordlist)} words from: {path}")

# ---------------------------------------------------------
# Subdomain Enumerator (runs in background thread)
# ---------------------------------------------------------
def enumerate_subdomains():
    global wordlist

    domain = domain_entry.get().strip()
    if not domain:
        messagebox.showerror("Error", "Please enter a domain!")
        return

    if not wordlist:
        messagebox.showerror("Error", "Please load a wordlist first!")
        return

    write_output(f"[+] Starting subdomain enumeration for: {domain}")
    write_output("[*] Please wait...\n")

    found = []

    for word in wordlist:
        subdomain = f"{word}.{domain}"

        try:
            socket.gethostbyname(subdomain)  # Check if valid
            write_output(f"[FOUND] {subdomain}")
            found.append(subdomain)
        except:
            pass  # Ignore invalid

    write_output("\n[+] Enumeration completed.")
    write_output(f"[+] Total found: {len(found)}")

    # Ask to save results
    if found:
        save = messagebox.askyesno("Save Results", "Save found subdomains to file?")
        if save:
            save_results(found)

# ---------------------------------------------------------
# Save results to text file
# ---------------------------------------------------------
def save_results(found_list):
    path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt")]
    )
    if path:
        with open(path, "w") as f:
            f.write("\n".join(found_list))
        write_output(f"[+] Results saved to {path}")

# ---------------------------------------------------------
# Thread handler for GUI
# ---------------------------------------------------------
def start_thread():
    t = threading.Thread(target=enumerate_subdomains)
    t.start()

# ---------------------------------------------------------
# GUI Setup
# ---------------------------------------------------------
root = tk.Tk()
root.title("Subdomain Enumerator – Easy GUI")

wordlist = []  # stores loaded words

tk.Label(root, text="Enter Domain:").pack()
domain_entry = tk.Entry(root, width=50)
domain_entry.pack(pady=5)

tk.Button(root, text="Load Wordlist", command=load_wordlist).pack(pady=5)
tk.Button(root, text="Start Scan", command=start_thread).pack(pady=5)

output_box = scrolledtext.ScrolledText(root, width=80, height=25)
output_box.pack()

root.mainloop()
