import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
from pysnmp.hlapi import *
import threading

class SNMPWalkApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SNMPwalk GUI")
        self.stop_flag = threading.Event()
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="Target Address:").grid(column=0, row=0, padx=10, pady=5, sticky='w')
        self.entry_target = tk.Entry(self, width=30)
        self.entry_target.grid(column=1, row=0, padx=10, pady=5, sticky='ew')

        tk.Label(self, text="Community String:").grid(column=0, row=1, padx=10, pady=5, sticky='w')
        self.entry_community = tk.Entry(self, width=30)
        self.entry_community.grid(column=1, row=1, padx=10, pady=5, sticky='ew')

        tk.Label(self, text="OIDs (one per line):").grid(column=0, row=2, padx=10, pady=5, sticky='w')
        self.txt_oid = scrolledtext.ScrolledText(self, width=30, height=5)
        self.txt_oid.grid(column=1, row=2, padx=10, pady=5, sticky='ew')

        tk.Button(self, text="Start SNMPwalk", command=self.start_snmp_walk).grid(column=0, row=3, columnspan=2, padx=10, pady=5)
        tk.Button(self, text="Stop SNMPwalk", command=self.stop_snmp_walk).grid(column=0, row=4, columnspan=2, padx=10, pady=5)

        self.txt_result = scrolledtext.ScrolledText(self, width=50, height=15)
        self.txt_result.grid(column=0, row=5, columnspan=2, padx=10, pady=5, sticky='nsew')

        tk.Button(self, text="Save Results", command=self.save_result).grid(column=0, row=6, columnspan=2, padx=10, pady=5)

        self.grid_rowconfigure(5, weight=1)
        self.grid_columnconfigure(1, weight=1)

    def snmp_walk(self, target, community, oids):
        snmp_engine = SnmpEngine()
        community_data = CommunityData(community)
        for oid in oids:
            for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                snmp_engine,
                community_data,
                UdpTransportTarget((target, 161), timeout=10.0, retries=5),
                ContextData(),
                ObjectType(ObjectIdentity(oid.strip())),
                lexicographicMode=False
            ):
                if self.stop_flag.is_set():
                    return
                if errorIndication:
                    yield str(errorIndication)
                    return
                elif errorStatus:
                    yield f'{errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or "?"}'
                    return
                else:
                    for varBind in varBinds:
                        yield ' = '.join([x.prettyPrint() for x in varBind])

    def start_snmp_walk(self):
        target = self.entry_target.get().strip()
        community = self.entry_community.get().strip()
        oids_input = self.txt_oid.get("1.0", tk.END).strip()
        oids = oids_input.split('\n') if oids_input else ['1.3.6.1']

        if not target or not community:
            messagebox.showwarning("Warning", "Please enter the target address and community string!")
            return

        self.txt_result.delete(1.0, tk.END)
        self.stop_flag.clear()
        threading.Thread(target=self.perform_snmp_walk, args=(target, community, oids)).start()

    def perform_snmp_walk(self, target, community, oids):
        for result in self.snmp_walk(target, community, oids):
            self.txt_result.insert(tk.END, result + '\n')
            self.txt_result.see(tk.END)
            self.update()

    def stop_snmp_walk(self):
        self.stop_flag.set()

    def save_result(self):
        result = self.txt_result.get(1.0, tk.END).strip()
        if not result:
            messagebox.showwarning("Warning", "No results to save!")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, "w") as file:
                file.write(result)
            messagebox.showinfo("Information", "Results saved successfully!")

if __name__ == "__main__":
    app = SNMPWalkApp()
    app.mainloop()
