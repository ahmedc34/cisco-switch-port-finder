"""
Switch Bulucu - LLDP/CDP ile bağlı olunan switch ve port bilgisini gösterir.
Gereksinim: Npcap (https://npcap.com), scapy. Yönetici olarak çalıştırılmalı.
"""
import os
import queue
import socket
import struct
import sys
import threading
import time
import tkinter as tk
import webbrowser
from tkinter import messagebox, ttk

from scapy.all import conf, raw, sniff
from scapy.arch.windows import get_windows_if_list

LLDP_MAC = "01:80:c2:00:00:0e"
CDP_MAC = "01:00:0c:cc:cc:cc"
TIMEOUT = 500


def mac_str(b):
    return ":".join(f"{x:02x}" for x in b)


def txt(b):
    return b.decode("utf-8", "replace").strip("\x00 ")


def safe(b):
    """Yazdirilabilir metinse metin, kisa ikili degerse sayi, degilse hex dondurur."""
    if b and all(32 <= x < 127 for x in b.strip(b"\x00")):
        return txt(b)
    if 0 < len(b) <= 4:
        return str(int.from_bytes(b, "big"))
    return "0x" + b.hex()


def parse_lldp(data):
    info = {"Protokol": "LLDP"}
    i = 14
    while i + 2 <= len(data):
        h = struct.unpack("!H", data[i:i + 2])[0]
        t, l = h >> 9, h & 0x1FF
        v = data[i + 2:i + 2 + l]
        i += 2 + l
        if t == 0:
            break
        if t == 1 and l > 1:
            sub = v[0]
            info["Switch ID"] = mac_str(v[1:]) if sub == 4 else (
                socket.inet_ntoa(v[2:6]) if sub == 5 and len(v) >= 6 else safe(v[1:]))
        elif t == 2 and l > 1:
            sub = v[0]
            info["Port"] = mac_str(v[1:]) if sub == 3 else safe(v[1:])
        elif t == 3 and l == 2:
            info["TTL (sn)"] = struct.unpack("!H", v)[0]
        elif t == 4:
            info["Port açıklaması"] = txt(v)
        elif t == 5:
            info["Switch adı"] = txt(v)
        elif t == 6:
            info["Sistem açıklaması"] = txt(v)
        elif t == 8 and l > 2:
            alen, sub = v[0], v[1]
            if sub == 1 and alen >= 5 and len(v) >= 6:
                info["Switch IP"] = socket.inet_ntoa(v[2:6])
        elif t == 127 and l >= 6 and v[:3] == b"\x00\x80\xc2" and v[3] == 1:
            info["VLAN"] = struct.unpack("!H", v[4:6])[0]
    return info


def parse_cdp(data):
    info = {"Protokol": "CDP"}
    i = 14 + 8 + 4  # eth + LLC/SNAP + ver/ttl/checksum
    info["TTL (sn)"] = data[23] if len(data) > 23 else "?"
    while i + 4 <= len(data):
        t, l = struct.unpack("!HH", data[i:i + 4])
        if l < 4:
            break
        v = data[i + 4:i + l]
        i += l
        if t == 1:
            info["Switch adı"] = txt(v)
        elif t in (2, 22) and len(v) >= 4:
            n = struct.unpack("!I", v[:4])[0]
            p = 4
            for _ in range(n):
                if p + 2 > len(v):
                    break
                plen = v[p + 1]
                p += 2 + plen
                alen = struct.unpack("!H", v[p:p + 2])[0]
                addr = v[p + 2:p + 2 + alen]
                p += 2 + alen
                if alen == 4:
                    info.setdefault("Switch IP", socket.inet_ntoa(addr))
                    break
        elif t == 3:
            info["Port"] = txt(v)
        elif t == 5:
            info["Sistem açıklaması"] = txt(v).replace("\n", " ")
        elif t == 6:
            info["Platform"] = txt(v)
        elif t == 10 and len(v) == 2:
            info["VLAN"] = struct.unpack("!H", v)[0]
        elif t == 11 and len(v) == 1:
            info["Duplex"] = "Full" if v[0] else "Half"
    return info


def classify(pkt):
    data = raw(pkt)
    if len(data) < 30:
        return None
    if struct.unpack("!H", data[12:14])[0] == 0x8100:  # VLAN etiketli cerceve
        data = data[:12] + data[16:]
    dst = mac_str(data[:6])
    etype = struct.unpack("!H", data[12:14])[0]
    if etype == 0x88CC:  # LLDP (hedef MAC markaya gore degisebilir)
        return parse_lldp(data)
    if dst == CDP_MAC and data[14:17] == b"\xaa\xaa\x03" and data[20:22] == b"\x20\x00":
        return parse_cdp(data)
    return None


class App:
    def __init__(self, root):
        self.root = root
        root.title("Switch Bulucu")
        root.geometry("620x520")
        self.q = queue.Queue()
        self.ifaces = [i for i in get_windows_if_list() if i.get("ips")]
        names = [f'{i["name"]} - {i.get("description", "")}' for i in self.ifaces]

        ttk.Label(root, text="Design by ahmedc",
                  font=("Segoe UI", 12, "bold")).pack(pady=(10, 0))

        top = ttk.Frame(root, padding=10)
        top.pack(fill="x")
        ttk.Label(top, text="Ağ kartı:").pack(anchor="w")
        self.combo = ttk.Combobox(top, values=names, state="readonly")
        self.combo.pack(fill="x", pady=4)
        if names:
            self.combo.current(0)
        self.btn = ttk.Button(top, text="Switch'i Bul", command=self.start)
        self.btn.pack(pady=6)
        self.status = ttk.Label(top, text="Kabloyu tak ve butona bas.")
        self.status.pack(anchor="w")

        self.out = tk.Text(root, font=("Consolas", 10), wrap="word")
        self.out.pack(fill="both", expand=True, padx=10, pady=10)

    def start(self):
        if not self.ifaces:
            self.status.config(text="Aktif ağ kartı bulunamadı.")
            return
        iface = self.ifaces[self.combo.current()]
        self.btn.state(["disabled"])
        self.out.insert("end", "\n" + "-" * 40 + "\n")
        self.show_local(iface)
        self.status.config(text=f"Dinleniyor... (en fazla {TIMEOUT} sn, LLDP/CDP bekleniyor)")
        threading.Thread(target=self.sniff, args=(iface,), daemon=True).start()
        self.root.after(300, self.poll)

    def show_local(self, iface):
        ips = [ip for ip in iface.get("ips", []) if "." in ip]
        gw = ""
        try:
            gw = conf.route.route("0.0.0.0")[2]
        except Exception:
            pass
        self.out.insert("end", "== Bu bilgisayar ==\n")
        self.out.insert("end", f"Kart     : {iface['name']}\n")
        self.out.insert("end", f"MAC      : {iface.get('mac', '?')}\n")
        self.out.insert("end", f"IP       : {', '.join(ips) or 'yok'}\n")
        self.out.insert("end", f"Gateway  : {gw or '?'}\n\n")

    def sniff(self, iface):
        merged = {}

        def handle(pkt):
            r = classify(pkt)
            if r:
                for k, v in r.items():
                    merged.setdefault(k, v)

        t0 = time.time()
        first = None
        try:
            while time.time() - t0 < TIMEOUT:
                sniff(iface=iface["name"], prn=handle, timeout=2, store=False)
                if merged:
                    if first is None:
                        first = time.time()
                    # IP geldiyse hemen bitir, gelmediyse diger protokolu (CDP/LLDP) icin 65 sn daha bekle
                    if "Switch IP" in merged or time.time() - first > 65:
                        break
        except Exception as e:
            self.q.put(("err", str(e)))
            return
        self.q.put(("ok", merged or None))

    def poll(self):
        try:
            kind, val = self.q.get_nowait()
        except queue.Empty:
            self.root.after(300, self.poll)
            return
        self.btn.state(["!disabled"])
        self.btn.focus_set()
        self.root.update_idletasks()
        if kind == "err":
            self.status.config(text="Hata (Npcap kurulu mu? Yönetici olarak mı çalışıyor?)")
            self.out.insert("end", val)
        elif val is None:
            self.status.config(text="Paket gelmedi.")
            self.out.insert("end", "LLDP/CDP paketi alınamadı. Switch'te LLDP/CDP kapalı olabilir.")
        else:
            self.status.config(text="Bulundu.")
            self.out.insert("end", "== Bağlı switch ==\n")
            for k, v in val.items():
                if k in ("Protokol", "TTL (sn)"):
                    continue
                if k == "Switch ID":
                    k = "Switch/Port Mac Adresi"
                self.out.insert("end", f"{k:<24}: {v}\n")
                self.out.see("end")


def npcap_var_mi():
    return any(os.path.exists(p) for p in (
        r"C:\Windows\System32\Npcap\wpcap.dll",
        r"C:\Windows\System32\wpcap.dll"))


if __name__ == "__main__":
    root = tk.Tk()
    if not npcap_var_mi():
        root.withdraw()
        if messagebox.askyesno(
                "Npcap bulunamadı",
                "Paket yakalamak için Npcap kurulu olmalı.\n\n"
                "npcap.com sayfası açılsın mı?"):
            webbrowser.open("https://npcap.com")
        sys.exit(1)
    App(root)
    root.mainloop()
