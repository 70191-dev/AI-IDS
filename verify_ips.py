import sqlite3
c = sqlite3.connect("data/ids.db")
print("=== Latest 10 live flows ===")
for r in c.execute("SELECT ts, src_ip, dst_ip, src_port, dst_port, protocol FROM traffic_flow WHERE source_mode='live' ORDER BY ts DESC LIMIT 10").fetchall():
    print(r)
