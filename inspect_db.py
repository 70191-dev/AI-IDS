import sqlite3
c = sqlite3.connect("data/ids.db")
print("=== Total flow count ===")
print(c.execute("SELECT COUNT(*) FROM traffic_flow").fetchone())
print()
print("=== Last 20 flows (any source) ===")
for r in c.execute("SELECT ts, src_ip, dst_ip, source_mode FROM traffic_flow ORDER BY ts DESC LIMIT 20").fetchall():
    print(r)
print()
print("=== Distinct source_mode values ===")
for r in c.execute("SELECT source_mode, COUNT(*) FROM traffic_flow GROUP BY source_mode").fetchall():
    print(r)
print()
print("=== Distinct src_ips in last 1000 flows ===")
for r in c.execute("SELECT src_ip, COUNT(*) FROM (SELECT src_ip FROM traffic_flow ORDER BY ts DESC LIMIT 1000) GROUP BY src_ip ORDER BY 2 DESC").fetchall():
    print(r)
