import sqlite3
c = sqlite3.connect("data/ids.db")
print("=== Replay flows: do they have src_ip/dst_ip? ===")
for r in c.execute("SELECT src_ip, dst_ip, COUNT(*) FROM traffic_flow WHERE source_mode='replay' GROUP BY src_ip IS NULL, dst_ip IS NULL").fetchall():
    print(r)

print()
print("=== Sample of 5 replay flows ===")
for r in c.execute("SELECT ts, src_ip, dst_ip FROM traffic_flow WHERE source_mode='replay' LIMIT 5").fetchall():
    print(r)
