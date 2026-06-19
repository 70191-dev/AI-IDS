import sqlite3
c = sqlite3.connect('data/ids.db')
q = """
SELECT t.ts, t.src_ip, t.dst_ip, d.score, d.label_text
FROM traffic_flow t
JOIN detection_result d ON d.flow_id = t.id
WHERE (t.src_ip='192.168.142.128' OR t.dst_ip='192.168.142.128')
  AND t.ts >= '2026-05-23T07:26:00'
  AND t.ts <= '2026-05-23T07:45:00'
ORDER BY d.score DESC
LIMIT 30
"""
for r in c.execute(q).fetchall():
    print(r)
