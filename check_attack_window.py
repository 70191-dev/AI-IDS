import sqlite3
c = sqlite3.connect("data/ids.db")
print("=== Top 20 highest-scored LIVE flows during attack window (07:26 - 07:45) ===")
q = """
SELECT t.ts, d.score, d.label_text, d.attack_type
FROM traffic_flow t
JOIN detection_result d ON d.flow_id = t.id
WHERE t.source_mode = 'live'
  AND t.ts >= '2026-05-23T07:26:00'
  AND t.ts <= '2026-05-23T07:45:00'
ORDER BY d.score DESC
LIMIT 20
"""
for r in c.execute(q).fetchall():
    print(r)

print()
print("=== Flow count per minute during attack window ===")
q2 = """
SELECT substr(t.ts, 1, 16) as minute, COUNT(*) as flows,
       SUM(CASE WHEN d.label=1 THEN 1 ELSE 0 END) as attacks
FROM traffic_flow t
JOIN detection_result d ON d.flow_id = t.id
WHERE t.source_mode = 'live'
  AND t.ts >= '2026-05-23T07:26:00'
  AND t.ts <= '2026-05-23T07:45:00'
GROUP BY minute
ORDER BY minute
"""
for r in c.execute(q2).fetchall():
    print(r)
