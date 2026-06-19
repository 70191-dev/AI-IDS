import sqlite3
c = sqlite3.connect("data/ids.db")

print("=== Per-minute summary during today attack window ===")
print("(minute, total_flows, attacks_detected, avg_score, max_score)")
for r in c.execute("""
    SELECT
        SUBSTR(t.ts, 1, 16) as minute,
        COUNT(*) as flows,
        SUM(CASE WHEN d.label=1 THEN 1 ELSE 0 END) as attacks,
        ROUND(AVG(d.score), 3) as avg_score,
        ROUND(MAX(d.score), 3) as max_score
    FROM traffic_flow t
    JOIN detection_result d ON d.flow_id = t.id
    WHERE t.source_mode='live'
      AND (t.src_ip='192.168.142.128' OR t.dst_ip='192.168.142.128')
      AND t.ts >= '2026-05-23T23:07:00'
      AND t.ts <  '2026-05-23T23:15:00'
    GROUP BY minute
    ORDER BY minute
""").fetchall():
    print(r)

print()
print("=== Detection breakdown by label ===")
for r in c.execute("""
    SELECT d.label_text, d.attack_type, COUNT(*) as cnt
    FROM traffic_flow t
    JOIN detection_result d ON d.flow_id = t.id
    WHERE t.source_mode='live'
      AND (t.src_ip='192.168.142.128' OR t.dst_ip='192.168.142.128')
      AND t.ts >= '2026-05-23T23:07:00'
      AND t.ts <  '2026-05-23T23:15:00'
    GROUP BY d.label_text, d.attack_type
    ORDER BY cnt DESC
""").fetchall():
    print(r)
