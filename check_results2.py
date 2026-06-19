import sqlite3
c = sqlite3.connect("data/ids.db")

print("=== Per-minute summary during attack window ===")
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
      AND t.ts >= '2026-05-23T17:53:00'
      AND t.ts <  '2026-05-23T18:10:00'
    GROUP BY minute
    ORDER BY minute
""").fetchall():
    print(r)

print()
print("=== Top 20 highest-scored flows during attack window ===")
print("(timestamp, score, label, attack_type, src_port, dst_port)")
for r in c.execute("""
    SELECT
        t.ts, d.score, d.label_text, d.attack_type,
        t.src_port, t.dst_port
    FROM traffic_flow t
    JOIN detection_result d ON d.flow_id = t.id
    WHERE t.source_mode='live'
      AND (t.src_ip='192.168.142.128' OR t.dst_ip='192.168.142.128')
      AND t.ts >= '2026-05-23T17:53:00'
      AND t.ts <  '2026-05-23T18:10:00'
    ORDER BY d.score DESC
    LIMIT 20
""").fetchall():
    print(r)

print()
print("=== Attack type breakdown if any attacks detected ===")
for r in c.execute("""
    SELECT d.attack_type, d.label_text, COUNT(*) as cnt
    FROM traffic_flow t
    JOIN detection_result d ON d.flow_id = t.id
    WHERE t.source_mode='live'
      AND (t.src_ip='192.168.142.128' OR t.dst_ip='192.168.142.128')
      AND t.ts >= '2026-05-23T17:53:00'
      AND t.ts <  '2026-05-23T18:10:00'
    GROUP BY d.attack_type, d.label_text
""").fetchall():
    print(r)
