import sqlite3
c = sqlite3.connect("data/ids.db")

print("=== Live flows in last 90 minutes, by detection result ===")
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
      AND t.src_ip='192.168.142.128'
    GROUP BY minute
    ORDER BY minute DESC
    LIMIT 30
""").fetchall():
    print(r)
