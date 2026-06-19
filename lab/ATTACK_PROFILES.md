# Attack Profiles — Phase 2 Week 1

Reference list of attack profiles to be executed from the Kali Linux VM
against the Windows IDS host over the VMware host-only network.
Substitute `<win_ip>` (Windows IDS host) and `<kali_ip>` (Kali attacker)
with the actual IPs from the lab setup when running.

For each run, also append a row to `lab/attack_log.csv` so the extraction
tools can find the time window.

| Profile         | Command                                                                   | Expected family |
|-----------------|---------------------------------------------------------------------------|-----------------|
| nmap_syn        | nmap -sS -T4 -p 1-10000 <win_ip>                                          | Port Scan       |
| nmap_connect    | nmap -sT -T4 -p 1-1000 <win_ip>                                           | Port Scan       |
| hping_flood     | sudo hping3 -S -p 80 --flood <win_ip>  (10s window)                       | DoS             |
| slowloris       | python3 slowloris.py <win_ip> -p 80 -s 200                                | DoS             |
| hydra_ssh       | hydra -l testuser -P /usr/share/wordlists/rockyou.txt ssh://<win_ip> -t 4 | Brute Force     |
| benign_browse   | curl loops + ssh login with correct password                              | Benign          |
| benign_dl       | curl http://<win_ip>/largefile > /dev/null                                | Benign          |

## Edge cases (Day 6)

These will be processed by `tools/process_edge_cases.py` when their rows
appear in `attack_log.csv` with names starting `edge_`.

| Profile          | Command                                              | What we're testing |
|------------------|------------------------------------------------------|--------------------|
| edge_slow_nmap   | nmap -T1 -sS -p 1-200 <win_ip>                       | Slow scan evasion  |
| edge_frag_nmap   | nmap -f -sS <win_ip>                                 | Fragmented packets |
| edge_decoy_nmap  | nmap -D RND:5 -sS <win_ip>                           | Decoy source IPs   |
| edge_mixed       | slowloris + concurrent benign large download        | Mixed traffic      |

## Logging convention

For each run, before starting the attack:
1. Note the start timestamp (local time, second precision).
2. Run the attack.
3. Note the end timestamp.
4. Append a row to `lab/attack_log.csv`:
   `attack_name,start_ts,end_ts,kali_ip,win_ip,notes`

Timestamps should be in `YYYY-MM-DD HH:MM:SS` (24h) format to match
what the extraction tool expects.
