SSH Brute Force Detection & Investigation with Splunk
A small hands-on SOC project built in Splunk Enterprise using a JSON-lines dataset of SSH authentication events. The goal was to load the logs, identify repeated authentication failures, find the most targeted accounts and servers, and review cases where failed attempts were followed by a successful login.
Project setup
- SIEM: Splunk Enterprise (Windows)
- Input file: ssh_logs_new.json (JSON Lines / NDJSON)
- Splunk index: ssh
- Source type: _json
- Host field: ssh_vipin
- Events analysed: 1,200
Dataset fields used
Field	Use
ts	Event timestamp
id.orig_h	Source IP
id.resp_h	Destination / SSH server IP
id.resp_p	Destination port (22)
username	Account involved in the login attempt
auth_success	Authentication result (true, false, or null)
auth_attempts	Number of authentication attempts represented by the event
event_type	Event classification
uid	Event / connection identifier


Detection logic
The dataset has two failure event types: Failed SSH Login and Multiple Failed Authentication Attempts. The auth_attempts value matters: counting failed event records alone would understate the number of failed attempts.

The main search aggregates attempts by source IP, target IP, and username. It flags groups with 10 or more failed attempts for review. This is a lab threshold, not a universal definition of brute force.
index=ssh
(event_type="Failed SSH Login" OR event_type="Multiple Failed Authentication Attempts")
| eval source_ip='id.orig_h'
| eval target_ip='id.resp_h'
| eval failed_attempts=tonumber(auth_attempts)
| stats sum(failed_attempts) as failed_attempts
        count as failed_event_records
        values(event_type) as failure_types
        by source_ip target_ip username
| where failed_attempts >= 10
| eval severity=case(
    failed_attempts>=20,"High",
    failed_attempts>=10,"Medium",
    true(),"Low")
| sort - failed_attempts
Key findings from this dataset
- 1,200 total SSH events.
- 608 failed-authentication event records, representing 2,102 failed attempts.
- 306 successful SSH login events.
- 286 connections without authentication.
- 59 source-IP / target-IP / username combinations met the 10-attempt threshold.
- The largest individual combination had 33 failed attempts: source 164.89.50.183, target 123.158.160.191, username svc_ssh.
- The top source by summed failed attempts was 25.47.52.197 with 88 attempts.
- The most targeted destination was 170.170.25.84 with 218 failed attempts.
- The most targeted username was admin with 191 failed attempts.
These are findings in the supplied dataset. An IP with many failures is a lead for investigation, not proof that the address is malicious.
Other searches used
Top source IPs
index=ssh
(event_type="Failed SSH Login" OR event_type="Multiple Failed Authentication Attempts")
| eval source_ip='id.orig_h', target_ip='id.resp_h'
| eval failed_attempts=tonumber(auth_attempts)
| stats sum(failed_attempts) as total_failed_attempts
        count as failed_event_records
        dc(target_ip) as targeted_servers
        by source_ip
| sort - total_failed_attempts
| head 10
Most targeted usernames
index=ssh
(event_type="Failed SSH Login" OR event_type="Multiple Failed Authentication Attempts")
| eval failed_attempts=tonumber(auth_attempts)
| stats sum(failed_attempts) as failed_attempts
        count as failed_records
        by username
| sort - failed_attempts
Successful login after previous failures
index=ssh
(event_type="Failed SSH Login"
 OR event_type="Multiple Failed Authentication Attempts"
 OR event_type="Successful SSH Login")
| eval source_ip='id.orig_h', target_ip='id.resp_h'
| eval failed_attempts=if(
    event_type="Failed SSH Login"
    OR event_type="Multiple Failed Authentication Attempts",
    tonumber(auth_attempts),0)
| eval is_success=if(event_type="Successful SSH Login",1,0)
| sort 0 ts
| streamstats sum(failed_attempts) as previous_failed_attempts
    by source_ip target_ip username
| where is_success=1 AND previous_failed_attempts>=10
| table ts source_ip target_ip username previous_failed_attempts event_type
The last search returned 7 matching successful-login events in this dataset. Treat them as investigation leads, not confirmed compromises. The search carries a running failure total for each source / target / username combination across the selected dataset; it does not enforce a five-minute lookback window.
How to reproduce
1. Install and open Splunk Enterprise on Windows (http://localhost:8000).
2. Select Add Data → Upload and choose ssh_logs_new.json.
3. Select JSON (_json) as the source type and use the ssh index.
4. Set the host value to ssh_vipin if you want to match the lab screenshots.
5. Set the time picker to All time and verify the total event count is 1,200.
6. Run the SPL searches above in Search & Reporting.
7. Save useful searches as reports or dashboard panels and capture your own screenshots.
Important data limitation
The event timestamps range from 2025-04-24 10:20:09.508780 UTC to 2025-04-24 10:20:09.522008 UTC — a span of only 13.228 milliseconds. The file therefore does not provide a realistic five-minute attack timeline. The threshold search identifies repeated failures within each source / target / username group across the supplied file; it does not prove those attempts occurred within five minutes. For genuine time-window detection, use logs with realistic event timing and a time-bounded rolling search.
Suggested repository contents

SSH-Brute-Force-Detection-Splunk/
├── README.md
├── Dataset/
│   └── ssh_logs_new.json
├── SPL-Queries/
│   ├── brute_force_detection.spl
│   ├── top_attacking_ips.spl
│   ├── targeted_usernames.spl
│   └── failed_then_successful_login.spl
└── Screenshots/
    └── splunk-search-results.png
