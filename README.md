# SOC-ANALYST
PROJECT CHECKER by John Bryce
The script runs a network scan (nmap), shows discovered IPs to the user, offers 3 built-in attacks (Brute Force, MITM, DoS) plus a random option, supports manual/selection/random target choices, executes the chosen attack, and logs every event to /var/log/attack_log.txt. It also performs dependency checks, cleanup, and supports testability (DEFAULT_TARGET, TEST_RANDOM_SEED, /tmp/soc_chosen).
