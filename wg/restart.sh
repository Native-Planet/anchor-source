#!/bin/bash
# iptables --line-numbers --list
echo "Restarting WG interface..."
# Look for all rules that have the 'fwded' comment
FWD_RULES=$(iptables --line-number -nL FORWARD|grep fwded|awk '{print $1}'|tac)
wg-quick down wg0
# Delete them (background)
for rul in $FWD_RULES; do iptables -D FORWARD $rul; done
sleep 0.1
wg-quick up wg0