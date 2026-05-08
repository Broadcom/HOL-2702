#!/usr/bin/bash
#
# This script, if present in your vpodrepo root, is run at the end of labsartup.
# It is called during the "final.py"
# Here's the overall flow:
# prelim.py -> ESXi.py -> VCF.py -> VVF.py -> vSphere.py -> pings.py -> services.py -> Kubernetes.py -> urls.py -> VCFfinal.py -> final.py -> odyssey.py 
#
# If you prefer scripting in Python:
# You may optionally place a "lab-update.py" in this folder and it would be called immediately folling the call of this lab-update.sh script
# 
# Source the .bashrc file for settings/paths/etc...
. /home/holuser/.bashrc
# Insert your custom code here:

rm -f /lmchol/home/holuser/Desktop/BuildChecklist.txt
truncate -s 0 /lmchol/home/holuser/.bash_history

# Example to echo text into file on Console VM. 
# NOTE: when this script runs, /lmchol is mounted to the "/" of the Console VM
# echo "Functional Testing!" > /lmchol/home/holuser/Documents/FT.txt

# Create encoded string for the value found in /home/holuser/creds.txt
export ENCODED_PASS=$(openssl passwd -6 "$(cat /home/holuser/creds.txt)")

# Store this value with the correct indentation in the cloudinit file
CLOUDINIT_FILE="/lmchol/home/holuser/Documents/files/cloudinit"
perl -pi -e 's{^(\s*)(lock_passwd: false.*)}{$1$2\n$1passwd: $ENCODED_PASS}gm' "$CLOUDINIT_FILE"
