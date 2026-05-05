#!/usr/bin/env python3
# Engineering workaround instead of restarting the WCP service
import subprocess
import sys
import os

# Add the hol directory to the sys path so we can import lsfunctions
sys.path.append('/home/holuser/hol')
try:
    import lsfunctions as lsf
except ImportError:
    # Fallback if we cannot import lsfunctions for local testing
    class lsf:
        @staticmethod
        def write_output(msg):
            print(msg)

def main():
    creds_file = '/home/holuser/creds.txt'
    password = 'VMware1!' # fallback
    if os.path.exists(creds_file):
        with open(creds_file, 'r') as f:
            password = f.read().strip()
            
    lsf.write_output("SSHing into Supervisor Control Plane VM (10.1.1.142) to create /var/lib/node.cfg...")
    
    # Use sshpass to provide the password, disable strict host key checking to avoid interactive prompts
    # Use sudo to ensure we have permissions to write to /var/lib
    # Note: If sudo requires a password, we pass it via echo and -S.
    cmd = (
        f'sshpass -p "{password}" ssh '
        f'-o StrictHostKeyChecking=accept-new '
        f'-o UserKnownHostsFile=/dev/null '
        f'vmware-system-user@10.1.1.142 '
        f'\'echo "{password}" | sudo -S touch /var/lib/node.cfg\''
    )
    
    # Using shell=True per vcf-9-api rule to avoid quoted password splitting issues
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    if result.returncode != 0:
        lsf.write_output(f"Error executing command on Supervisor Control Plane:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}")
        sys.exit(result.returncode)
    
    lsf.write_output("Successfully touched /var/lib/node.cfg on Supervisor Control Plane VM.")

if __name__ == "__main__":
    main()
