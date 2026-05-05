#!/usr/bin/env python3
# Engineering workaround instead of restarting the WCP service
import subprocess
import sys
import os
import re
import base64
import requests
import urllib3

# Suppress insecure request warnings for Harbor API calls
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

def update_harbor_password(vcenter_host, vcenter_password, new_password):
    lsf.write_output(f"SSHing into vCenter ({vcenter_host}) to retrieve Supervisor credentials...")
    cmd_vc = (
        f'sshpass -p "{vcenter_password}" ssh '
        f'-o StrictHostKeyChecking=accept-new '
        f'-o UserKnownHostsFile=/dev/null '
        f'root@{vcenter_host} '
        f'\'python3 /usr/lib/vmware-wcp/decryptK8Pwd.py\''
    )
    res_vc = subprocess.run(cmd_vc, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res_vc.returncode != 0:
        lsf.write_output(f"Error retrieving Supervisor credentials: {res_vc.stderr}")
        return
        
    # Parse output for IP and password
    ip_match = re.search(r'IP:\s*([0-9\.]+)', res_vc.stdout)
    pwd_match = re.search(r'PWD:\s*(\S+)', res_vc.stdout)
    
    if not ip_match or not pwd_match:
        # Fallback regex just in case format differs slightly
        ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', res_vc.stdout)
        if not ip_match:
            lsf.write_output(f"Could not parse Supervisor IP from output:\n{res_vc.stdout}")
            return
            
    sup_ip = ip_match.group(1) if ip_match else '10.1.1.188'
    sup_pwd = pwd_match.group(1) if pwd_match else '1mjo-RFJ6M4T~FP5' # Fallback to user provided if regex fails
    
    lsf.write_output(f"Retrieved Supervisor IP: {sup_ip}")
    
    # SSH into Supervisor to get Harbor admin password
    lsf.write_output(f"SSHing into Supervisor ({sup_ip}) to retrieve Harbor admin password...")
    
    # First, dynamically find the harbor namespace
    cmd_find_ns = (
        f'sshpass -p "{sup_pwd}" ssh '
        f'-o StrictHostKeyChecking=accept-new '
        f'-o UserKnownHostsFile=/dev/null '
        f'root@{sup_ip} '
        f'\'kubectl get secret -A | grep harbor-core-ver-1 | awk "{{print \\$1}}" | head -n 1\''
    )
    res_ns = subprocess.run(cmd_find_ns, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    namespace = res_ns.stdout.strip()
    if not namespace:
        namespace = "svc-harbor-zjx6i" # Fallback to known namespace
        
    cmd_sup = (
        f'sshpass -p "{sup_pwd}" ssh '
        f'-o StrictHostKeyChecking=accept-new '
        f'-o UserKnownHostsFile=/dev/null '
        f'root@{sup_ip} '
        f'\'kubectl get secret harbor-core-ver-1 -n {namespace} -o jsonpath="{{.data.HARBOR_ADMIN_PASSWORD}}"\' '
    )
    res_sup = subprocess.run(cmd_sup, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res_sup.returncode != 0:
        lsf.write_output(f"Error retrieving Harbor password: {res_sup.stderr}")
        return
        
    b64_pwd = res_sup.stdout.strip()
    if not b64_pwd:
        lsf.write_output("Harbor admin password secret was empty.")
        return
        
    current_harbor_pwd = base64.b64decode(b64_pwd).decode('utf-8')
    
    # Use Harbor API to change password
    lsf.write_output("Updating Harbor admin password via API...")
    harbor_api_url = f"https://{sup_ip}/api/v2.0/users/1/password"
    payload = {
        "old_password": current_harbor_pwd,
        "new_password": new_password
    }
    
    try:
        auth = ('admin', current_harbor_pwd)
        response = requests.put(harbor_api_url, json=payload, auth=auth, verify=False)
        if response.status_code in (200, 201):
            lsf.write_output("Successfully updated Harbor admin password.")
        else:
            lsf.write_output(f"Failed to update Harbor password. Status: {response.status_code}, Response: {response.text}")
    except Exception as e:
        lsf.write_output(f"Exception occurred while calling Harbor API: {str(e)}")

def main():
    creds_file = '/home/holuser/creds.txt'
    password = 'VMware1!' # fallback
    if os.path.exists(creds_file):
        with open(creds_file, 'r') as f:
            password = f.read().strip()
            
    # lsf.write_output("SSHing into Supervisor Control Plane VM (10.1.1.142) to create /var/lib/node.cfg...")
    
    # # Use sshpass to provide the password, disable strict host key checking to avoid interactive prompts
    # # Use sudo to ensure we have permissions to write to /var/lib
    # # Note: If sudo requires a password, we pass it via echo and -S.
    # cmd = (
    #     f'sshpass -p "{password}" ssh '
    #     f'-o StrictHostKeyChecking=accept-new '
    #     f'-o UserKnownHostsFile=/dev/null '
    #     f'vmware-system-user@10.1.1.142 '
    #     f'\'echo "{password}" | sudo -S touch /var/lib/node.cfg\''
    # )
    
    # # Using shell=True per vcf-9-api rule to avoid quoted password splitting issues
    # result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # if result.returncode != 0:
    #     lsf.write_output(f"Error executing command on Supervisor Control Plane:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}")
    #     sys.exit(result.returncode)
    
    # lsf.write_output("Successfully touched /var/lib/node.cfg on Supervisor Control Plane VM.")

    # Update Harbor admin password
    vcenter_host = 'vc-wld01-a.site-a.vcf.lab'
    update_harbor_password(vcenter_host, password, password)

if __name__ == "__main__":
    main()
