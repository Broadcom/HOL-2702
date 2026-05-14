#!/usr/bin/env python3
# lab-update.py - Harbor admin password reset for HOL-2702
# Version 1.2 - 2026-05-14
# Retrieves Harbor's current admin password from the Supervisor cluster secret,
# waits for Harbor to be healthy, then resets it to the lab standard password.

import subprocess
import sys
import os
import re
import time
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


HARBOR_WORKLOADS = [
    ("sts",        "harbor-database"),
    ("sts",        "harbor-redis"),
    ("sts",        "harbor-trivy"),
    ("deployment", "harbor-core"),
    ("deployment", "harbor-jobservice"),
    ("deployment", "harbor-nginx"),
    ("deployment", "harbor-portal"),
    ("deployment", "harbor-registry"),
]


def wait_for_harbor(harbor_ip, sup_ip, sup_pwd, namespace, timeout_seconds=600, interval=15):
    """
    Two-phase Harbor readiness check.

    Phase 1 — kubectl rollout status: SSH into the Supervisor and wait for every
    Harbor Deployment and StatefulSet to report fully rolled out. This is the
    authoritative signal that pods are Running and Ready, regardless of how long
    the database or other components take to initialise.

    Phase 2 — HTTP health endpoint: once all pods are Ready, poll the Harbor
    health API to confirm the LoadBalancer is forwarding traffic and all internal
    Harbor components report healthy.

    Returns True when both phases pass, False if either times out.
    """
    # --- Phase 1: Kubernetes workload readiness ---
    lsf.write_output(f"Phase 1: Waiting for Harbor workloads to be Ready in namespace '{namespace}' (timeout {timeout_seconds}s)...")
    for kind, name in HARBOR_WORKLOADS:
        lsf.write_output(f"  Waiting for {kind}/{name}...")
        cmd = (
            f'sshpass -p "{sup_pwd}" ssh '
            f'-o StrictHostKeyChecking=accept-new '
            f'-o UserKnownHostsFile=/dev/null '
            f'root@{sup_ip} '
            f'"kubectl rollout status {kind}/{name} -n {namespace} --timeout={timeout_seconds}s"'
        )
        result = subprocess.run(
            cmd, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=timeout_seconds + 30,
        )
        if result.returncode != 0:
            lsf.write_output(f"  {kind}/{name} did not become ready: {result.stderr.strip()}")
            return False
        lsf.write_output(f"  {kind}/{name} is ready.")

    lsf.write_output("Phase 1 complete: all Harbor workloads are Ready.")

    # --- Phase 2: HTTP health endpoint ---
    lsf.write_output(f"Phase 2: Confirming Harbor health endpoint at {harbor_ip}...")
    health_url = f"https://{harbor_ip}/api/v2.0/health"
    deadline = time.time() + 120  # pods are ready; LB should respond quickly
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        try:
            resp = requests.get(health_url, verify=False, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('status') == 'healthy':
                    lsf.write_output(f"Harbor health endpoint confirmed healthy (attempt {attempt}).")
                    return True
                lsf.write_output(f"Harbor health returned status='{data.get('status')}' (attempt {attempt})")
            else:
                lsf.write_output(f"Harbor health check returned HTTP {resp.status_code} (attempt {attempt})")
        except Exception as e:
            lsf.write_output(f"Harbor health endpoint not yet reachable (attempt {attempt}): {e}")

        remaining = int(deadline - time.time())
        if remaining > 0:
            lsf.write_output(f"Retrying in {interval}s... ({remaining}s remaining)")
            time.sleep(interval)

    lsf.write_output("Phase 2 failed: Harbor health endpoint did not respond after all pods were Ready.")
    return False


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
        sys.exit(1)

    # Parse output for IP and password
    ip_match = re.search(r'IP:\s*([0-9\.]+)', res_vc.stdout)
    pwd_match = re.search(r'PWD:\s*(\S+)', res_vc.stdout)

    if not ip_match or not pwd_match:
        # Fallback regex just in case format differs slightly
        ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', res_vc.stdout)
        if not ip_match:
            lsf.write_output(f"Could not parse Supervisor IP from output:\n{res_vc.stdout}")
            sys.exit(1)

    sup_ip = ip_match.group(1)
    sup_pwd = pwd_match.group(1)

    lsf.write_output(f"Retrieved Supervisor IP: {sup_ip}")

    # SSH into Supervisor to get Harbor namespace and IP
    lsf.write_output(f"SSHing into Supervisor ({sup_ip}) to retrieve Harbor IP...")

    # Dynamically find the harbor namespace
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
        namespace = "svc-harbor-zjx6i"  # Fallback to known namespace

    cmd_harbor_ip = (
        f'sshpass -p "{sup_pwd}" ssh '
        f'-o StrictHostKeyChecking=accept-new '
        f'-o UserKnownHostsFile=/dev/null '
        f'root@{sup_ip} '
        f'\'kubectl get svc harbor-nginx -n {namespace} -o jsonpath="{{.status.loadBalancer.ingress[0].ip}}"\' '
    )
    res_harbor_ip = subprocess.run(cmd_harbor_ip, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    harbor_ip = res_harbor_ip.stdout.strip()
    if not harbor_ip:
        lsf.write_output("Could not determine Harbor LoadBalancer IP.")
        sys.exit(1)

    lsf.write_output(f"Found Harbor IP: {harbor_ip}")

    # Wait for Harbor to be fully healthy before attempting any API calls
    lsf.write_output(f"Waiting for Harbor at {harbor_ip} to become healthy (kubectl + HTTP, up to 10 minutes)...")
    if not wait_for_harbor(harbor_ip, sup_ip, sup_pwd, namespace, timeout_seconds=600, interval=15):
        lsf.write_output(f"Harbor at {harbor_ip} did not become healthy within the timeout. Failing lab.")
        sys.exit(1)

    # Check if the new password already works
    lsf.write_output("Checking if Harbor password is already up to date...")
    check_url = f"https://{harbor_ip}/api/v2.0/users/current"
    try:
        auth_check = ('admin', new_password)
        res = requests.get(check_url, auth=auth_check, verify=False, timeout=10)
        if res.status_code == 200:
            lsf.write_output("Harbor password is already correct. No update needed.")
            return
    except Exception as e:
        lsf.write_output(f"Password pre-check failed (will attempt update anyway): {e}")

    lsf.write_output("Harbor password needs to be updated. Retrieving current password from Supervisor...")

    cmd_sup = (
        f'sshpass -p "{sup_pwd}" ssh '
        f'-o StrictHostKeyChecking=accept-new '
        f'-o UserKnownHostsFile=/dev/null '
        f'root@{sup_ip} '
        f'\'kubectl get secret harbor-core-ver-1 -n {namespace} -o jsonpath="{{.data.HARBOR_ADMIN_PASSWORD}}"\' '
    )
    res_sup = subprocess.run(cmd_sup, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res_sup.returncode != 0:
        lsf.write_output(f"Error retrieving Harbor password secret: {res_sup.stderr}")
        sys.exit(1)

    b64_pwd = res_sup.stdout.strip()
    if not b64_pwd:
        lsf.write_output("Harbor admin password secret was empty.")
        sys.exit(1)

    current_harbor_pwd = base64.b64decode(b64_pwd).decode('utf-8')

    # Use Harbor API to change password
    lsf.write_output("Updating Harbor admin password via API...")
    harbor_api_url = f"https://{harbor_ip}/api/v2.0/users/1/password"
    payload = {
        "old_password": current_harbor_pwd,
        "new_password": new_password
    }

    try:
        auth = ('admin', current_harbor_pwd)
        response = requests.put(harbor_api_url, json=payload, auth=auth, verify=False, timeout=30)
        if response.status_code in (200, 201):
            lsf.write_output("Successfully updated Harbor admin password.")
        else:
            lsf.write_output(f"Failed to update Harbor password. Status: {response.status_code}, Response: {response.text}")
            sys.exit(1)
    except Exception as e:
        lsf.write_output(f"Exception occurred while calling Harbor API: {str(e)}")
        sys.exit(1)


def main():
    creds_file = '/home/holuser/creds.txt'
    password = ''
    if os.path.exists(creds_file):
        with open(creds_file, 'r') as f:
            password = f.read().strip()

    vcenter_host = 'vc-wld01-a.site-a.vcf.lab'
    # The vCenter password and the desired Harbor admin password are both the lab standard password.
    update_harbor_password(vcenter_host, password, password)


if __name__ == "__main__":
    main()
