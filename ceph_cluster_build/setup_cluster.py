#!/usr/bin/env python3
import subprocess
import sys
import time
import os
import glob
import string
import re
from configurecluster import *

CONFIG_FILE = "cluster.config"
VIRT_CLONE = "/usr/bin/virt-clone"

def create_ip_for_host(config, local_ip, public_ip, filename="ipconfigure.sh"):
    """
    Generate an ipconfigure.sh script for assigning local (cluster) and public IPs.
    Uses interface names from config if provided, otherwise defaults.
    """
    cluster_iface = config.get("CLUSTER_INTERFACE", "enp1s0")
    public_iface = config.get("PUBLIC_INTERFACE", "enp8s0")
    gateway = config.get("GATEWAY", "192.168.100.1")

    print(f"📝 Generating {filename} for {local_ip} (cluster) and {public_ip} (public)")

    with open(filename, "w") as f:
        f.write(f'nmcli connection modify {cluster_iface} ipv4.addresses "{local_ip}/24" ipv4.gateway "{gateway}" ipv4.method manual\n')
        f.write(f'nmcli connection modify {public_iface} ipv4.addresses "{public_ip}/24" ipv4.gateway "{gateway}" ipv4.method manual\n')

    print(f"✅ IP configuration script written: {filename}")

# ---------------- CONFIG LOADER ----------------
def load_config(file_path=CONFIG_FILE):
    """Load key=value pairs from config file into dict"""
    config = {}
    with open(file_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, value = line.split("=", 1)
                config[key.strip()] = value.strip().strip('"')
    return config

# ---------------- SSH KEY HANDLING ----------------
def build_authorized_keys(config):
    collected_keys = set()

    start_ip = int(config["START_IP"])
    no_of_vm = int(config["NO_OF_VMS"])
    host_base_name = config["HOST_BASE_NAME"]
    pubkey_dir = config["PUBKEY_DIR"]
    authorized_keys = config["AUTHORIZED_KEYS"]

    for i in range(start_ip, start_ip + no_of_vm):
        pubkey_file = os.path.join(pubkey_dir, f"{host_base_name}{i}_id_rsa.pub")
        if os.path.exists(pubkey_file):
            with open(pubkey_file, "r") as f:
                key = f.read().strip()
                if key and key not in collected_keys:
                    collected_keys.add(key)
        else:
            print(f"⚠️ Skipping missing key file: {pubkey_file}")

    local_key_file = os.path.expanduser("~/.ssh/id_rsa.pub")
    if os.path.exists(local_key_file):
        with open(local_key_file, "r") as f:
            local_key = f.read().strip()
            if local_key and local_key not in collected_keys:
                collected_keys.add(local_key)
                print(f"➕ Added local system key: {local_key_file}")
    else:
        print(f"⚠️ Local public key not found: {local_key_file}")

    with open(authorized_keys, "w") as f:
        f.write("\n".join(collected_keys) + "\n")

    print(f"✅ Authorized_keys built with {len(collected_keys)} unique keys")


def distribute_keys(config):
    start_ip = int(config["START_IP"])
    no_of_vm = int(config["NO_OF_VMS"])
    base_ip = config["BASE_IP"]
    ssh_user = config["SSH_USER"]
    ssh_pass = config["SSH_PASS"]
    authorized_keys = config["AUTHORIZED_KEYS"]

    for i in range(start_ip, start_ip + no_of_vm):
        ip = f"{base_ip}{i}"
        print(f"🚀 Copying authorized_keys to {ip}...")
        try:
            subprocess.run([
                "sshpass", "-p", ssh_pass,
                "scp", "-o", "StrictHostKeyChecking=no",
                authorized_keys,
                f"{ssh_user}@{ip}:/root/.ssh/authorized_keys"
            ], check=True)
            print(f"✅ Copied authorized_keys to {ip}")
        except subprocess.CalledProcessError:
            print(f"❌ Failed to copy to {ip}")

def generating_ssh_key(hostname, ip):
    print(f"Copying generate_ssh_key.sh to {hostname}")
    run_cmd(f"sshpass -p samba scp -o StrictHostKeyChecking=no generate_ssh_key.sh root@{ip}:/root/", check=True)
    run_cmd(f"sshpass -p samba ssh root@{ip} 'bash generate_ssh_key.sh'", check=True)
    run_cmd(f"sshpass -p samba scp root@{ip}:/root/.ssh/id_rsa.pub {hostname}_id_rsa.pub", check=True)
    time.sleep(5)

def configuring_vm(config, hostname, ip, public_ip):
    ssh_user = config["SSH_USER"]
    ssh_pass = config.get("SSH_PASS", "samba")

    print(f"\n⚙️ Configuring VM {hostname} ({ip}, {public_ip})")

    # --- Update /etc/hosts on host system ---
    with open("/etc/hosts", "r+") as f:
        hosts = f.read()
        if hostname not in hosts:
            f.write(f"{ip}\t{hostname}\n")
            print(f"📝 Added {hostname} -> {ip} to /etc/hosts")

    # --- Ensure VM is running ---
    if check_vm_status(hostname) != "running":
        start_vm(hostname)

    if check_vm_status(hostname) == "running":
        time.sleep(5)

        vm_ips = get_vm_ips(hostname)
        vmip = vm_ips[0]
        run_cmd(f"sshpass -p {ssh_pass} ssh {ssh_user}@{vmip} 'mkdir -p /mnt/sambadr'")
        run_cmd(f"sshpass -p {ssh_pass} ssh {ssh_user}@{vmip} 'mount -t virtiofs commonfs /mnt/sambadir'")

        print(f"✅ Assigning hostname and IP for {hostname}")
        run_cmd(f"sshpass -p {ssh_pass} ssh -o StrictHostKeyChecking=No {ssh_user}@{vmip} 'hostnamectl hostname {hostname}'")
        run_cmd(f"sshpass -p {ssh_pass} scp -o StrictHostKeyChecking=No ipconfigure.sh {ssh_user}@{vmip}:/root/.")
        run_cmd(f"sshpass -p {ssh_pass} ssh -o StrictHostKeyChecking=No {ssh_user}@{vmip} 'bash ipconfigure.sh'")
        run_cmd(f"sshpass -p {ssh_pass} ssh {ssh_user}@{vmip} 'rm ipconfigure.sh'")
        run_cmd(f"rm ipconfigure.sh")
        time.sleep(5)
        stop_vm(hostname)
        start_vm(hostname)
        generating_ssh_key(hostname, ip)
        stop_vm(hostname)
        print(f"✅ VM {hostname} configured successfully")
    else:
        print(f"❌ VM {hostname} not running for IP assign")
        sys.exit(1)

def clone_vm(config):
    start_ip = int(read_config('START_IP'))
    no_of_vm = int(read_config('NO_OF_VMS'))
    base_ip = read_config('BASE_IP')
    ssh_user = read_config('SSH_USER')
    ssh_pwd = read_config('SSH_PASS')
    host_base_name = read_config('HOST_BASE_NAME')
    original_vm = read_config('ORIGINAL_VM')
    no_of_device = int(read_config('NO_OF_DEVICE'))

    for i in range(start_ip, start_ip + no_of_vm):
        host_name = f"{host_base_name}{i}"
        ip = f"{base_ip}{i}"
        public_ip = f"{base_ip}{i + 10}"
        if check_vm_exists(host_name):
            continue
        print(f"############## Cloning {host_name} #######################")
        cmd = f"{VIRT_CLONE} --original {original_vm} --name {host_name} --auto-clone --file /var/lib/libvirt/images/{host_name}.qcow2"
        run_cmd(cmd, check=True)
        create_ip_for_host(config, ip, public_ip)
        configuring_vm(config, host_name, ip, public_ip)
        run_cmd(f"ssh-copy-id -o {ssh_user}@{host_name}")

        if i == start_ip:
            print(f"Adding disk(s) to {host_name}")
            start_letter = "b"
            if check_vm_exists(host_name):
                for j in range(no_of_device):
                    letter_index = string.ascii_lowercase.index(start_letter)
                    device_letter = string.ascii_lowercase[letter_index + j]
                    device_name = f"vd{device_letter}"
                    disk = f"/var/lib/libvirt/images/{host_name}_disk{j}.qcow2"
                    run_cmd(f"qemu-img create -f qcow2 {disk} 5G")
                    time.sleep(1)
                    run_cmd(f"virsh attach-disk {host_name} {disk} {device_name} --cache=none --subdriver=qcow2 --persistent")
                    print(f"Disk {disk} added to {host_name}")

def cleanup_local_authorized_keys(config):
    authorized_keys = config["AUTHORIZED_KEYS"]
    pubkey_dir = config["PUBKEY_DIR"]
    host_base_name = config["HOST_BASE_NAME"]

    if os.path.exists(authorized_keys):
        os.remove(authorized_keys)
        print(f"🗑️ Deleted local {authorized_keys}")

    pub_files = glob.glob(os.path.join(pubkey_dir, f"{host_base_name}*_id_rsa.pub"))
    for pub_file in pub_files:
        os.remove(pub_file)
        print(f"🗑️ Deleted {pub_file}")


def make_distribute_ssh_keys(config):
    build_authorized_keys(config)
    distribute_keys(config)
    cleanup_local_authorized_keys(config)

# ---------------- GENERIC HELPERS ----------------
def copy_file(host, src, dest, user="root"):
    scp_cmd = f"scp {src} {user}@{host}:{dest}"
    print(f"📤 Copying {src} -> {host}:{dest}")
    subprocess.run(scp_cmd, shell=True, check=True)


def run_remote(host, cmd, user="root"):
    ssh_cmd = f"ssh {user}@{host} '{cmd}'"
    print(f"▶️ Running remote on {host}: {cmd}")
    subprocess.run(ssh_cmd, shell=True, check=True)


def run_cmd(cmd, check=False, capture=True):
    print(f"$ {cmd}")
    result = subprocess.run(cmd, shell=True,
                            stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.PIPE if capture else None,
                            text=True)
    if check and result.returncode != 0:
        print(f"❌ Command failed: {cmd}\n{result.stderr}")
        sys.exit(1)
    return result.stdout.strip() if capture else ""

# ---------------- VM HANDLING ----------------
def get_base_ip_from_ip(ip: str) -> str:
    return '.'.join(ip.split('.')[:3]) + '.'
def get_vm_ips(vm_name):
    """Return all IPv4 addresses of a VM as a list."""
    output = run_cmd(f"virsh domifaddr {vm_name}")
    ips = []
    for line in output.splitlines():
        print(line)
        # Match IPv4 addresses like 192.168.122.176/24
        match = re.search(r'(\d+\.\d+\.\d+\.\d+)/\d+', line)
        if match:
            ips.append(match.group(1))
    return ips
def get_gateway_over_ssh(vm_ip, user="root", password="samba"):
    """SSH into VM and extract default gateway from `ip route`."""
    cmd = f"sshpass -p {password} ssh -o StrictHostKeyChecking=no {user}@{vm_ip} ip route | grep default"
    output = run_cmd(cmd)
    match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', output)
    if match:
        return match.group(1)
    return None

def find_vm_gateways(vm_name, user="root", password="samba"):
    """Find all gateways for a VM by checking all its IPs."""
    ips = get_vm_ips(vm_name)
    results = {}
    for ip in ips:
        gw = get_gateway_over_ssh(ip, user, password)
        results[ip] = gw
    return results

def check_vm_exists(vm_name):
    out = run_cmd(f"virsh list --all | grep -w {vm_name}", check=False)
    return bool(out)


def check_vm_status(vm_name):
    return run_cmd(f"virsh domstate {vm_name} 2>/dev/null", check=False)


def stop_vm(vm_name):
    status = check_vm_status(vm_name)
    if status == "running":
        print(f"{vm_name} VM is running. Shutting it down")
        run_cmd(f"virsh shutdown {vm_name}")
        while check_vm_status(vm_name) == "running": time.sleep(1)
    elif status in ("shut off", "paused"):
        print(f"{vm_name} VM is not running")
    elif status == "crashed":
        print("❌ VM has crashed")
    else:
        print(f"ℹ️ Unknown VM state: {status}")


def start_vm(vm_name):
    status = check_vm_status(vm_name)
    if status == "running":
        print(f"✅ VM {vm_name} is running")
    elif status in ("shut off", "paused"):
        print(f"⚠️ VM {vm_name} is not running, starting it")
        run_cmd(f"virsh start {vm_name}")
        time.sleep(20)
    elif status == "crashed":
        print("❌ VM has crashed")
    else:
        print(f"ℹ️ Unknown VM state: {status}")

def start_ceph_vm(config):
    start_ip = int(config["START_IP"])
    base_ip = config["BASE_IP"]
    host_base_name = config["HOST_BASE_NAME"]

    # Ceph VM is the first VM in the cluster
    ceph_vm_name = f"{host_base_name}{start_ip}"
    ceph_vm_ip = f"{base_ip}{start_ip}"

    print(f"🚀 Starting Ceph VM {ceph_vm_name} ({ceph_vm_ip})")
    try:
        start_vm(ceph_vm_name)
        print(f"✅ Ceph VM {ceph_vm_name} started successfully")
    except Exception as e:
        print(f"❌ Failed to start Ceph VM {ceph_vm_name}: {e}")

def start_samba_vm(config):
    start_ip = int(config["START_IP"])
    no_of_vms = int(config["NO_OF_VMS"])
    base_ip = config["BASE_IP"]
    host_base_name = config["HOST_BASE_NAME"]

    # Samba nodes start after the Ceph node
    for i in range(start_ip + 1, start_ip + no_of_vms):
        samba_vm_name = f"{host_base_name}{i}"
        samba_vm_ip = f"{base_ip}{i}"

        print(f"🚀 Starting Samba VM {samba_vm_name} ({samba_vm_ip})")
        try:
            start_vm(samba_vm_name)
            print(f"✅ Samba VM {samba_vm_name} started successfully")
        except Exception as e:
            print(f"❌ Failed to start Samba VM {samba_vm_name}: {e}")

def provision_ceph_node(config):
    start_ip = int(config["START_IP"])
    base_ip = config["BASE_IP"]
    host_base_name = config["HOST_BASE_NAME"]
    ssh_user = config["SSH_USER"]

    # Ceph node = first VM
    ceph_vm_name = f"{host_base_name}{start_ip}"
    ceph_vm_ip = f"{base_ip}{start_ip}"

    print(f"\n####################  PROVISION CEPH NODE  #############################")
    print(f"⚙️  Provisioning Ceph on {ceph_vm_name} ({ceph_vm_ip})")

    try:
        copy_file(ceph_vm_name, "cluster.config", "cluster.config", ssh_user)
        copy_file(ceph_vm_name, "provision.py", "provision.py", ssh_user)
        run_remote(ceph_vm_name, "python3 provision.py", ssh_user)
        print(f"✅ Ceph node {ceph_vm_name} provisioned successfully")
    except Exception as e:
        print(f"❌ Failed to provision Ceph node {ceph_vm_name}: {e}")

def provision_samba_node(config):
    start_ip = int(config["START_IP"])
    no_of_vms = int(config["NO_OF_VMS"])
    no_of_samba_vms = int(config["NO_OF_SAMBA_VMS"])
    base_ip = config["BASE_IP"]
    host_base_name = config["HOST_BASE_NAME"]
    ssh_user = config["SSH_USER"]

    print("\n####################  PROVISION SAMBA NODES ############################")

    if (no_of_samba_vms > 1):
        # Samba nodes start after Ceph node
        for i in range(start_ip + no_of_vms - no_of_samba_vms, start_ip + no_of_vms):
            samba_vm_name = f"{host_base_name}{i}"
            samba_vm_ip = f"{base_ip}{i}"

            print(f"\n⚙️  Provisioning Samba on {samba_vm_name} ({samba_vm_ip})")

            try:
                copy_file(samba_vm_name, "cluster.config", "cluster.config", ssh_user)
                copy_file(samba_vm_name, "deploy_samba_cluster.py", "deploy_samba_cluster.py", ssh_user)
                copy_file(samba_vm_name, "installsamba.sh", "installsamba.sh", ssh_user)
                run_remote(samba_vm_name, "python3 deploy_samba_cluster.py", ssh_user)
                print(f"✅ Samba node {samba_vm_name} provisioned successfully")
            except Exception as e:
                print(f"❌ Failed to provision Samba node {samba_vm_name}: {e}")

def cleanup_vms(config):
    start_ip = int(config["START_IP"])
    no_of_vms = int(config["NO_OF_VMS"])
    host_base_name = config["HOST_BASE_NAME"]

    print("\n<<<<<<<<<<<<<< Cleaning up VMs >>>>>>>>>>>>>>>>")

    # Step 1: Shutdown and undefine all VMs
    for i in range(start_ip, start_ip + no_of_vms):
        vm_name = f"{host_base_name}{i}"
        status = check_vm_status(vm_name)

        if status == "running":
            print(f"⚠️  {vm_name} is running, shutting down...")
            run_cmd(f"virsh shutdown {vm_name}")
            time.sleep(5)

        print(f"🗑️  Removing VM definition for {vm_name}")
        run_cmd(f"virsh undefine {vm_name} --remove-all-storage")

    # Step 2: Remove leftover disks
    for i in range(start_ip, start_ip + no_of_vms):
        vm_name = f"{host_base_name}{i}"
        for disk_file in glob.glob(f"/var/lib/libvirt/images/{vm_name}_disk*.qcow2"):
            if os.path.exists(disk_file):
                os.remove(disk_file)
                print(f"🗑️  Deleted disk {disk_file}")

    print("✅ Cleanup completed")

def cluster_init():
    base_vm = read_config("ORIGINAL_VM")
    base_ip = read_config("BASE_IP")
    gateway = read_config("GATEWAY")

    if not base_vm:
        raise ValueError("BASE_VM (ORIGINAL_VM) not defined in GENERAL section")

    # Step 2: If both BASE_IP and GATEWAY exist, nothing to do
    if base_ip and gateway:
        print(f"BASE_IP = {base_ip}, GATEWAY = {gateway} already defined")

    else :
        start_vm(base_vm)

        ips = get_vm_ips(base_vm)
        if not ips:
            raise RuntimeError(f"Cannot get IP address for {base_vm}")

        first_ip = ips[0]
        base_ip = get_base_ip_from_ip(first_ip)
        gateway = get_gateway_over_ssh(first_ip)  # replace with actual gateway detection

        update_config("BASE_IP", base_ip)
        update_config("GATEWAY", gateway)
        stop_vm(base_vm)


# ---------------- MAIN ENTRY ----------------
def main():
    cluster_init()
    args = sys.argv[1:]
    config = load_config(CONFIG_FILE)

    if "--cleanup" in args:
        cleanup_vms(config)
    if "--clone" in args:
        clone_vm(config)
    if "--start_samba_cluster" in args:
        provision_samba_node(config)
    if "--start-ceph-cluster" in args:
        start_ceph_vm(config)
        start_samba_vm(config)
        make_distribute_ssh_keys(config)
        provision_ceph_node(config)
        provision_samba_node(config)
        print("Ceph provision not yet refactored")
    if "--single-ceph-single-samba" in args:
        config["NO_OF_VMS"] = 2
        clone_vm(config)
        start_ceph_vm(config)
        start_samba_vm(config)
        make_distribute_ssh_keys(config)
        print("Single Ceph + Samba clone not yet refactored")

if __name__ == "__main__":
    main()

