#!/usr/bin/env python3
import subprocess
import sys
import time
import os
import glob

# Config
ORIGINAL_VM = "cephnode1_ori"
HOST_BASE_NAME = "cephnode"
NO_OF_VM = 3
BASE_IP = "192.168.122."
START_IP = 190
NO_OF_DEVICE = 1
VIRT_CLONE = "/usr/bin/virt-clone"

SSH_USER = "root"
SSH_PASS = "samba"
AUTHORIZED_KEYS = "./authorized_keys"
PUBKEY_DIR = "./"




def build_authorized_keys():
    """Merge all VM public keys into authorized_keys."""
    collected_keys = set()

    for i in range(START_IP, START_IP + NO_OF_VM):
        pubkey_file = os.path.join(PUBKEY_DIR, f"{HOST_BASE_NAME}{i}_id_rsa.pub")
        if os.path.exists(pubkey_file):
            with open(pubkey_file, "r") as f:
                key = f.read().strip()
                if key and key not in collected_keys:
                    collected_keys.add(key)
        else:
            print(f"⚠️ Skipping missing key file: {pubkey_file}")

    with open(AUTHORIZED_KEYS, "w") as f:
        f.write("\n".join(collected_keys) + "\n")

    print(f"✅ Authorized_keys built with {len(collected_keys)} unique keys")

def distribute_keys():
    """Copy authorized_keys to all VMs."""
    for i in range(START_IP, START_IP + NO_OF_VM):
        ip = f"{BASE_IP}{i}"
        print(f"🚀 Copying authorized_keys to {ip}...")
        try:
            subprocess.run([
                "sshpass", "-p", SSH_PASS,
                "scp", "-o", "StrictHostKeyChecking=no",
                AUTHORIZED_KEYS,
                f"{SSH_USER}@{ip}:/root/.ssh/authorized_keys"
            ], check=True)
            print(f"✅ Copied authorized_keys to {ip}")
        except subprocess.CalledProcessError:
            print(f"❌ Failed to copy to {ip}")

def cleanup_local_authorized_keys():
    """Delete local authorized_keys file after distribution."""
    if os.path.exists(AUTHORIZED_KEYS):
        os.remove(AUTHORIZED_KEYS)
        print(f"🗑️ Deleted local {AUTHORIZED_KEYS}")

    pub_files = glob.glob(os.path.join(PUBKEY_DIR, f"{HOST_BASE_NAME}*_id_rsa.pub"))
    for pub_file in pub_files:
        os.remove(pub_file)
        print(f"🗑️ Deleted {pub_file}")



def make_distribute_ssh_keys():
    build_authorized_keys()
    distribute_keys()
    ########cleanup_local_authorized_keys()












def run_cmd(cmd, check=False, capture=True):
    """Run shell command, optionally fail hard."""
    print(f"$ {cmd}")
    result = subprocess.run(cmd, shell=True,
                            stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.PIPE if capture else None,
                            text=True)
    if check and result.returncode != 0:
        print(f"❌ Command failed: {cmd}\n{result.stderr}")
        sys.exit(1)
    return result.stdout.strip() if capture else ""


def check_vm_exists(vm_name):
    out = run_cmd(f"virsh list --all | grep -w {vm_name}", check=False)
    if out:
        print(f"{vm_name} vm found")
        return True
    else:
        print(f"{vm_name} vm not found")
        return False


def check_vm_status(vm_name):
    return run_cmd(f"virsh domstate {vm_name} 2>/dev/null", check=False)


def stop_vm(vm_name):
    status = check_vm_status(vm_name)
    if status == "running":
        print(f"{vm_name} VM is running. Shutting it down")
        run_cmd(f"virsh shutdown {vm_name}")
        time.sleep(5)
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


def clean_vm():
    print("<<<<<<<<<<<<<< Cleaning VM >>>>>>>>>>>>>>>>")
    for i in range(START_IP, START_IP + NO_OF_VM):
        host_name = f"{HOST_BASE_NAME}{i}"
        status = check_vm_status(host_name)
        if status == "running":
            run_cmd(f"virsh shutdown {host_name}")
            print("Sleeping 5 sec")
            time.sleep(5)
        run_cmd(f"virsh undefine {host_name} --remove-all-storage")
    host_name = f"{HOST_BASE_NAME}{START_IP}"
    for j in range(NO_OF_DEVICE):
        disk = f"/var/lib/libvirt/images/{host_name}_disk{j}.qcow2"
        if os.path.exists(disk):
            os.remove(disk)
            print(f"🗑️ Removed {disk}")


def create_ip_for_host(local_ip, public_ip):
    print(f"Generating ip configure script for {local_ip} and public id {public_ip}")
    with open("ipconfigure.sh", "w") as f:
        f.write(f'nmcli connection modify enp1s0 ipv4.addresses "{local_ip}/24" ipv4.gateway "192.168.122.1"\n')
        f.write(f'nmcli connection modify enp8s0 ipv4.addresses "{public_ip}/24" ipv4.gateway "192.168.122.1"\n')


def generating_ssh_key(hostname, ip):
    print(f"Copying generate_ssh_key.sh to {hostname}")
    run_cmd(f"sshpass -p samba scp -o StrictHostKeyChecking=no generate_ssh_key.sh root@{ip}:/root/", check=True)
    run_cmd(f"sshpass -p samba ssh root@{ip} 'bash generate_ssh_key.sh'", check=True)
    run_cmd(f"sshpass -p samba scp root@{ip}:/root/.ssh/id_rsa.pub {hostname}_id_rsa.pub", check=True)
    time.sleep(5)


def assign_hostname_ip_vm(hostname, ip):
    print(f"Assigning hostname and IP for {hostname}")

    # /etc/hosts update
    with open("/etc/hosts", "r+") as f:
        hosts = f.read()
        if hostname not in hosts:
            f.write(f"{ip}\t{hostname}\n")

    if check_vm_status(hostname) != "running":
        start_vm(hostname)

    if check_vm_status(hostname) == "running":
        run_cmd(f"sshpass -p samba ssh root@192.168.122.160 'hostnamectl hostname {hostname}'")
        run_cmd(f"sshpass -p samba scp ipconfigure.sh root@192.168.122.160:/root/.")
        run_cmd(f"sshpass -p samba ssh root@192.168.122.160 'bash ipconfigure.sh'")
        run_cmd(f"sshpass -p samba ssh root@192.168.122.160 'rm ipconfigure.sh'")
        run_cmd(f"rm ipconfigure.sh")
        time.sleep(5)
        stop_vm(hostname)
        start_vm(hostname)
        generating_ssh_key(hostname, ip)
        stop_vm(hostname)
    else:
        print(f"❌ VM {hostname} not running for IP assign")
        sys.exit(1)


def clone_vm():
    for i in range(START_IP, START_IP + NO_OF_VM):
        host_name = f"{HOST_BASE_NAME}{i}"
        ip = f"{BASE_IP}{i}"
        public_ip = f"{BASE_IP}{i + 10}"
        if check_vm_exists(host_name):
            continue
        print(f"############## Cloning {host_name} #######################")
        cmd = f"{VIRT_CLONE} --original {ORIGINAL_VM} --name {host_name} --auto-clone --file /var/lib/libvirt/images/{host_name}.qcow2"
        run_cmd(cmd, check=True)
        create_ip_for_host(ip, public_ip)
        assign_hostname_ip_vm(host_name, ip)

        if i == START_IP:
            print(f"Adding disk(s) to {host_name}")
            if check_vm_exists(host_name):
                for j in range(NO_OF_DEVICE):
                    disk = f"/var/lib/libvirt/images/{host_name}_disk{j}.qcow2"
                    run_cmd(f"qemu-img create -f qcow2 {disk} 5G")
                    run_cmd(f"virsh attach-disk {host_name} {disk} vdb --cache=none --subdriver=qcow2 --persistent")
                    print(f"Disk {disk} added to {host_name}")


def start_ceph_vm():
    host_name = f"{HOST_BASE_NAME}{START_IP}"
    print(f"Starting Ceph VM {host_name}")
    start_vm(host_name)
    time.sleep(10)


def start_samba_vm():
    for i in range(START_IP + 1, START_IP + NO_OF_VM):
        host_name = f"{HOST_BASE_NAME}{i}"
        print(f"Starting Samba VM {host_name}")
        start_vm(host_name)


def start_ceph_cluster():
    print("<<<<<<<<<<<< Starting Ceph Cluster >>>>>>>>>>>>>>")
    head = f"{HOST_BASE_NAME}{START_IP}"
    if check_vm_status(head) != "running":
        print(f"Head node {head} not running, starting...")
        start_vm(head)
        print("Waiting 10s...")
        time.sleep(10)
    else:
        print(f"Head node {head} already running")


def start_samba_cluster():
    print("<<<<<<<<<<<< Starting Samba Cluster >>>>>>>>>>>>>>")
    for i in range(START_IP + 1, START_IP + NO_OF_VM):
        host_name = f"{HOST_BASE_NAME}{i}"
        start_vm(host_name)
        print(f"Setting up Samba + CTDB on {host_name}")
        run_cmd(f"ssh {host_name} 'sudo systemctl enable smb ctdb && sudo systemctl start smb ctdb && sudo ctdb status'")


def main():
    args = sys.argv[1:]
    if "--cleanup" in args:
        clean_vm()
    if "--clone" in args:
        clone_vm()
    if "--start-ceph-cluster" in args:
        start_ceph_vm()
        start_samba_vm()
        make_distribute_ssh_keys()
        print("Start ceph cluster")


if __name__ == "__main__":
    main()
