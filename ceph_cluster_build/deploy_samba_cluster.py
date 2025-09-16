#!/usr/bin/python3
import os
import subprocess
import time
import pwd
import shutil

CONFIG_FILE = "cluster.config"

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

def add_user(username, password="samba", prefix_path=""):
    try:
        # Check if user exists
        pwd.getpwnam(username)
        print(f"User {username} already exists.")
    except KeyError:
        # User does not exist → create it
        print(f"User {username} does not exist. Creating...")
        run_cmd(f"useradd -M -s /bin/bash {username} || true")
        run_cmd(f"(echo '{password}'; echo '{password}') | {prefix_path}/bin/smbpasswd -s -a {username}")

        print(f"User {username} created successfully.")

def run_cmd(cmd):
    print(f"▶️ Running local: {cmd}")
    try:
        subprocess.run(cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Local command failed: {e}")

def run_remote(host, cmd, user="root"):
    ssh_cmd = f"ssh {user}@{host} '{cmd}'"
    print(f"▶️ Running remote on {host}: {cmd}")
    try:
        subprocess.run(ssh_cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Remote command on {host} failed: {e}")

def copy_file(host, src, dest, user="root"):
    scp_cmd = f"scp {src} {user}@{host}:{dest}"
    print(f"📤 Copying {src} -> {host}:{dest}")
    try:
        subprocess.run(scp_cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ File copy to {host} failed: {e}")

#files are related to samba so we are giving PREFIX_PATH
def write_ip_to_node(prefix_path, all_nodes):
    with open(f"{prefix_path}/etc/ctdb/nodes", "w") as f:
        f.write("\n".join(all_nodes) + "\n")

#files are related to samba so we are giving PREFIX_PATH
def write_public_address(device, base_ip, no_of_vms, start_ip, prefix_path):
    os.makedirs(f"{prefix_path}/etc/ctdb", exist_ok=True)
    with open(f"{prefix_path}/etc/ctdb/public_addresses", "w") as f:
        for i in range(no_of_vms):
            pub_ip = f"{base_ip}{start_ip + 10 + i}"
            f.write(f"{pub_ip}/24 {device}\n")

#files are related to samba so we are giving PREFIX_PATH
def write_ctdb_conf_file(prefix_path):
    ctdb_conf =f"""
[logging]
        log file = {prefix_path}/var/log/log.ctdb
        log level = NOTICE

[cluster]
        recovery lock = {prefix_path}/etc/ctdb/reclock
        cluster lock = {prefix_path}/etc/ctdb/cluster_lock
"""
    os.makedirs(f"{prefix_path}/etc/ctdb", exist_ok=True)
    with open(f"{prefix_path}/etc/ctdb/ctdb.conf", "w") as f:
        f.write(ctdb_conf)

def ceph_fuse_install():
    if shutil.which("ceph-fuse"):
        print("✅ ceph-fuse is already installed")
        return

    print("ℹ️ ceph-fuse not found. Installing...")

    run_cmd("dnf install -y centos-release-ceph-squid", check=True)
    run_cmd("dnf install -y ceph-fuse ceph-common", check=True)

    if shutil.which("ceph-fuse"):
        print("✅ ceph-fuse installation successful")
    else:
        print("❌ ceph-fuse installation failed")

def update_local_mount():
    run_cmd("mkdir -p /mnt/commonfs")

def get_ceph_file_system_name()
    ceph_head_node = read_config("CEPH_HEAD_NODE")
    if ceph_head_node is None:
        print("❌ System is not configured properly. Reconfigure it")

    output = run_remote(ceph_head_node, "ceph fs ls")
    if not output:
        print("❌ Failed to get Ceph file systems from head node")
        return None

    fs_names = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("name:"):
            # Format: name: cephfs, metadata pool: ...
            try:
                fs_name = line.split("name:")[1].split(",")[0].strip()
                fs_names.append(fs_name)
            except IndexError:
                continue

    if not fs_names:
        print("❌ No filesystem name found in ceph fs ls output")
        return None

    # Return first one if only single FS is expected
    return fs_names[0] if len(fs_names) == 1 else fs_names

def generating_ceph_key_ring():
    samba_user = read_config("SAMBA_USER")
    ceph_head_node = read_config("CEPH_HEAD_NODE")
    ssh_user = read_config("SSH_USER") or "root"

    if not samba_user or not ceph_head_node:
        print("❌ SAMBA_USER or CEPH_HEAD_NODE not found in config")
        return None

    fs_name = get_ceph_file_system_name()
    if not fs_name:
        print("❌ Could not determine Ceph filesystem name")
        return None

    keyring_path = f"/etc/ceph/ceph.client.{samba_user}.keyring"
    os.makedirs("/etc/ceph", exist_ok=True)

    # Build command
    cmd = (
        f"ssh {ssh_user}@{ceph_head_node} "
        f"\"sudo ceph fs authorize {fs_name} client.{samba_user} / rw\" "
        f"| sudo tee {keyring_path}"
    )

    # Run with run_cmd
    output = run_cmd(cmd, check=True)

    print(f"✅ Ceph keyring generated at {keyring_path}")
    return keyring_path


def write_smb_conf_file(prefix_path):
    smb_conf = f"""
[global]
        include = registry
        clustering = yes
        log level = 10

[share1]
        path = /mnt-cephfs/volumes/_nogroup/smbshares/share1
        read only = no
        inherit permissions = yes
"""
    os.makedirs(f"{prefix_path}/etc/", exist_ok=True)
    with open(f"{prefix_path}/etc/smb.conf", "w") as f:
        f.write(smb_conf)

def main():
    cfg = load_config(CONFIG_FILE)

    START_IP = int(cfg["START_IP"])
    NO_OF_VMS = int(cfg["NO_OF_VMS"])
    BASE_IP = cfg["BASE_IP"]
    SAMBA_PKG = cfg["SAMBA_PKG"]
    SSH_USER = cfg["SSH_USER"]
    PREFIX_PATH = cfg["PATH_TO_CONFIGURE"]
    SAMBA_PATH = cfg["SAMBA_PATH"]
    SSH_PASS = cfg.get("SSH_PASS", "")
    NETWORK_INTERFACE = cfg.get("NETWORK_INTERFACE", "enp8s0")
    NO_SAMBA_VMS = int(cfg["NO_OF_SAMBA_VMS"])

    HEAD_NODE = f'{BASE_IP}{START_IP}'
    ALL_NODES = [f"{BASE_IP}{START_IP}" for i in range(NO_OF_VMS)]
    SAMBA_NODES = [
        f"{BASE_IP}{ip}"
        for ip in range(START_IP + NO_OF_VMS - NO_SAMBA_VMS, START_IP + NO_OF_VMS)
    ]

    print(f"Head Node: {HEAD_NODE}")
    print(f"Samba cluster Nodes: {SAMBA_NODES}")

    run_cmd(f"mount -t virtiofs commonfs /mnt/commonfs/")
    time.sleep(5)
    if not os.path.exists(SAMBA_PKG):
        print(f"❌ Samba path {SAMBA_PKG} not found")
        return

    run_cmd(f"bash installsamba.sh")

    write_ctdb_conf_file(PREFIX_PATH)
    write_ip_to_node(PREFIX_PATH, SAMBA_NODES)
    write_public_address(NETWORK_INTERFACE, BASE_IP, NO_SAMBA_VMS,
                         START_IP + NO_OF_VMS - NO_SAMBA_VMS,
                         PREFIX_PATH)
    write_smb_conf_file(PREFIX_PATH)


#    print(f"\n⚙️ Setting up Samba + CTDB on {host}")


    for port in ["22/tcp", "4379/tcp", "4379/udp", "445/tcp"]:
        run_cmd(f"firewall-cmd --zone=public --permanent --add-port={port}")
    run_cmd("systemctl restart firewalld")

    add_user("user1", "samba", PREFIX_PATH)

    for script in ["00.ctdb", "01.reclock", "05.system", "10.interface", "95.database"]:
        run_cmd(f"{PREFIX_PATH}/bin/ctdb event script enable legacy {script}")

    time.sleep(10)
    run_cmd(f"{PREFIX_PATH}/sbin/ctdbd")
    time.sleep(10)
    run_cmd(f"{PREFIX_PATH}/sbin/smbd -D")

    

if __name__ == "__main__":
    main()

