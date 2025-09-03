#!/usr/bin/python3
import os
import subprocess
import time

CONFIG_FILE = "cluster.txt"

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
    ctdb_conf = """
[logging]
        location = syslog
        log level = NOTICE

[cluster]
        cluster lock = /mnt-cephfs/volumes/_nogroup/smbshares/cluster_lock
"""
    os.makedirs(f"{prefix_path}/etc/ctdb", exist_ok=True)
    with open(f"{prefix_path}/etc/ctdb/ctdb.conf", "w") as f:
        f.write(ctdb_conf)

def update_local_mount():
    run_cmd("mkdir -p /mnt/commonfs")

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

    HEAD_NODE = f'{BASE_IP}{START_IP}'
    ALL_NODES = [f"{BASE_IP}{START_IP}" for i in range(NO_OF_VMS)]
    SAMBA_NODES = [f"{BASE_IP}{START_IP + i}" for i in range(NO_OF_VMS)]

    print(f"Head Node: {HEAD_NODE}")
    print(f"Samba cluster Nodes: {SAMBA_NODES}")

    run_cmd("mkdir -p /mnt-cephfs/volumes/_nogroup/smbshares/share1")
    run_cmd("touch /mnt-cephfs/volumes/_nogroup/smbshares/cluster_lock")
    run_cmd("chmod 0777 /mnt-cephfs/volumes/_nogroup/smbshares/share1")
    run_cmd("/usr/local/samba/private/")

    run_cmd(f"mount -t virtiofs commonfs /mnt/commonfs/")
    time.sleep(5)
    if not os.path.exists(SAMBA_PKG):
        print(f"❌ Samba path {SAMBA_PKG} not found")
        return

    run_cmd(f"bash installsamba.sh")

    write_ctdb_conf_file(PREFIX_PATH)
    write_ip_to_node(PREFIX_PATH, SAMBA_NODES)
    write_public_address(NETWORK_INTERFACE, BASE_IP, NO_OF_VMS, START_IP, PREFIX_PATH)
    write_smb_conf_file(PREFIX_PATH)


#    print(f"\n⚙️ Setting up Samba + CTDB on {host}")


    for port in ["22/tcp", "4379/tcp", "4379/udp", "445/tcp"]:
        run_cmd(f"firewall-cmd --zone=public --permanent --add-port={port}")
    run_cmd("systemctl restart firewalld")

    run_cmd(f"useradd -M -s /sbin/nologin user1 || true")
    run_cmd(f"(echo s1ngt3l; echo s1ngt3l) | passwd user1")
    run_cmd(f"(echo s1ngt3l; echo s1ngt3l) | /mnt/commonfs/bin/smbpasswd -a user1")

    for script in ["00.ctdb", "01.reclock", "05.system", "10.interface", "95.database"]:
        run_cmd(f"/mnt/commonfs/bin/ctdb event script enable legacy {script}")

    time.sleep(10)
    run_cmd(f"{PREFIX_PATH}/sbin/smbd -D")
    time.sleep(10)
    run_cmd(f"{PREFIX_PATH}/sbin/ctdbd")

    

if __name__ == "__main__":
    main()

