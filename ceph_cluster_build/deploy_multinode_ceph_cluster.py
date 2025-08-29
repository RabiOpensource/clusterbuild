#!/usr/bin/python3
import os
import subprocess

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

def run_local(cmd):
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
def write_public_address(device, base_ip, no_of_vms, start_ip, PREFIX_PATH):
    os.makedirs(f"{PREFIX_PATH}/etc/ctdb", exist_ok=True)
    with open(f"{PREFIX_PATH}/etc/ctdb/public_addresses", "w") as f:
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
def write_smb_conf_file(prefix_path):
    smb_conf = f"""
[global]
        include = registry
        clustering = yes

[share1]
        path = /mnt-cephfs/volumes/_nogroup/smbshares/share1
        read only = no
        inherit permissions = yes
"""
    os.makedirs(f"{prefix_path}/etc/samba", exist_ok=True)
    with open(f"{prefix_path}/etc/samba/smb.conf", "w") as f:
        f.write(smb_conf)

def main():
    cfg = load_config(CONFIG_FILE)

    START_IP = int(cfg["START_IP"])
    NO_OF_VMS = int(cfg["NO_OF_VMS"])
    BASE_IP = cfg["BASE_IP"]
    SAMBA_PKG = cfg["SAMBA_PKG"]
    SSH_USER = cfg["SSH_USER"]
    PREFIX_PATH = cfg["PATH_TO_CONFIGURE"]
    SSH_PASS = cfg.get("SSH_PASS", "")
    NETWORK_INTERFACE = cfg.get("NETWORK_INTERFACE", "enp8s0")

    HEAD_NODE = f'{BASE_IP}{START_IP}'
    ALL_NODES = [f"{BASE_IP}{START_IP + i}" for i in range(NO_OF_VMS)]

    print(f"Head Node: {HEAD_NODE}")
    print(f"Cluster Nodes: {ALL_NODES}")

    run_local("mkdir -p /mnt-cephfs/volumes/_nogroup/smbshares/share1")
    run_local("touch /mnt-cephfs/volumes/_nogroup/smbshares/cluster_lock")
    run_local("chmod 0777 /mnt-cephfs/volumes/_nogroup/smbshares/share1")

    for host in ALL_NODES[1:]:
        print(f"\n⚙️ Setting up Ceph on {host}")
        copy_file(host, "-o StrictHostKeyChecking=no /root/.ssh/config", "/root/.ssh", SSH_USER)
        #following files are related to ceph. So files should copy to /etc/ceph
        for file in ["ceph.conf", "ceph.client.admin.keyring", "ceph.pub", "rbdmap"]:
            copy_file(host, f"-o StrictHostKeyChecking=no /etc/ceph/{file}", "/etc/ceph", SSH_USER)

        run_remote(host, "dnf install -y centos-release-ceph-reef", SSH_USER)
        run_remote(host, "dnf install -y ceph-fuse", SSH_USER)
        run_remote(host, "mkdir -p /mnt-cephfs", SSH_USER)
        run_remote(host, "ceph-fuse /mnt-cephfs/", SSH_USER)

    if not os.path.exists(SAMBA_PKG):
        print(f"❌ Samba package {SAMBA_PKG} not found")
        return
    #run_local(f"tar xzf {SAMBA_PKG}")

    write_ctdb_conf_file(PREFIX_PATH)
    write_ip_to_node(PREFIX_PATH, ALL_NODES)
    write_public_address(NETWORK_INTERFACE, BASE_IP, NO_OF_VMS, START_IP, PREFIX_PATH)
    write_smb_conf_file(PREFIX_PATH)


    for host in ALL_NODES:
        print(f"\n⚙️ Setting up Samba + CTDB on {host}")

#        if host != HEAD_NODE:
#            copy_file(host, SAMBA_PKG, "/", SSH_USER)
#            run_remote(host, f"tar xzf {SAMBA_PKG} -C /", SSH_USER)

        for port in ["22/tcp", "4379/tcp", "4379/udp", "445/tcp"]:
            run_remote(host, f"-o StrictHostKeyChecking=no firewall-cmd --zone=public --permanent --add-port={port}", SSH_USER)
        run_remote(host, "systemctl restart firewalld", SSH_USER)

        for file in ["ctdb.conf", "nodes", "public_addresses"]:
            copy_file(host, f"{PREFIX_PATH}/etc/ctdb/{file}", "/etc/ctdb", SSH_USER)
        copy_file(host, f"{PREFIX_PATH}/etc/samba/smb.conf", "/etc/samba", SSH_USER)

        run_remote(host, "useradd -M -s /sbin/nologin user1 || true", SSH_USER)
#        copy_file(host, "/samba-helper.sh", "/", SSH_USER)
#        run_remote(host, "/bin/bash /samba-helper.sh", SSH_USER)

        for script in ["00.ctdb", "01.reclock", "05.system", "10.interface", "95.database"]:
            run_remote(host, f"ctdb event script enable legacy {script}", SSH_USER)

        run_remote(host, f"{PREFIX_PATH}/sbin/ctdbd", SSH_USER)
        run_remote(host, f"{PREFIX_PATH}/sbin/smbd", SSH_USER)

if __name__ == "__main__":
    main()

