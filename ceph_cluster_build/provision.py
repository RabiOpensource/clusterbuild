#!/usr/bin/python3
import subprocess
import time
#from config_loader import load_cluster_config

def load_cluster_config():
    cfg = {}
    with open("cluster.txt") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip('"')
                cfg[key] = val

    # Convert known fields
    cfg["START_IP"] = int(cfg.get("START_IP", 0))
    cfg["NO_OF_VMS"] = int(cfg.get("NO_OF_VMS", 0))

    if "HEAD_NODE_IP" not in cfg:
        cfg["HEAD_NODE_IP"] = f"{cfg['BASE_IP']}{cfg['START_IP']}"

    return cfg

def run(cmd, check=True, capture_output=False):
    """Run a shell command."""
    print(f"👉 Running: {cmd}")
    return subprocess.run(
        cmd,
        shell=True,
        check=check,
        text=True,
        capture_output=capture_output
    )

def ensure_host_in_etc_hosts(ip: str, hostname: str, hosts_file: str = "/etc/hosts"):
    """ 
    Ensure that the given hostname is mapped to the given IP in /etc/hosts.
    If the hostname does not exist, append it.
    """
    found = False

    # Read current /etc/hosts
    if os.path.exists(hosts_file):
        with open(hosts_file, "r") as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] == hostname:
                        found = True
                        break

    # Append if not found
    if not found:
        entry = f"{ip}\t{hostname}\n"
        try:
            with open(hosts_file, "a") as f:
                f.write(entry)
            print(f"✅ Added {hostname} -> {ip} to {hosts_file}")
        except PermissionError:
            print(f"❌ Permission denied: Need sudo/root to modify {hosts_file}")
    else:
        print(f"ℹ️ Host {hostname} already exists in {hosts_file}")



def main():
    cfg = load_cluster_config()

    START_IP = cfg["START_IP"]
    NO_OF_VMS = cfg["NO_OF_VMS"]
    BASE_IP = cfg["BASE_IP"]
    SSH_USER = cfg["SSH_USER"]
    HEAD_NODE_IP = cfg["HEAD_NODE_IP"]

    # --- Install Ceph packages ---
    run("dnf install -y centos-release-ceph-reef")
    run("dnf install -y cephadm")
    run("cephadm add-repo --dev main")
    run("dnf update -y cephadm")

    # --- Bootstrap Ceph cluster ---
    run("cephadm install ceph-common")
    run(f"cephadm bootstrap --mon-ip={HEAD_NODE_IP} --initial-dashboard-password='x' --allow-overwrite")

    # --- SSH config for cephnode?? ---
    ssh_config = "/root/.ssh/config"
    with open(ssh_config, "w") as f:
        f.write("Host cephnode??\n")
        f.write("\tStrictHostKeyChecking no\n")
        f.write("\tUpdateHostKeys yes\n")

    # --- Loop through all VMs ---
    for i in range(START_IP, NO_OF_VMS + 1):
        host = f"cephnode{i}"
        ip = f"{BASE_IP}{START_IP + i}"

        ensure_host_in_etc_hosts(ip, host)
        print(f"\n➡️ Processing {host} ({ip})")

        # Wait until SSH is available
        while run(f"ssh {SSH_USER}@{host} /bin/true", check=False).returncode != 0:
            print(f"⏳ Waiting for {host} SSH ...")
            time.sleep(1)

        # Copy ceph.pub
        run(f"ssh-copy-id -f -i /etc/ceph/ceph.pub {SSH_USER}@{host}")

        # Install podman
        run(f"ssh {host} dnf install -y podman")

        # Add host to orchestrator
        run(f"ceph orch host add {host} {ip}")

        # Add label
        run(f"ceph orch host label add {host} smb")

    # Label cephnode1 as smb explicitly
    run("ceph orch host label add cephnode1 smb")

    # --- Apply OSD ---
    run("ceph orch apply osd --all-available-devices")

    while run("ceph -s | grep HEALTH_OK", check=False).returncode != 0:
        print("⏳ Waiting for cluster HEALTH_OK ...")
        time.sleep(5)

    # --- Create filesystem ---
    run("ceph fs volume create mycephfs")

    while run("ceph fs ls | grep mycephfs", check=False).returncode != 0:
        print("⏳ Waiting for mycephfs ...")
        time.sleep(5)

    # --- Create smbshares subvolume ---
    while run("ceph fs subvolume ls mycephfs | grep smbshares", check=False).returncode != 0:
        print("📂 Creating smbshares ...")
        run("ceph fs subvolume create mycephfs smbshares --mode 0777")
        time.sleep(5)

    # --- Enable orchestrator ---
    run("ceph mgr module enable orchestrator")

    # --- Install clients ---
    run("dnf install -y ceph-fuse samba-client")
    run("mkdir -p /mnt-cephfs && ceph-fuse /mnt-cephfs")

    print("✅ Ceph bootstrap complete!")

if __name__ == "__main__":
    main()
