#!/usr/bin/python3
import os
import subprocess
import time
import pwd
import shutil
import re
from configurecluster import *

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
        run_cmd(f"useradd -m -s /bin/bash {username} || true")
        run_cmd(f"(printf '%s\n' '{password}'; printf '%s\n' '{password}') | {prefix_path}/bin/smbpasswd -s -a {username}")

        print(f"User {username} created successfully.")

def run_cmd(cmd, check=False, capture=True):
    shell = isinstance(cmd, str)

    print(f"▶️ Running local: {cmd}")

    try:
        subprocess.run(cmd, shell=True, check=True)
        result = subprocess.run(
            cmd,
            shell=shell,
            check=check,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.STDOUT if capture else None,
            text=True
        )
        return result.stdout.strip() if capture else ""
    except subprocess.CalledProcessError as e:
        print(f"❌ Local command failed: {e}")
        if e.stdout:
            print(f"--- output ---\n{e.stdout}")
        sys.exit(1 if check else 0)
def run_remote(host, command, user="root"):
    import subprocess
    print(f"▶️ Running remote on {host}: {command}")
    result = subprocess.run(
        ["ssh", host, command],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"❌ Command failed: {result.stderr}")
        return None
    return result.stdout.strip()

def copy_file(host, src, dest, user="root"):
    scp_cmd = f"scp {src} {user}@{host}:{dest}"
    print(f"📤 Copying {src} -> {host}:{dest}")
    try:
        subprocess.run(scp_cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ File copy to {host} failed: {e}")

#files are related to samba so we are giving PREFIX_PATH
def write_ip_to_node( all_nodes):
    prefix_path = read_config("PATH_TO_CONFIGURE")
    with open(f"{prefix_path}/etc/ctdb/nodes", "w") as f:
        f.write("\n".join(all_nodes) + "\n")

#files are related to samba so we are giving PREFIX_PATH
def write_public_address(device, base_ip, no_of_vms, start_ip):
    prefix_path = read_config("PATH_TO_CONFIGURE")
    os.makedirs(f"{prefix_path}/etc/ctdb", exist_ok=True)
    with open(f"{prefix_path}/etc/ctdb/public_addresses", "w") as f:
        for i in range(no_of_vms):
            pub_ip = f"{base_ip}{start_ip + 10 + i}"
            f.write(f"{pub_ip}/24 {device}\n")

def check_add_firewall_port(port, protocol="tcp"):
    try:
        port_proto = f"{port}/{protocol}"

        # Get list of open ports
        result = run_cmd("firewall-cmd --list-ports")
        open_ports = result.strip().split() if result else []

        if port_proto in open_ports:
            print(f"✅ Port {port_proto} is already allowed in firewall.")
            return True

        # Add port permanently and reload firewall
        print(f"➕ Adding port {port_proto} to firewall...")
        run_cmd(f"firewall-cmd --permanent --add-port={port_proto}")
        run_cmd("firewall-cmd --reload")

        # Verify
        result_after = run_cmd("firewall-cmd --list-ports")
        if port_proto in result_after.strip().split():
            print(f"✅ Port {port_proto} successfully added to firewall.")
            return True
        else:
            print(f"❌ Failed to add port {port_proto} to firewall.")
            return False

    except Exception as e:
        print(f"⚠️ Error ensuring firewall port {port}/{protocol}: {e}")
        return False


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

def get_ceph_file_system_name():
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
    samba_user = read_config("SAMBA_USER") or "user1"
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


    check_cmd = f"ssh {ssh_user}@{ceph_head_node} 'ceph auth get client.{samba_user}'"
    auth_output = run_cmd(check_cmd, check=False)
    already_authorized = False
    if auth_output:
        match = re.search(r'caps mds = .*fsname=([A-Za-z0-9._-]+)', auth_output)
        if match and match.group(1) == fs_name:
            already_authorized = True

    if already_authorized:
        print(f"ℹ️ User client.{samba_user} is already authorized for FS '{fs_name}', fetching keyring...")
        get_key_cmd = f"ssh {ssh_user}@{ceph_head_node} 'ceph auth get client.{samba_user}' | tee {keyring_path}"
        run_cmd(get_key_cmd, check=True)
    else:
        print(f"🔑 Authorizing client.{samba_user} for FS '{fs_name}'...")
        auth_cmd = (
            f"ssh {ssh_user}@{ceph_head_node} "
            f"\"ceph fs authorize {fs_name} client.{samba_user} / rw\" "
            f"| tee {keyring_path}"
        )
        run_cmd(auth_cmd, check=True)

    if os.path.exists(keyring_path):
        print(f"✅ Ceph keyring ready at {keyring_path}")
        return keyring_path
    else:
        print("❌ Failed to generate keyring")
        return None

def mount_cephfs(mount_point="/mnt/cephfs"):
    samba_user = read_config("SAMBA_USER") or "user1"
    ceph_head_node = read_config("CEPH_HEAD_NODE")
    if not samba_user or not ceph_head_node:
        print("❌ SAMBA_USER or CEPH_HEAD_NODE not found in config")
        return False

    fs_name = get_ceph_file_system_name()
    if not fs_name:
        print("❌ Could not determine Ceph filesystem name")
        return False

    # Ensure secret key exists
    secret_key = get_user_keyring_secrate_key()
    if not secret_key:
        print("❌ Could not retrieve secret key")
        return False

    if not is_mounted(mount_point):
        print("we count not able find mount path")
        # Create mount directory
        os.makedirs(mount_point, exist_ok=True)

        # Build Ceph mount command using secret key directly
        cmd = (
            f"sudo mount -t ceph {ceph_head_node}:6789:/ "
            f"{mount_point} -o name={samba_user},secret={secret_key},fs={fs_name}"
        )

        print("executing command " + cmd)
        output = run_cmd(cmd, check=False)
        if "mount" in output.lower() or os.path.ismount(mount_point):
            print(f"✅ CephFS mounted at {mount_point}")
            return True
        else:
            print(f"❌ Failed to mount CephFS at {mount_point}")
            return False

def get_user_keyring_secrate_key():
    keyring_path = generating_ceph_key_ring()
    if not keyring_path or not os.path.exists(keyring_path):
        print(f"❌ Keyring file not found: {keyring_path}")
        return None

    with open(keyring_path, "r") as f:
        content = f.read()

    # Extract "key = ..." line
    match = re.search(r'key\s*=\s*([A-Za-z0-9+/=]+)', content)
    if match:
        secret = match.group(1).strip()
        print(f"✅ Found secret key in {keyring_path}")
        return secret
    else:
        print("❌ No secret key found in keyring file")
        return None
def is_mounted(mount_point: str) -> bool:
    try:
        with open("/proc/mounts", "r") as f:
            mounts = f.read().splitlines()
        return any(mount_point in line.split() for line in mounts)
    except Exception as e:
        print(f"Error checking mounts: {e}")
        return False

def write_smb_conf_file():
    samba_cluster = read_config("SAMBA_CLUSTERING")
    ceph_filesystem = get_ceph_file_system_name()
    prefix_path=read_config("PATH_TO_CONFIGURE")
    valid_user = "user1"
    global_section = f"""
[global]
        log level = 10

"""
    if samba_cluster:
        global_section += "        clustering = yes\n"
    smb_conf = global_section + f"""
[share1]
        vfs objects = ceph_new
        path = /
        valid users = root {valid_user}
        ceph_new: filesystem = {ceph_filesystem}
        ceph_new: user_id = {valid_user}
        ceph_new: config_file = /etc/ceph/ceph.conf
        browseable = yes
        path = /mnt/cephfs/volumes/smbshares/share1
        read only = no
 """
    os.makedirs(f"{prefix_path}/etc/", exist_ok=True)
    with open(f"{prefix_path}/etc/smb.conf", "w") as f:
        f.write(smb_conf)

def build_installsamba_script():
    configure_cmd = "./configure --enable-debug --without-ldb-lmdb --without-json  --without-ad-dc --enable-selftest"
    clustering = read_config("SAMBA_CLUSTERING")

    if clustering and clustering.strip().lower() in ["1", "yes", "true", "enabled"]:
        configure_cmd += " --with-cluster-support"
    configure_cmd +="; make clean; make all -j$(nproc); make install"

    # Write the configure string to script file
    with open("installsamba.sh", "w") as f:
        f.write("#!/bin/bash\n")
        f.write(configure_cmd + "\n")

def samba_node_init():
    samba_cluster = read_config("SAMBA_CLUSTERING")
    prefix_path=read_config("PATH_TO_CONFIGURE")
    start_ip = int(read_config("START_IP"))
    base_ip = read_config("BASE_IP")
    no_of_vms = int(read_config("NO_OF_VMS"))
    net_interace = read_config("NETWORK_INTERFACE")
    no_samba_vms = int(read_config("NO_OF_SAMBA_VMS"))
    samba_nodes = [
        f"{base_ip}{ip}"
        for ip in range(start_ip + no_of_vms - no_samba_vms, start_ip + no_of_vms)
    ]
    ceph_fuse_install()
    generating_ceph_key_ring()
    mount_cephfs()
    write_smb_conf_file()
    if samba_cluster:
        write_ctdb_conf_file()
        write_ip_to_node(prefix_path, samba_nodes)
        write_public_address(net_interace, base_ip, no_samba_vms,
                             start_ip + no_of_vms - no_samba_vms,
                             prefix_path)

def start_servers():
    samba_cluster = read_config("SAMBA_CLUSTERING")
    prefix_path=read_config("PATH_TO_CONFIGURE")
    if samba_cluster:
        run_cmd(f"{prefix_path}/sbin/ctdbd")
        time.sleep(10)
    run_cmd(f"{prefix_path}/sbin/smbd -D")
    time.sleep(10)

def main():
    samba_cluster = read_config("SAMBA_CLUSTERING")
    samba_pkg = read_config("SAMBA_PKG")
    ssh_user = read_config("SSH_USER")
    prefix_path=read_config("PATH_TO_CONFIGURE")
    start_ip = int(read_config("START_IP"))
    samba_path = read_config("SAMBA_PATH")
    ssh_passwd = read_config("SSH_PASS")
    net_interace = read_config("NETWORK_INTERFACE")
    base_ip = read_config("BASE_IP")
    no_of_vms = int(read_config("NO_OF_VMS"))

    head_node = f'{base_ip}{start_ip}'
    all_node = [f"{base_ip}{start_ip}" for i in range(no_of_vms)]
    samba_node_init()

    print(f"Ceph head Node: {head_node}")
    #print(f"Samba cluster Nodes: {samba_nodes}")

    if not is_mounted("commonfs"):
        run_cmd(f"mount -t virtiofs commonfs /mnt/commonfs/")
    time.sleep(5)
    if not os.path.exists(samba_pkg):
        print(f"❌ Samba path {samba_pkg} not found")
        return
    build_installsamba_script()

    run_cmd(f"bash installsamba.sh")

    if samba_cluster:
        print(f"\n⚙️ Setting up Samba + CTDB on {host}")

    for port in ["22", "4379", "4379", "445"]:
        check_add_firewall_port(port)

    run_cmd("systemctl restart firewalld")

    add_user("user1", "samba", prefix_path)

    if samba_cluster:
        for script in ["00.ctdb", "01.reclock", "05.system", "10.interface", "95.database"]:
            run_cmd(f"{PREFIX_PATH}/bin/ctdb event script enable legacy {script}")


    start_servers()
    

if __name__ == "__main__":
    main()

