#!/usr/bin/env python3
import configparser
import os

CLUSTER_FILE = "cluster.txt"

def update_cluster_file(group, results):
    """
    Update or append entries in cluster.txt (INI format).
    
    :param group: Section name (e.g., "CENTOSBASE") or None/"GENERAL"
    :param results: dict of {key: value}
    """
    config = configparser.ConfigParser()
    config.optionxform = str  # preserve case sensitivity

    # Load existing cluster.txt
    if os.path.exists(CLUSTER_FILE):
        config.read(CLUSTER_FILE)
    else:
        config["GENERAL"] = {}

    # Default to GENERAL if group not defined
    section = group if group and group != "GENERAL" else "GENERAL"

    # Ensure section exists
    if section not in config:
        config[section] = {}

    # Update keys in the section
    for key, value in results.items():
        config[section][key] = value if value else "UNKNOWN"

    # Write back to cluster.txt
    with open(CLUSTER_FILE, "w") as f:
        config.write(f)

if __name__ == "__main__":
    # Example usage
    general_updates = {
        "SSH_USER": "root",
        "NO_OF_VMS": "5"
    }
    update_cluster_file("GENERAL", general_updates)

    vm_updates = {
        "192.168.122.176_GATEWAY": "192.168.122.1",
        "192.168.122.155_GATEWAY": "192.168.122.1"
    }
    update_cluster_file("CENTOSBASE", vm_updates)

    print("cluster.txt updated (test mode)")

