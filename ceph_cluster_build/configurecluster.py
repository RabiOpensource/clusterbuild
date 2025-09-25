#!/usr/bin/env python3
import configparser
import os

CLUSTER_FILE = "cluster.config"

def update_config(key, value, group:str = "GENERAL", file_path: str = CLUSTER_FILE):
    config = configparser.ConfigParser()
    config.optionxform = str  # keep case

    if os.path.exists(file_path):
        config.read(file_path)

    if "GENERAL" not in config:
        config["GENERAL"] = {}

    section = group if group in config else "GENERAL"
    if section not in config:
        config[section] = {}

    config[section][key] = value

    with open(file_path, "w") as f:
        config.write(f)

def read_config(key: str, group: str = "GENERAL", file_path: str = CLUSTER_FILE):
    config = configparser.ConfigParser()
    config.optionxform = str  # keep case

    if not os.path.exists(file_path):
        return None

    config.read(file_path)

    # Try given group first
    if group in config and key in config[group]:
        return config[group][key]

    # Fallback to GENERAL
    if "GENERAL" in config and key in config["GENERAL"]:
        return config["GENERAL"][key]

    return None

def remove_config(key: str, group: str = "GENERAL", file_path: str = CLUSTER_FILE):
    """
    Remove a key from the cluster.config file.
    If the section becomes empty, it is kept (not deleted).
    """
    config = configparser.ConfigParser()
    config.optionxform = str  # preserve case

    if not os.path.exists(file_path):
        print(f"⚠️ Config file {file_path} does not exist.")
        return False

    config.read(file_path)

    if group in config and key in config[group]:
        config.remove_option(group, key)

        with open(file_path, "w") as f:
            config.write(f)

        print(f"🗑️ Removed '{key}' from section [{group}] in {file_path}")
        return True
    else:
        print(f"⚠️ Key '{key}' not found in section [{group}] of {file_path}")
        return False

def update_gateway_to_config(config_file, ip, gateway):
    key = "GATEWAY"
    update_config(key, gateway)
    print(f"✅ Gateway {gateway} is updated in cluster config")

def update_base_ip_to_config(ipaddress: str) -> str:
    baseip = '.'.join(ipaddress.split('.')[:3]) + '.'
    update_config("BASE_IP", baseip)
