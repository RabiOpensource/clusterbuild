#!/bin/bash
ORIGINAL_VM="cephnode1_ori"
HOST_BASE_NAME="cephnode"
NO_OF_VM="1"
BASE_IP="192.168.122."
START_IP="180"
NO_OF_DEVICE="1"

VIRT_CLONE="/usr/bin/virt-clone"

check_vm_exists() {
    # quiet grep; return 0 if found, 1 if not
    if virsh list --all | grep -wq "$1"; then
        echo "vm found"
        return 0    # success -> VM exists
    else
        echo "vm not found"
        return 1    # failure -> VM does NOT exist
    fi
}
check_vm_status() {
	echo $(virsh domstate $1 2>/dev/null)
}
stop_vm() {
	status=$(check_vm_status "$1")

	case "$status" in
	    "running")
		echo "${1} VM is running. Shutting it down"
		virsh shutdown $1
		sleep 5
		;;
	    "shut off"|"paused")
		echo "${1} VM is not running"
		;;
	    "crashed")
		echo "❌ VM has crashed"
		;;
	    *)
		echo "ℹ️  Unknown VM state: $status"
		;;
	esac

}
start_vm(){
	status=$(check_vm_status "$1")

	case "$status" in
	    "running")
		echo "✅ VM is running"
		;;
	    "shut off"|"paused")
		echo "⚠️  VM is not running, so starting your vm $1"
		virsh start $1
		sleep 20
		;;
	    "crashed")
		echo "❌ VM has crashed"
		;;
	    *)
		echo "ℹ️  Unknown VM state: $status"
		;;
	esac
}

clean_vm() {
	echo "<<<<<<<<<<<<<< Cleaning VM for you  >>>>>>>>>>>>>>>>>>"
	for (( i=$((START_IP)); i < $((START_IP + NO_OF_VM )); i++ ))
	do

		HOST_NAME="${HOST_BASE_NAME}${i}"
		echo "########################## $(virsh domstate ${HOST_NAME})"
		if [[ $(virsh domstate ${HOST_NAME}) == "running" ]]; then
			echo "comming here to shutdown vm"
			virsh shutdown ${HOST_NAME}
			echo "Going for sleep for 5 sec"
			sleep 5
		fi
		/usr/bin/virsh undefine ${HOST_NAME} --remove-all-storage
	done
	HOST_NAME="${HOST_BASE_NAME}${START_IP}"
	for (( j=0; j < $NO_OF_DEVICE; j++))
	do
		DISKNAME="/var/lib/libvirt/images/${HOST_NAME}_disk${j}.qcow2"
		rm -rf ${DISKNAME}
	done

}

create_ip_for_host() {
	echo "nmcli connection modify enp1s0 ipv4.addresses \"${1}/24\" ipv4.gateway \"192.168.122.1\" " > ipconfigure.sh
}

assign_hostname_ip_vm(){

	if [[  $(grep -w ${1} /etc/hosts) == "" ]]; then
		echo  "${2}			${1}" >> /etc/hosts
	fi
	if [[ "$(check_vm_status ${1})" != "running" ]]; then
		start_vm ${1}
	fi
	#as the vm clone and started so initial vm ip is 192.168.122.160
	if [[ "$(check_vm_status ${1})" == "running" ]]; then
#		sshpass -p samba ssh root@192.168.122.160 "$(nmcli connection modify enp1s0 ipv4.addresses "${2}/24" ipv4.gateway "192.168.122.1" )"
		sshpass -p samba ssh root@192.168.122.160 "hostnamectl hostname ${1}"
		sshpass -p samba scp ipconfigure.sh root@192.168.122.160:/root/.
		sshpass -p samba ssh  root@192.168.122.160 "bash ipconfigure.sh"
				
		stop_vm ${1}
		start_vm ${1}
		sshpass -p samba scp generate_ssh_key.sh root@${2}:/root/.
		sshpass -p samba ssh  root@${2} "bash generate_ssh_key.sh"
		sshpass -p samba scp  root@${2}:/root/.ssh/id_rsa.pub ${1}_id_rsa.pub
		sleep 2
		stop_vm ${1}

	else
		echo "This VM ${1} is not up make it up before password less communication"
		exit 1
	fi

}

clone_vm() {
	for (( i=$((START_IP)); i < $((START_IP + NO_OF_VM )); i++ ))
	do
		HOST_NAME="${HOST_BASE_NAME}${i}"
		IP="${BASE_IP}${i}"
		if [[ "$(check_vm_exits ${HOST_NAME})" == 1 ]]; then
			continue
		fi

		echo "############## Cloning vm for ${HOST_NAME} #######################"
		${VIRT_CLONE} --original ${ORIGINAL_VM} --name ${HOST_NAME} \
				--auto-clone --file "/var/lib/libvirt/images/${HOST_NAME}.qcow2"

	        if [[ $? -ne 0 ]]; then
            		echo "Error: virt-clone failed for ${HOST_NAME}. Exiting..."
            		exit 1
        	fi	

		create_ip_for_host ${IP}
		assign_hostname_ip_vm ${HOST_NAME} ${IP}

		#As we are making first node as ceph node and we are adding disk to it
		if [[ "${i}" == ${START_IP} ]]; then
			echo ""
			echo ""
			echo "Adding a disk to host ${HOST_NAME}"
			if check_vm_exists "$HOST_NAME"; then
				for (( j=0; j < $NO_OF_DEVICE; j++))
				do
					DISKNAME="/var/lib/libvirt/images/${HOST_NAME}_disk${j}.qcow2"
					qemu-img create -f qcow2 "${DISKNAME}" 5G
					virsh attach-disk ${HOST_NAME} ${DISKNAME} vdb --cache=none --subdriver=qcow2 --persistent
					echo "DISK ${HOST_NAME}_disk${j}.qcow2 is added to host ${HOST_NAME}"
				done
			fi
		fi
	done
}
start_ceph_vm() {

	HOST_NAME="${HOST_BASE_NAME}${START_IP}"
	echo ""
	echo ""
	echo "Starting ceph VM ${HOST_NAME}"
	start_vm ${HOST_NAME}
	sleep 10
}
start_samba_vm() {
	for (( i=$((START_IP + 1)); i < $((START_IP + NO_OF_VM )); i++ ))
	do
		HOST_NAME="${HOST_BASE_NAME}${i}"
		start_vm ${HOST_NAME}
	done
}

start_ctdb_in_samba_vm() {
	echo " <<<<<<<<<<<<<<<<<<<<<<<< Starting CTDB IN  VM >>>>>>>>>>>>>>>>>>>>>>>>>"
}
start_ceph_cluster() {
	echo "<<<<<<<<<<<<<< Starting Ceph Cluster Setup on Head Node >>>>>>>>>>>>>>"

	HOST_NAME="${HOST_BASE_NAME}${START_IP}"

	# Check VM status first
	if [[ "$(check_vm_status ${HOST_NAME})" != "running" ]]; then
		echo "Head node ${HOST_NAME} is not running. Starting it..."
		start_vm "${HOST_NAME}"
		echo "Waiting 10 seconds for ${HOST_NAME} to boot..."
		sleep 10
	else
		echo "Head node ${HOST_NAME} is already running."
	fi
}

start_samba_cluster() {
	echo "<<<<<<<<<<<<<< Starting Samba Cluster Setup >>>>>>>>>>>>>>"

	for (( i=$((START_IP+1)); i < $((START_IP + NO_OF_VM)); i++ ))
	do
		HOST_NAME="${HOST_BASE_NAME}${i}"
		start_vm ${HOST_NAME}

		echo "---- Setting up Samba + CTDB on ${HOST_NAME} ----"
		ssh ${HOST_NAME} "
			sudo systemctl enable smb ctdb
			sudo systemctl start smb ctdb
			sudo ctdb status
		"
	done
}
<< 'SETUP_SSH_KEY'
 it is mandatory to call for all node and all node should share their key 
with host and amonth each oher
SETUP_SSH_KEY

setup_ssh_key_with_node() {
	echo "<<<<<<<<<<<<<< Generating ssh for all nodes  >>>>>>>>>>>>>>"

}


for arg in "$@"; do

	if [[ "$arg" == "--cleanup" ]]; then
		clean_vm
	fi

	if [[ "$arg" == "--clone" ]]; then
		clone_vm
	fi

	if [[ "$arg" == "--start-ceph-cluster" ]]; then
		start_ceph_vm
		start_samba_vm
		echo "Start ceph cluster"
	fi
done
