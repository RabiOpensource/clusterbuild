#/usr/local/samba/bin/smbcontrol ctdb shutdown
sleep 1
#/usr/local/samba/bin/smbcontrol smbd shutdown
sleep 1
ps -ea | grep smbd

#/usr/local/samba/sbin/ctdbd
sleep 1
/usr/local/samba/sbin/smbd
sleep 1
ps -ea | grep smbd
ps -ea | grep ctdb
