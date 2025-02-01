iptables -A INPUT -s 192.168.220.0/24 -p tcp -m multiport --dports 3306,5432,27017 -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports 3306,5432,27017 -j DROP

