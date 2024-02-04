import sys


def allow_http(port):
    sys.cmd("iptables -A INPUT -p tcp --dport %d -j ACCEPT" % port)
