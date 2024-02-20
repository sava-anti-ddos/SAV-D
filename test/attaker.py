from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.volatile import RandShort
from scapy.sendrecv import sr1


def send_custom_dns_query(src_ip, dns_server, domain):
    """
    Sends a custom DNS query to a DNS server.

    Args:
        src_ip (str): The source IP address.
        dns_server (str): The DNS server IP address.
        domain (str): The domain to query.

    Returns:
        None
    """
    dns_query = DNS(rd=1, qd=DNSQR(qname=domain))

    udp = UDP(sport=RandShort(), dport=53)

    ip = IP(src=src_ip, dst=dns_server)

    response = sr1(ip / udp / dns_query, iface="eth0")
    if response:
        response.show()
    else:
        print("No response received.")


if __name__ == "__main__":
    send_custom_dns_query("172.20.", "8.8.8.8", "www.baidu.com")
