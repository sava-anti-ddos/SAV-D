from linuxnet.iptables import IptablesPacketFilterTable, ChainRule, Targets, PacketMatch, TcpMatch, UdpMatch


class IPTableHelper:

    def __init__(self):
        self.table = IptablesPacketFilterTable('filter')
        self.table.read_system_config()
        self.input_chain = self.table.get_chain('INPUT')

    def block_src_ip(self, src_ip):
        match_src_ip = PacketMatch().source_address().equals(src_ip)
        rule = ChainRule(match=match_src_ip, target=Targets.DROP)
        self.input_chain.append_rule(rule)

    def block_dst_ip(self, dst_ip):
        match_dst_ip = PacketMatch().dest_address().equals(dst_ip)
        rule = ChainRule(match=match_dst_ip, target=Targets.DROP)
        self.input_chain.append_rule(rule)

    def block_tcp_packet(self,
                         src_port=None,
                         dst_port=None,
                         tcp_flag=None,
                         tcp_option_number=None):
        match_tcp = PacketMatch().protocol().equals('tcp')
        match_tcp_packet = TcpMatch()
        if src_port:
            match_tcp_packet.source_port().equals(src_port)
        if dst_port:
            match_tcp_packet.dest_port().equals(dst_port)
        if tcp_flag:
            match_tcp_packet.tcp_flags().equals(tcp_flag)
        if tcp_option_number:
            match_tcp_packet.tcp_option().equals(tcp_option_number)

        rule = ChainRule(match_list=[match_tcp, match_tcp_packet],
                         target=Targets.DROP)
        self.input_chain.append_rule(rule)

    def block_udp_packet(self, src_port=None, dest_port=None):
        match_udp = PacketMatch().protocol().equals('udp')
        match_udp_packet = UdpMatch()
        if src_port:
            match_udp_packet.source_port().equals(src_port)

        if dest_port:
            match_udp_packet.dest_port().equals(dest_port)

        rule = ChainRule(match_list=[match_udp, match_udp_packet],
                         target=Targets.DROP)
        self.input_chain.append_rule(rule)

    def flush(self):
        self.input_chain.flush()


if __name__ == '__main__':
    iptable = IPTableHelper()
    iptable.flush()
