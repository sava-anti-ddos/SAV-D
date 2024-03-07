from linuxnet.iptables import IptablesPacketFilterTable, ChainRule, Targets, PacketMatch, TcpMatch, UdpMatch
from log import get_logger

logger = get_logger(__name__)


class IPTableHelper:
    """
    Helper class for managing IPTables rules.

    Attributes:
        table (IptablesPacketFilterTable): The IPTables packet filter table.
        input_chain (Chain): The INPUT chain of the packet filter table.

    Methods:
        block_src_ip: Blocks packets with a specific source IP address.
        block_dst_ip: Blocks packets with a specific destination IP address.
        block_src_dst_ip: Blocks packets with a specific source and destination IP address.
        block_tcp_packet: Blocks TCP packets based on various criteria.
        block_udp_packet: Blocks UDP packets based on various criteria.
        flush: Flushes the INPUT chain, removing all rules.
    """

    def __init__(self):
        self.table = IptablesPacketFilterTable('filter')
        self.table.read_system_config()
        self.input_chain = self.table.get_chain('INPUT')
        self.forward_chain = self.table.get_chain('FORWARD')

    def block_src_ip(self, src_ip):
        """
        Blocks packets with a specific source IP address.

        Args:
            src_ip (str): The source IP address to block.
        """
        try:
            match_src_ip = PacketMatch().source_address().equals(src_ip)
            input_chain_rule = ChainRule(match=match_src_ip,
                                         target=Targets.DROP)
            logger.debug(input_chain_rule.to_iptables_args())
            self.input_chain.append_rule(input_chain_rule)

            forward_chain_rule = ChainRule(match=match_src_ip,
                                           target=Targets.DROP)
            logger.debug(forward_chain_rule.to_iptables_args())
            self.forward_chain.append_rule(forward_chain_rule)
        except Exception as e:
            logger.error(f"Error in block_src_ip: {e}")

    def block_dst_ip(self, dst_ip):
        """
        Blocks packets with a specific destination IP address.

        Args:
            dst_ip (str): The destination IP address to block.
        """
        try:
            match_dst_ip = PacketMatch().dest_address().equals(dst_ip)

            input_chain_rule = ChainRule(match=match_dst_ip,
                                         target=Targets.DROP)
            logger.debug(input_chain_rule.to_iptables_args())
            self.input_chain.append_rule(input_chain_rule)

            forward_chain_rule = ChainRule(match=match_dst_ip,
                                           target=Targets.DROP)
            logger.debug(forward_chain_rule.to_iptables_args())
            self.forward_chain.append_rule(forward_chain_rule)
        except Exception as e:
            logger.error(f"Error in block_dst_ip: {e}")

    def block_src_dst_ip(self, src_ip, dst_ip):
        """
        Blocks packets with a specific source and destination IP address.

        Args:
            src_ip (str): The source IP address to block.
            dst_ip (str): The destination IP address to block.
        """
        try:
            match_src_dst_ip = PacketMatch().source_address().equals(src_ip)
            match_src_dst_ip.dest_address().equals(dst_ip)

            input_chain_rule = ChainRule(match=match_src_dst_ip,
                                         target=Targets.DROP)
            logger.debug(input_chain_rule.to_iptables_args())
            self.input_chain.append_rule(input_chain_rule)

            forward_chain_rule = ChainRule(match=match_src_dst_ip,
                                           target=Targets.DROP)
            logger.debug(forward_chain_rule.to_iptables_args())
            self.forward_chain.append_rule(forward_chain_rule)
        except Exception as e:
            logger.error(f"Error in block_src_dst_ip: {e}")

    def block_tcp_packet(self,
                         src_port=None,
                         dst_port=None,
                         tcp_flag=None,
                         tcp_option_number=None):
        """
        Blocks TCP packets based on various criteria.

        Args:
            src_port (int, optional): The source port to match. Defaults to None.
            dst_port (int, optional): The destination port to match. Defaults to None.
            tcp_flag (str, optional): The TCP flag to match. Defaults to None.
            tcp_option_number (int, optional): The TCP option number to match. Defaults to None.
        """
        try:
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

            input_chain_rule = ChainRule(
                match_list=[match_tcp, match_tcp_packet], target=Targets.DROP)

            logger.debug(input_chain_rule.to_iptables_args())
            self.input_chain.append_rule(input_chain_rule)

            forward_chain_rule = ChainRule(
                match_list=[match_tcp, match_tcp_packet], target=Targets.DROP)
            logger.debug(forward_chain_rule.to_iptables_args())
            self.forward_chain.append_rule(forward_chain_rule)
        except Exception as e:
            logger.error(f"Error in block_tcp_packet: {e}")

    def block_udp_packet(self, src_port=None, dest_port=None):
        """
        Blocks UDP packets based on various criteria.

        Args:
            src_port (int, optional): The source port to match. Defaults to None.
            dest_port (int, optional): The destination port to match. Defaults to None.
        """
        try:
            match_udp = PacketMatch().protocol().equals('udp')
            match_udp_packet = UdpMatch()
            if src_port:
                match_udp_packet.source_port().equals(src_port)
            if dest_port:
                match_udp_packet.dest_port().equals(dest_port)

            input_chain_rule = ChainRule(
                match_list=[match_udp, match_udp_packet], target=Targets.DROP)
            logger.debug(input_chain_rule.to_iptables_args())
            self.input_chain.append_rule(input_chain_rule)

            forward_chain_rule = ChainRule(
                match_list=[match_udp, match_udp_packet], target=Targets.DROP)
            logger.debug(forward_chain_rule.to_iptables_args())
            self.forward_chain.append_rule(forward_chain_rule)
        except Exception as e:
            logger.error(f"Error in block_udp_packet: {e}")

    def block_src_dns_packet(self, src_ip=None, dst_port=None):
        """
        Blocks DNS packets based on various criteria.

        Args:
            src_ip (str, optional): The source IP address to match. Defaults to None.
            dst_port (int, optional): The destination port to match. Defaults to None.
        """
        try:
            m = PacketMatch().protocol().equals('udp')
            m.source_address().equals(src_ip)

            match_dns_packet = UdpMatch()

            if dst_port:
                match_dns_packet.dest_port().equals(dst_port)

            input_chain_rule = ChainRule(match_list=[m, match_dns_packet],
                                         target=Targets.DROP)
            print(input_chain_rule.to_iptables_args())
            logger.debug(input_chain_rule.to_iptables_args())
            self.input_chain.append_rule(input_chain_rule)

            forward_chain_rule = ChainRule(match_list=[m, match_dns_packet],
                                           target=Targets.DROP)
            logger.debug(forward_chain_rule.to_iptables_args())
            self.forward_chain.append_rule(forward_chain_rule)
        except Exception as e:
            logger.error(f"Error in block_src_dns_packet: {e}")

    def get_forward_chain_rule_src_ip(self):
        src_ip = []
        rules = self.forward_chain.get_rules()
        for rule in rules:
            rule_str = rule.to_iptables_args()
            src_ip.append(rule_str[3])
        return src_ip

    def flush(self):
        """
        Flushes the INPUT chain, removing all rules.
        """
        try:
            logger.debug("flush chain, remove all rules")
            self.input_chain.flush()
            self.forward_chain.flush()
        except Exception as e:
            logger.error(f"Error in flush: {e}")


if __name__ == '__main__':
    iptable = IPTableHelper()
    iptable.block_src_dns_packet("40.40.10.10", 53)
    print(iptable.get_forward_chain_rule_src_ip())
    iptable.flush()
