from acl_helper import IPTableHelper
from log import get_logger

logger = get_logger(__name__)


class FilterRule:

    def __init__(self):
        self.rules = None

    async def apply_rule(self, rules):
        """
        Apply the given rule to the local firewall.

        Args:
            rule (str): The rule to be applied.

        Returns:
            None
        """
        logger.info('Applying rule to the local firewall')
        ipt = IPTableHelper()
        rule_src_ips = ipt.get_forward_chain_rule_src_ip()
        for line in rules:
            try:
                if line not in rule_src_ips:
                    logger.info(f'Adding rule: {line}')
                    ipt.block_src_dns_packet(line)
                else:
                    continue
            except Exception as e:
                logger.error(f"Error in apply_rule: {e}")