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
        for line in rules:
            ipt.block_src_ip(line)