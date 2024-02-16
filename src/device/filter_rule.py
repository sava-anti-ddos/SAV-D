from acl_helper import IPTableHelper


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
        ipt = IPTableHelper()
        for line in rules:
            ipt.block_src_dst_ip(line[0], line[1])
