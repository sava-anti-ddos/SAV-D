from filter_rule import FilterRule
from log import get_logger

logger = get_logger(__name__)


class ReceiveRule:
    """
    A class that represents a rule receiver.
    """

    def __init__(self):
        self.rules = None

    async def receive_rule(self, data):
        """
        Receive the rule from the controller.

        Args:
            data (list): The rule data to be received.

        Raises:
            ValueError: If the rule data is not a list.

        Returns:
            None
        """
        logger.info('Receiving rule from the controller')
        try:
            # make sure that data is a list
            if isinstance(data, list):
                self.rules = data
                # apply the rule
                logger.info('Applying rule to the filter rule module')
                fr = FilterRule()
                await fr.apply_rule(self.rules)
            else:
                raise ValueError("Invalid rule data")
        except Exception as e:
            logger.error(f"Error receiving rule: {e}")
