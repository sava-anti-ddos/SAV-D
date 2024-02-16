from filter_rule import FilterRule


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
        try:
            # make sure that data is a list
            if isinstance(data, list):
                self.rules = data
                # apply the rule
                fr = FilterRule()
                await fr.apply_rule(self.rules)
                print(f"Received rules: {self.rules}")
            else:
                raise ValueError("Invalid rule data")
        except Exception as e:
            print(f"Error receiving rule: {e}")
