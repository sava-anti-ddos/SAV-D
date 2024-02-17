from log import get_logger

logger = get_logger(__name__)


class IssueRules:

    def __init__(self, transport=None):
        """
        Initializes an instance of the IssueRules class.

        Args:
            transport (TransportServer): The transport server used for sending control messages.
        """
        self.transport = transport

    async def send_rules(self, data):
        """
        Sends a list of rules to the transport server.

        Args:
            data (list): The list of rules to be sent.

        Raises:
            Exception: If an error occurs while sending the rules.
        """
        logger.info(f"Sending rules: {data}")
        try:
            # check data whether it is a list of rules
            if isinstance(data, list):
                # make a buffer to store a part of the data
                buffer = []
                # iterate over the data
                for rule in data:
                    # append the rule to the buffer
                    buffer.append(rule)
                    # if the buffer is full
                    if len(buffer) == 128:
                        # send the buffer to the transport server
                        await self.transport.send_control_message(buffer)
                        # clear the buffer
                        buffer.clear()
                # if the buffer is not empty
                if buffer:
                    # send the buffer to the transport server
                    await self.transport.send_control_message(buffer)
        except Exception as e:
            logger.error(f"Error sending rules: {e}")
