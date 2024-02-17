from log import get_logger

logger = get_logger(__name__)


class Information:
    """
    This class represents information data.

    Attributes:
        data (list): A list of information data.
    """

    data = ['sip', 'sport', 'dport']

    def __init__(self, set_info):
        self.data = set_info


class RuleGenerator:
    """
    A class that generates rules based on specified information from a database.
    """

    def __init__(self, db_name):
        """
        Initialize the RuleGenerator object.

        Args:
            db_name (str): The name of the database.

        Returns:
            None
        """
        self.db = db_name

        self.connection = None
        self.info = None

    def set_info(self, information):
        """
        Set the information for the object.

        Args:
            information: The information to be set.

        Returns:
            None
        """
        logger.info("RuleGenerator set info: " + information)
        self.info = information

    def launch(self):
        """
        Opens a connection to the database and prints a message.
        """
        self.connection = self.db.get_connection()
        logger.info("Open a connection to db")

    def fetch_data(self):
        """
        Fetches specific info from the Blacklist table.

        Returns:
            list: A list of tuples containing the fetched data.
        """
        logger.info("Fetch data from the blacklist table")
        try:
            cursor = self.connection.cursor()
            query = f"SELECT {', '.join(self.info)} FROM Blacklist"
            cursor.execute(query)
            data = cursor.fetchall()
        finally:
            return data

    def generate_rules(self):
        """
        Generates a list of rules based on the specified info.

        Returns:
            list: A list of rules generated from the fetched data.
        """
        logger.info("Generate rules")
        data = self.fetch_data()
        rules = []
        for row in data:
            rule = ' '.join(str(item) for item in row)
            rules.append(rule)
        return rules

    def shutdown(self):
        """
        Closes the connection and releases the database connection.
        """
        self.conn = None
        self.db.release_connection(self.connection)
        logger.info("Connection closed")
