import asyncio

from controller import TransportServer
from config import Config
from rule_issuance import IssueRules
from ip_blacklist import CSVHandler, BlacklistDatabase
from log import get_logger
from pyfiglet import Figlet

logger = get_logger(__name__)

# Create a server instance and all the devices will connect to this
server = TransportServer(Config.controller_ip, Config.controller_port)
issue_rules = IssueRules(server)
ip_blacklist = BlacklistDatabase(Config.db_path)


async def transport_server():
    """
    Function to start the transport server.
    """
    logger.info("Starting transport server")
    await server.start_server()


async def issue_rules_main(rules):
    """
    Main function to start the issue rules process.
    """
    logger.info("Starting issue rules main")
    # while True:
    #     try:
    #         await asyncio.sleep(15)
    #         await issue_rules.send_rules(rules)
    #     except Exception as e:
    #         logger.error(f"Error in issue_rules_main: {e}")


async def sniffer_csv_file_store2db_main():
    """
    Main function to start the CSV file store process.
    """
    logger.info("Starting csv file store main")
    while True:
        try:
            await asyncio.sleep(Config.task_time)
            csv_handler = CSVHandler(Config.readinfo_path,
                                     Config.writeinfo_path, Config.encoding)
            data = csv_handler.csv_read_and_move()
            if data:
                ip_blacklist.blacklist_update_batch(data)
        except Exception as e:
            logger.error(f"Error in sniffer_csv_file_store2db_main: {e}")


async def main():
    logger.info("Starting main")
    server_task = asyncio.create_task(transport_server())
    rules_task = asyncio.create_task(issue_rules_main([]))
    csv_store_task = asyncio.create_task(sniffer_csv_file_store2db_main())
    await asyncio.gather(
        server_task,
        rules_task,
        csv_store_task,
    )


def banner():
    """
    Print the banner for the device.

    Returns:
        None
    """
    figlet = Figlet(font='slant')
    rendered_text = figlet.renderText("SAV-D Controller")
    print(rendered_text)
    print("Contact URL: www.sava-anti-ddos.com")

    logger.info(f"\n" + rendered_text)
    logger.info("Contact URL: www.sava-anti-ddos.com")


if __name__ == "__main__":
    banner()
    # Start the SAVD controller
    asyncio.run(main())
