import asyncio
from config import Config
from ip_blacklist import CSVHandler
from log import get_logger
from pyfiglet import Figlet

logger = get_logger(__name__)

from globals import server, issue_rules, db, rule_generator


async def transport_server():
    """
    Function to start the transport server.
    """
    logger.info("Starting transport server")
    await server.start_server()


async def issue_rules_from_blacklist_main():
    """
    Main function to start the issue rules process.
    """
    logger.info("Starting issue rules main")

    while True:
        try:
            await asyncio.sleep(15)
            logger.info("generating rules from blacklist")
            rule_generator.set_info()
            rule_generator.launch()
            data = rule_generator.generate_rules("IPBlacklist")
            logger.debug("blacklist rules extract")
            await issue_rules.send_rules(data)
            logger.debug(data)
            rule_generator.shutdown()
        except Exception as e:
            logger.error(f"Error in issue_rules_main: {e}")


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
                db.sniffer_info_update_batch(data)
        except Exception as e:
            logger.error(f"Error in sniffer_csv_file_store2db_main: {e}")


async def main():
    logger.info("Starting main")
    server_task = asyncio.create_task(transport_server())
    rules_task = asyncio.create_task(issue_rules_from_blacklist_main())
    csv_store_task = asyncio.create_task(sniffer_csv_file_store2db_main())
    await asyncio.gather(
        server_task,
        rules_task,
        csv_store_task,
    )


def db_init():
    # db initialization
    db.create_table()
    # lab blacklist ip
    # db.ip_blacklist_update('40.40.10.10')


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
    db_init()
    # Start the SAVD controller
    asyncio.run(main())
