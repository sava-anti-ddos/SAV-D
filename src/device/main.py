from monitor import PacketSniffer, PacketInformationUpload
from device import Transport
from config import Config
import asyncio
from log import get_logger

logger = get_logger(__name__)

# Create a transport instance for sending data to the controller
transport = Transport(Config.controller_ip, Config.controller_port)


async def periodic_upload(packet_info_upload):
    """
    Periodically gets data from local and uploads it using the given PacketInformationUpload instance.

    Args:
        packet_info_upload (PacketInformationUpload): The instance used to upload packet information.

    Returns:
        None
    """
    while True:
        logger.info("Uploading sniffer data to controller")
        await packet_info_upload.get_data_from_local()
        logger.info("Data uploaded to controller")

        logger.info("Sleeping for " + str(Config.sniffer_upload_interval) +
                    " seconds")
        await asyncio.sleep(Config.sniffer_upload_interval)


async def periodic_upload_main():
    """
    Main function to start the periodic upload process.

    Returns:
        None
    """
    # Create a packet information upload instance
    upload = PacketInformationUpload(transport)
    await periodic_upload(upload)


if __name__ == "__main__":
    # # Create a packet sniffer instance
    logger.info("Starting packet sniffer")
    sniffer = PacketSniffer(Config.sniffer_interface)
    sniffer.start()

    logger.info("Sniffer at interface: " + Config.sniffer_interface)

    # Start the connection to controller
    logger.info("Starting transport to controller")
    asyncio.run(transport.start())
    logger.info("Transport started")

    # # Start the periodic upload
    logger.info("Starting periodic upload")
    asyncio.run(periodic_upload_main())
    logger.info("Periodic upload started")
