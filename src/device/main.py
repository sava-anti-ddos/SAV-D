from monitor import PacketSniffer, PacketInformationUpload
from device import Transport
from config import initialize_config
import asyncio
from log import get_logger
from pyfiglet import Figlet
import argparse

logger = get_logger(__name__)

global Config

# Create a transport instance for sending data to the controller
global transport


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


def banner():
    """
    Print the banner for the device.

    Returns:
        None
    """
    figlet = Figlet(font='slant')
    rendered_text = figlet.renderText("SAVA Simulator")
    print(rendered_text)
    print("Contact URL: www.sava-anti-ddos.com")


if __name__ == "__main__":
    banner()

    # Configure the argument parser
    parser = argparse.ArgumentParser(description="SAVA Simulator Device")
    parser.add_argument("--M",
                        "--mode",
                        dest="mode",
                        help="mode of operation (sava or anti-ddos-device)",
                        required=True)
    parser.add_argument("-C",
                        "--config-file",
                        dest="file",
                        help="Config file for the device",
                        required=True)

    args = parser.parse_args()

    # Load the configuration from the file
    Config = initialize_config(args.file)
    transport = Transport(Config.controller_ip, Config.controller_port, Config)

    # Configure the device based on the mode
    if args.mode == "sava":
        Config.is_sava = True
    elif args.mode == "anti-ddos-device":
        Config.is_sava = False
    else:
        parser.print_help()

    # Start the connection to controller
    logger.info("Starting transport to controller")
    asyncio.run(transport.start())
    logger.info("Transport started")

    if Config.is_sava:
        # Create a packet sniffer instance
        logger.info("Starting packet sniffer")
        if Config.sniffer_interface_config == 0:
            sniffer = PacketSniffer(Interface=Config.sniffer_interface,
                                    Config=Config)
        else:
            sniffer = PacketSniffer(Config=Config)

        # SAVA device start sinffer
        logger.info("Sniffer at interface")
        sniffer.start()

        # Start the periodic upload
        logger.info("Starting periodic upload")
        asyncio.run(periodic_upload_main())
        logger.info("Periodic upload started")
