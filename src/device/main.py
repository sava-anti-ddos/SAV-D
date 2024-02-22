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

    logger.info(f"\n" + rendered_text)
    logger.info("Contact URL: www.sava-anti-ddos.com")


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
    logger.info(f"Mode of operation: {args.mode}")
    if args.mode == "sava":
        Config.is_sava = True
    elif args.mode == "anti-ddos-device":
        Config.is_sava = False
    else:
        parser.print_help()

    logger.info(f"Check device is sava:" + str(Config.is_sava))
    if Config.is_sava:
        # Create a packet sniffer instance
        logger.info("Starting packet sniffer")
        if Config.sniffer_interface_config == 0:
            logger.info(f"Sniffer at interface: " + Config.sniffer_interface)
            sniffer = PacketSniffer(Interface=Config.sniffer_interface,
                                    Config=Config)
        else:
            logger.info(f"Sniffer at all interfaces")
            sniffer = PacketSniffer(Config=Config)

        # SAVA device start sinffer
        sniffer.start()

    # Start the SAVA device
    logger.info("Starting SAVA device")
    asyncio.run(transport.start())
