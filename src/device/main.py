from monitor import PacketSniffer, PacketInformationUpload
from device import Transport
from config import Config
import asyncio

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
        await packet_info_upload.get_data_from_local()
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
    sniffer = PacketSniffer(Config.sniffer_interface)
    sniffer.start()

    # Start the connection to controller
    asyncio.run(transport.start())

    # # Start the periodic upload
    asyncio.run(periodic_upload_main())
