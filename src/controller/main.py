import asyncio

from controller import TransportServer
from config import Config
from rule_issuance import IssueRules

# Create a server instance and all the devices will connect to this
server = TransportServer(Config.controller_ip, Config.controller_port)
issue_rules = IssueRules(server)


async def transport_server():
    """
    Function to start the transport server.
    """
    await server.start_server()


async def issue_rules_main(rules):
    """
    Main function to start the issue rules process.
    """
    while True:
        try:
            print("Issuing rules")
            await asyncio.sleep(15)
            await issue_rules.send_rules(rules)
        except Exception as e:
            print(f"Error in issue_rules_main: {e}")


async def main():
    test_rules = [['192.168.0.1', '192.168.0.2'], ['192.168.0.3', '192.168.0.4'], ['192.168.0.5', '192.168.0.6']]
    # asyncio.gather run two task
    server_task = asyncio.create_task(transport_server())
    rules_task = asyncio.create_task(issue_rules_main(test_rules))
    await asyncio.gather(
        server_task,
        rules_task,
    )


if __name__ == "__main__":

    # Start the SAVD controller
    asyncio.run(main())
