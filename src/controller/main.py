import asyncio

from transport import TransportServer
from config import Config
from issue_rules import IssueRules

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
    try:
        print("Issuing rules")
        await asyncio.sleep(15)
        await issue_rules.send_rules(rules)
    except Exception as e:
        print(f"Error in issue_rules_main: {e}")

async def main():
    test_rules = [["127.0.0.1", 3306], ["127.0.0.1", 3307], ["127.0.0.1", 3308]]
    # 使用 asyncio.gather 来并发运行两个协程
    server_task = asyncio.create_task(transport_server())
    rules_task = asyncio.create_task(issue_rules_main(test_rules))
    await asyncio.gather(
        server_task,
        rules_task,
    )


if __name__ == "__main__":

    # Start the SAVD controller
    asyncio.run(main())