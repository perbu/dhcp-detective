# DHCP Detective

DHCP Detective is a tool for detecting rogue DHCP servers on a network. It listens for DHCP packets on a specified network interface and alerts via Slack if it detects a DHCP server other than the one specified by its MAC address.

## Features

- Listens for DHCP packets on a specified network interface
- Filters packets based on an allowed MAC address (presumably the legitimate DHCP server)
- Sends alerts to a Slack channel if a rogue DHCP server is detected
- Throttles alerts to once every 10 minutes to avoid flooding the Slack channel

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/perbu/dhcp-detective.git
   ```

2. Install the dependencies:
   ```
   go mod download
   ```

3. Create a `.env` file in the project root with your Slack bot token and channel:
   ```
   SLACK_TOKEN=your_slack_bot_token
   SLACK_CHANNEL=your_slack_channel_id
   ```

## Usage

Run the tool with the following command:

```
go run main.go -i interface -a allowed_mac_address
```

Replace `interface` with the network interface to listen on (e.g., `eth0`) and `allowed_mac_address` with the MAC address of the legitimate DHCP server.

For example:

```
go run main.go -i eth0 -a 00:11:22:33:44:55
```

The tool will start listening for DHCP packets on the specified interface. If it detects a DHCP packet from a server other than the one specified by the allowed MAC address, it will send an alert to the configured Slack channel.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

This project is licensed under the BSD 3-Clause License. See the [LICENSE.md](LICENSE.md) file for details.
