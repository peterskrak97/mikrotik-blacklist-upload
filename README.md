# Mikrotik BlackList Automation Tool

This is a simple automation tool which takes IP blacklist from Cisco Talos and uploads it into a Mikrotik (running RouterOS 7.X) device using REST API.

All IP addresses from Cisco Talos's IP blacklist will be uploaded under one address-list object, so you could then use this object in a firewall rule to protect your network from communicating with those IP addresses.

# Run

Build the binary using `go build .` and run the binary, or run the program with `go run main.go`.

After launching the program, you will be prompted to enter:
* `Username`: Mikrotik's admin username
* `Password`: Mikrotik's admin password
* `IP Address`: The IPv4 address of the Mikrotik device

Note: this tool currently only works for IPv4.

