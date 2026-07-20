import nmap

scanner = nmap.PortScanner()

target = "127.0.0.1"

print("=" * 50)
print("NETWORK SCANNER")
print("=" * 50)

print(f"\nScanning Target : {target}\n")

scanner.scan(target, arguments="-F")

for host in scanner.all_hosts():

    print("-" * 50)
    print(f"Host : {host}")
    print(f"Status : {scanner[host].state()}")

    for protocol in scanner[host].all_protocols():

        print(f"\nProtocol : {protocol}")

        for port in sorted(scanner[host][protocol].keys()):

            state = scanner[host][protocol][port]["state"]

            print(f"Port {port:<5} --> {state}")

print("\nScan Completed Successfully!")
