from flask import Flask, render_template, request, send_file
import nmap

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():

    target = ""
    ports = []

    if request.method == "POST":

        target = request.form["target"]

        scanner = nmap.PortScanner()
        scanner.scan(target, arguments="-F")

        for host in scanner.all_hosts():
            for protocol in scanner[host].all_protocols():
                for port in sorted(scanner[host][protocol].keys()):
                    state = scanner[host][protocol][port]["state"]

                    ports.append({
                        "port": port,
                        "state": state
                    })

    return render_template(
        "index.html",
        target=target,
        ports=ports,
        total_ports=len(ports)
    )


@app.route("/download")
def download():

    target = "127.0.0.1"

    scanner = nmap.PortScanner()
    scanner.scan(target, arguments="-F")

    with open("scan_report.txt", "w") as f:

        f.write("NETWORK SCAN REPORT\n")
        f.write("=============================\n\n")
        f.write(f"Target: {target}\n\n")

        for host in scanner.all_hosts():

            f.write(f"Host: {host}\n")
            f.write(f"Status: {scanner[host].state()}\n\n")

            for protocol in scanner[host].all_protocols():

                f.write(f"Protocol: {protocol}\n")

                for port in sorted(scanner[host][protocol].keys()):

                    state = scanner[host][protocol][port]["state"]
                    f.write(f"Port {port}: {state}\n")

                f.write("\n")

    return send_file("scan_report.txt", as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
