Okay, let's dive deep into Module 4: Threat Hunting Tools and Techniques (Part 1: Network). This module will be heavily hands-on, focusing on practical skills using industry-standard tools.

**Module 4: Threat Hunting Tools and Techniques (Part 1: Network)**

**Module Objective:** Learn to leverage network-based tools and techniques for detecting malicious activity.

**Module Duration:** Approximately 8 hours (including lecture, hands-on labs, and exercises).

**Prerequisites:**

*   Basic understanding of TCP/IP networking.
*   Familiarity with the Linux command line.
*   A virtual machine with Kali Linux installed (or another security-focused distribution).
*   Basic understanding of packet capture and analysis principles.

**Module Structure:**

1.  **Introduction to Network Threat Hunting (30 minutes)**
2.  **Network Intrusion Detection Systems (NIDS) with Snort/Suricata (2 hours)**
3.  **Network Traffic Analysis (NTA) with Wireshark (2 hours)**
4.  **Network Traffic Analysis (NTA) with Zeek (Bro) (2 hours)**
5.  **NetFlow Analysis (1 hour)**
6.  **DNS Analysis (1 hour)**
7.  **Module Project/Exercise: Network Forensics Challenge (30 minutes)**

---

**1. Introduction to Network Threat Hunting (30 minutes)**

*   **What is Network Threat Hunting?**

    *   Proactive searching for malicious activity on a network that has evaded existing security controls.
    *   Focus on anomalies, unusual patterns, and indicators of compromise (IoCs) in network traffic.
    *   Driven by hypotheses, threat intelligence, and a deep understanding of network protocols and behavior.

*   **Why Network Threat Hunting?**

    *   Traditional security tools are reactive (signature-based).
    *   Advanced attackers use stealthy techniques to bypass defenses.
    *   Network traffic provides a rich source of data for detecting malicious activity.

*   **Key Data Sources for Network Threat Hunting:**

    *   Packet captures (PCAP files)
    *   Network flow data (NetFlow, sFlow, IPFIX)
    *   Network intrusion detection system (NIDS) alerts
    *   DNS logs
    *   Proxy logs

*   **Common Network Threat Hunting Scenarios:**

    *   Detecting command-and-control (C&C) traffic.
    *   Identifying data exfiltration.
    *   Finding lateral movement within the network.
    *   Detecting malware infections.
    *   Identifying rogue devices.

---

**2. Network Intrusion Detection Systems (NIDS) with Snort/Suricata (2 hours)**

*   **Introduction to NIDS:**

    *   Monitors network traffic for malicious activity based on predefined rules.
    *   Generates alerts when suspicious traffic is detected.
    *   Can be signature-based or anomaly-based.
    *   Examples: Snort, Suricata.

*   **Snort vs. Suricata:**

    *   Similar functionality, but Suricata offers better performance and multi-threading support.
    *   Both use similar rule syntax.

*   **Installing Snort/Suricata (Kali Linux):**

    *   **Snort:** `sudo apt update && sudo apt install snort`
    *   **Suricata:** `sudo apt update && sudo apt install suricata`

*   **Configuring Snort/Suricata:**

    *   Configuration files are located in `/etc/snort` or `/etc/suricata`.
    *   Key configuration options:
        *   `HOME_NET`: Defines the network(s) to be monitored.
        *   `EXTERNAL_NET`: Defines the external network (usually the internet).
        *   `RULE_PATH`: Specifies the directory containing the Snort/Suricata rules.
        *   `INTERFACE`: Specifies the network interface to monitor.

*   **Snort/Suricata Rule Syntax:**

    *   A Snort/Suricata rule consists of a header and options.
    *   **Header:** `action protocol src_ip src_port -> dest_ip dest_port (options)`
        *   `action`: What to do when the rule matches (e.g., `alert`, `log`, `pass`, `drop`, `reject`).
        *   `protocol`: Network protocol (e.g., `tcp`, `udp`, `icmp`, `ip`).
        *   `src_ip`: Source IP address.
        *   `src_port`: Source port.
        *   `->`: Direction of traffic.
        *   `dest_ip`: Destination IP address.
        *   `dest_port`: Destination port.
    *   **Options:** Keywords that specify additional criteria for matching traffic.
        *   `msg`: Alert message.
        *   `content`: Matches specific content within the packet.
        *   `sid`: Snort ID (unique identifier for the rule).
        *   `rev`: Revision number.
        *   `classtype`: Classifies the type of attack.
        *   `flags`: TCP flags.
        *   `dsize`: Packet data size.
        *   `ttl`: Time to live

*   **Writing Snort/Suricata Rules (Examples):**

    *   **Detecting ICMP traffic:**

        ```
        alert icmp any any -> any any (msg:"ICMP Traffic Detected"; sid:1000001; rev:1;)
        ```

    *   **Detecting HTTP traffic containing the string "malware.exe":**

        ```
        alert tcp any any -> any 80 (msg:"HTTP Traffic with malware.exe"; content:"malware.exe"; http_uri; sid:1000002; rev:1;)
        ```

    *   **Detecting a specific User-Agent:**

        ```
        alert tcp any any -> any 80 (msg:"Suspicious User-Agent"; content:"BadBot/1.0"; http_header; sid:1000003; rev:1;)
        ```

*   **Testing Snort/Suricata Rules:**

    1.  Create a rule file (e.g., `local.rules`) in the rules directory (`/etc/snort/rules` or `/etc/suricata/rules`).
    2.  Add your rules to the file.
    3.  Run Snort/Suricata in test mode:

        *   **Snort:** `sudo snort -c /etc/snort/snort.conf -T -i eth0` (replace `eth0` with your network interface)
        *   **Suricata:** `sudo suricata -c /etc/suricata/suricata.yaml -T -i eth0`

    4.  Generate traffic that matches your rule (e.g., using `curl` or `ping`).
    5.  Verify that Snort/Suricata generates an alert.

*   **Running Snort/Suricata in Production Mode:**

    *   **Snort:** `sudo snort -c /etc/snort/snort.conf -i eth0 -A console` (outputs alerts to the console)
    *   **Suricata:** `sudo suricata -c /etc/suricata/suricata.yaml -i eth0` (logs alerts to a file)

*   **Analyzing Snort/Suricata Alerts:**

    *   Alerts are typically logged to a file (e.g., `/var/log/snort/alert` or `/var/log/suricata/fast.log`).
    *   Alerts contain information about the event, including:
        *   Timestamp
        *   Source and destination IP addresses and ports
        *   Rule ID
        *   Alert message
        *   Packet data (optional)
    *   Use tools like `grep`, `awk`, or specialized SIEM solutions to analyze alerts.

*   **Hands-on Exercise:**

    1.  Install Snort/Suricata on your Kali Linux VM.
    2.  Create a custom rule to detect a specific type of traffic (e.g., traffic to a known malicious IP address).
    3.  Test the rule by generating the traffic and verifying that Snort/Suricata generates an alert.
    4.  Analyze the alert and extract relevant information.

---

**3. Network Traffic Analysis (NTA) with Wireshark (2 hours)**

*   **Introduction to Wireshark:**

    *   A powerful network packet analyzer.
    *   Captures and analyzes network traffic in real-time.
    *   Provides detailed information about each packet, including protocol headers, data, and timestamps.
    *   Essential tool for network troubleshooting, security analysis, and threat hunting.

*   **Installing Wireshark (Kali Linux):**

    *   `sudo apt update && sudo apt install wireshark`

*   **Capturing Network Traffic:**

    *   Run Wireshark as root: `sudo wireshark`
    *   Select the network interface to capture traffic on.
    *   Start the capture.
    *   Stop the capture when you have collected enough data.

*   **Wireshark Interface:**

    *   **Packet List Pane:** Displays a summary of each captured packet.
    *   **Packet Details Pane:** Displays detailed information about the selected packet.
    *   **Packet Bytes Pane:** Displays the raw bytes of the selected packet.
    *   **Filter Bar:** Allows you to filter the captured traffic based on various criteria.

*   **Wireshark Filters:**

    *   **Capture Filters:** Filter traffic *before* it is captured. Useful for reducing the amount of data captured.
        *   Example: `tcp port 80` (captures only HTTP traffic).
        *   Example: `host 192.168.1.100` (captures traffic to/from the IP address 192.168.1.100).
    *   **Display Filters:** Filter traffic *after* it has been captured. More flexible than capture filters.
        *   Example: `http.request.method == "GET"` (displays only HTTP GET requests).
        *   Example: `ip.src == 10.0.0.1 && tcp.port == 443` (displays TCP traffic from 10.0.0.1 to port 443).
        *   Example: `http contains "password"` (displays HTTP traffic containing the string "password").
        *   Example: `tcp.flags.syn == 1 && tcp.flags.ack == 0` (displays TCP SYN packets).

*   **Analyzing Network Traffic with Wireshark:**

    *   **Following TCP Streams:** Allows you to view the entire conversation between two hosts.
        *   Right-click on a packet and select "Follow" -> "TCP Stream".
    *   **Examining Protocol Headers:** Provides information about the protocol being used, source and destination addresses, and other relevant details.
    *   **Extracting Files:** Allows you to extract files that have been transmitted over the network (e.g., images, documents, executables).
        *   "File" -> "Export Objects" -> "HTTP".
    *   **Statistical Analysis:** Wireshark provides various statistical tools for analyzing network traffic.
        *   "Statistics" -> "Summary"
        *   "Statistics" -> "Conversations"
        *   "Statistics" -> "Endpoints"

*   **Wireshark for Threat Hunting (Examples):**

    *   **Detecting C&C Traffic:** Look for unusual connection patterns, long-lived connections, or traffic to known malicious IP addresses or domains.
    *   **Identifying Data Exfiltration:** Look for large amounts of data being transferred to external hosts, or traffic to unusual ports or protocols.
    *   **Detecting Malware Infections:** Look for suspicious DNS queries, HTTP requests to malicious websites, or traffic containing malware signatures.
    *   **Analyzing Encrypted Traffic (HTTPS):** While you can't see the content, you can still analyze the TLS/SSL handshake to identify potential issues.

*   **Hands-on Exercise:**

    1.  Capture network traffic while browsing a website or using a specific application.
    2.  Use Wireshark filters to isolate specific types of traffic.
    3.  Follow a TCP stream to view the entire conversation between two hosts.
    4.  Examine the protocol headers of different packets.
    5.  Extract files that have been transmitted over the network.
    6.  Analyze the captured traffic for suspicious activity.

---

**4. Network Traffic Analysis (NTA) with Zeek (Bro) (2 hours)**

*   **Introduction to Zeek (Bro):**

    *   A powerful network security monitoring framework.
    *   Analyzes network traffic and generates detailed logs of events.
    *   Provides a high-level view of network activity, making it easier to identify anomalies and suspicious behavior.
    *   Scriptable and extensible, allowing you to customize its behavior.
    *   Focuses on creating context-rich logs, not just alerting.

*   **Installing Zeek (Bro) (Kali Linux):**

    ```bash
    sudo apt update
    sudo apt install zeek
    ```

*   **Configuring Zeek (Bro):**

    *   Configuration files are located in `/opt/zeek/etc`.
    *   Key configuration options:
        *   `node.cfg`: Defines the Zeek nodes in your deployment.
        *   `networks.cfg`: Defines the networks that Zeek should monitor.
        *   `zeekctl.cfg`: Zeek Control Framework configuration.
    *   To configure Zeek for a single-machine setup, edit `node.cfg` and ensure the interface is correctly set.  For example:

        ```
        [zeek]
        type=standalone
        host=localhost
        interface=eth0  # Change this to your actual interface
        lb_method=pf_ring
        ```

*   **Starting and Stopping Zeek (Bro):**

    *   Use the `zeekctl` command-line tool to manage Zeek.
    *   `sudo zeekctl deploy` (starts Zeek and deploys the configuration).
    *   `sudo zeekctl status` (checks the status of Zeek).
    *   `sudo zeekctl stop` (stops Zeek).
    *   `sudo zeekctl cron` (processes logs).

*   **Zeek (Bro) Log Files:**

    *   Zeek generates a variety of log files, located in `/opt/zeek/spool/zeek/`.
    *   Key log files:
        *   `conn.log`: Contains information about network connections.
        *   `dns.log`: Contains information about DNS queries.
        *   `http.log`: Contains information about HTTP requests.
        *   `ssl.log`: Contains information about SSL/TLS connections.
        *   `files.log`: Contains information about extracted files.
        *   `notice.log`: Contains notices generated by Zeek scripts.
        *   `software.log`: Contains information about detected software versions.

*   **Analyzing Zeek (Bro) Logs:**

    *   Zeek logs are typically stored in tab-separated value (TSV) format.
    *   Use command-line tools like `grep`, `awk`, `cut`, and `sort` to analyze the logs.
    *   Consider using specialized log analysis tools or SIEM solutions to process and visualize Zeek logs.

*   **Zeek (Bro) Scripting:**

    *   Zeek uses its own scripting language for customizing its behavior.
    *   Scripts can be used to:
        *   Detect specific types of traffic.
        *   Generate alerts.
        *   Modify the behavior of Zeek.
        *   Integrate with other security tools.
    *   Zeek scripts are located in `/opt/zeek/share/zeek/site`.

*   **Zeek (Bro) for Threat Hunting (Examples):**

    *   **Detecting C&C Traffic:** Use Zeek scripts to identify unusual connection patterns or traffic to known malicious IP addresses or domains.
    *   **Identifying Data Exfiltration:** Use Zeek scripts to detect large amounts of data being transferred to external hosts.
    *   **Detecting Malware Infections:** Use Zeek scripts to identify suspicious DNS queries, HTTP requests to malicious websites, or traffic containing malware signatures.
    *   **Analyzing Software Versions:** Use the `software.log` file to identify outdated or vulnerable software on the network.

*   **Hands-on Exercise:**

    1.  Install Zeek on your Kali Linux VM.
    2.  Start Zeek and generate some network traffic.
    3.  Examine the Zeek log files and identify relevant information.
    4.  Write a simple Zeek script to detect a specific type of traffic or generate an alert.
    5.  Test the script and verify that it works as expected.

    **Example Zeek script (detecting connections to a specific IP):**

    ```zeek
    @load base/frameworks/notice

    event connection_established(c: connection)
      {
      if (c?$id && c$id$resp_h == 1.2.3.4)  # Replace with a suspicious IP
        {
        Notice::create([
            $note = Notice::NOTE_SUSPICIOUS,
            $ts = Time::now(),
            $conn = c,
            $msg = fmt("Connection established to suspicious IP: %s", c$id$resp_h),
            $sub = "Suspicious Connection"
        ]);
        }
      }
    ```

    Save this script as `suspicious_ip.zeek` in `/opt/zeek/share/zeek/site/`, then run `sudo zeekctl deploy`

---

**5. NetFlow Analysis (1 hour)**

*   **Introduction to NetFlow:**

    *   A network protocol developed by Cisco for collecting network flow data.
    *   Provides information about network traffic flows, including:
        *   Source and destination IP addresses and ports.
        *   Protocol.
        *   Number of packets and bytes transferred.
        *   Start and end times.
    *   Less detailed than packet captures, but more scalable and efficient for large networks.

*   **NetFlow vs. Packet Capture:**

    | Feature          | NetFlow                  | Packet Capture              |
    | ---------------- | ------------------------ | ---------------------------- |
    | Data Captured    | Flow information         | Full packet content        |
    | Scalability      | High                     | Low                         |
    | Storage Required | Low                      | High                        |
    | Processing Power | Low                      | High                        |
    | Detail           | Less detailed            | Very detailed              |

*   **NetFlow Architecture:**

    *   **NetFlow Exporter:** A device (e.g., router, switch, firewall) that generates NetFlow data.
    *   **NetFlow Collector:** A server that receives and stores NetFlow data.
    *   **NetFlow Analyzer:** A tool that analyzes NetFlow data to identify trends, anomalies, and security threats.

*   **Tools for NetFlow Collection and Analysis:**

    *   **ntopng:** A network traffic monitoring tool that supports NetFlow.
    *   **SolarWinds NetFlow Traffic Analyzer:** A commercial NetFlow analyzer.
    *   **Wireshark:** Can be used to capture and analyze NetFlow data (but not a collector).
    *   **Softflowd:** A software-based NetFlow exporter.

*   **Analyzing NetFlow Data for Threat Hunting (Examples):**

    *   **Detecting C&C Traffic:** Look for unusual connection patterns, long-lived connections, or traffic to known malicious IP addresses or domains.
    *   **Identifying Data Exfiltration:** Look for large amounts of data being transferred to external hosts, or traffic to unusual ports or protocols.
    *   **Detecting DDoS Attacks:** Look for a sudden increase in traffic to a specific host or network.
    *   **Identifying Rogue Devices:** Look for devices that are not authorized to be on the network.

*   **Hands-on Exercise:**

    1.  Install a NetFlow collector and analyzer (e.g., ntopng) on your Kali Linux VM.
    2.  Configure a device (e.g., a router or switch) to export NetFlow data to the collector.  If you don't have a physical device, use `softflowd` on a virtual machine to generate NetFlow from captured traffic.
    3.  Analyze the NetFlow data and identify relevant information.
    4.  Use the NetFlow analyzer to identify suspicious activity.

---

**6. DNS Analysis (1 hour)**

*   **Introduction to DNS Analysis:**

    *   The Domain Name System (DNS) is used to translate domain names into IP addresses.
    *   DNS traffic can be a valuable source of information for threat hunting.
    *   Malicious actors often use DNS for command-and-control, data exfiltration, and other malicious activities.

*   **Key DNS Records:**

    *   **A Record:** Maps a domain name to an IPv4 address.
    *   **AAAA Record:** Maps a domain name to an IPv6 address.
    *   **CNAME Record:** Creates an alias for a domain name.
    *   **MX Record:** Specifies the mail server for a domain.
    *   **TXT Record:** Contains arbitrary text data.

*   **Tools for DNS Analysis:**

    *   **nslookup:** A command-line tool for querying DNS servers.
    *   **dig:** A more advanced command-line tool for querying DNS servers.
    *   **Wireshark:** Can be used to capture and analyze DNS traffic.
    *   **Zeek (Bro):** Generates detailed logs of DNS queries.
    *   **Passive DNS:** A database of historical DNS records.

*   **Analyzing DNS Traffic for Threat Hunting (Examples):**

    *   **Detecting Domain Generation Algorithms (DGAs):** DGAs are used by malware to generate a large number of random domain names, making it difficult to block them. Look for DNS queries to domains with unusual character patterns or high entropy.
    *   **Identifying Fast Flux DNS:** Fast flux DNS is a technique used by malware to rapidly change the IP addresses associated with a domain name, making it difficult to track down the malware. Look for domains with a very short TTL (Time To Live) and a large number of associated IP addresses.
    *   **Detecting DNS Tunneling:** DNS tunneling is a technique used to exfiltrate data over the DNS protocol. Look for DNS queries with unusually large payloads or traffic to unusual domains.
    *   **Identifying DNS Hijacking:** DNS hijacking is a technique used to redirect DNS queries to malicious servers. Look for DNS queries that return unexpected results.

*   **Hands-on Exercise:**

    1.  Use `nslookup` or `dig` to query DNS servers for various domain names.
    2.  Capture DNS traffic using Wireshark and analyze the packets.
    3.  Examine the Zeek (Bro) `dns.log` file and identify relevant information.
    4.  Use passive DNS to research the history of a domain name.
    5.  Analyze DNS traffic for suspicious activity.

---

**7. Module Project/Exercise: Network Forensics Challenge (30 minutes)**

*   **Objective:** Apply the knowledge and skills learned in this module to analyze a PCAP file and identify malicious activity.

*   **Scenario:** You are a threat hunter investigating a potential security incident. You have been provided with a PCAP file containing network traffic from the affected system. Your task is to analyze the PCAP file and identify any malicious activity.

*   **Steps:**

    1.  Download the PCAP file from a provided source (e.g., a link to a capture on Malware-Traffic-Analysis.net).
    2.  Use Wireshark, Zeek, Snort/Suricata (if applicable), and any other relevant tools to analyze the PCAP file.
    3.  Look for suspicious traffic patterns, malicious domains, malware signatures, and other indicators of compromise.
    4.  Document your findings in a report, including:
        *   A summary of the incident.
        *   A list of the tools and techniques you used.
        *   A description of the malicious activity you identified.
        *   Recommendations for remediation.

*   **Example PCAP Resources:**

    *   Malware-Traffic-Analysis.net: A great resource for PCAP files and malware analysis exercises.
    *   The Zoo: A collection of malware samples and PCAP files.

---

This detailed outline and content should provide a solid foundation for understanding and applying network-based threat hunting techniques. Remember to emphasize the hands-on exercises, as practical experience is crucial for developing these skills. Good luck!