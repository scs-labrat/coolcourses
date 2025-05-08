Okay, here are 10 slides for Module 4, "Threat Hunting Tools and Techniques (Part 1: Network)," based on the provided content, formatted in Markdown with detailed narrations.

---

**Slide 1: Module 4: Network Threat Hunting - Introduction**

*   **Title:** Module 4: Network Threat Hunting - Introduction
*   **Bullet Points:**
    *   Proactive hunting for malicious activity that bypasses existing defenses.
    *   Focus on network anomalies, patterns, and indicators of compromise (IoCs).
    *   Driven by hypotheses, threat intelligence, and understanding of network behavior.
    *   Key data sources: PCAP files, NetFlow, NIDS alerts, DNS logs, Proxy logs.
*   **Narration Script:**
    "Welcome to Module 4, where we'll be diving into the exciting world of Network Threat Hunting! Unlike traditional security approaches, which react to known threats, network threat hunting is all about proactively searching for malicious activity that might have slipped past your existing defenses. We'll learn how to identify anomalies, spot suspicious patterns, and uncover indicators of compromise in network traffic. This process is driven by informed hypotheses, leveraging threat intelligence, and a deep understanding of how networks typically behave. The key to effective network threat hunting lies in the data; we'll be using PCAP files containing packet captures, NetFlow data that summarizes network traffic, alerts from Network Intrusion Detection Systems, DNS logs, and Proxy logs."

---

**Slide 2: Why Network Threat Hunting?**

*   **Title:** Why Network Threat Hunting?
*   **Bullet Points:**
    *   Traditional security tools are often reactive and signature-based.
    *   Advanced attackers bypass defenses using stealthy techniques.
    *   Network traffic provides a rich and often overlooked source of data.
    *   Uncover: Command & Control, Data Exfiltration, Lateral Movement, Malware Infections.
*   **Narration Script:**
    "So, why should we bother with network threat hunting? The simple answer is that traditional security tools, relying on signatures and known patterns, are often reactive and struggle against advanced attackers. These attackers employ stealthy techniques designed to bypass conventional defenses. The network, however, provides a rich and often underutilized source of data. By analyzing network traffic, we can uncover malicious activities such as Command and Control communications where attackers control compromised systems, Data Exfiltration where sensitive data is being stolen, Lateral Movement as attackers move through a network, and of course, Malware Infections."

---

**Slide 3: NIDS with Snort/Suricata - Introduction**

*   **Title:** NIDS with Snort/Suricata - Introduction
*   **Bullet Points:**
    *   Network Intrusion Detection Systems (NIDS) monitor traffic based on rules.
    *   Generate alerts for suspicious activity.
    *   Can be signature-based or anomaly-based.
    *   Snort and Suricata are popular open-source options.
*   **Narration Script:**
    "Let's move on to Network Intrusion Detection Systems, or NIDS, and specifically focus on two popular open-source options: Snort and Suricata. NIDS act as sentinels, monitoring network traffic based on a predefined set of rules. When they detect activity that matches these rules, they generate alerts. These rules can be signature-based, looking for specific patterns, or anomaly-based, identifying deviations from normal network behavior. Snort and Suricata are powerful tools for identifying known threats and suspicious activities on your network."

---

**Slide 4: Snort/Suricata - Configuration & Rule Syntax**

*   **Title:** Snort/Suricata - Configuration & Rule Syntax
*   **Bullet Points:**
    *   Configuration files in `/etc/snort` or `/etc/suricata`.
    *   Key options: `HOME_NET`, `EXTERNAL_NET`, `RULE_PATH`, `INTERFACE`.
    *   Rule Structure: `action protocol src_ip src_port -> dest_ip dest_port (options)`.
    *   Common Options: `msg`, `content`, `sid`, `rev`, `classtype`, `flags`, `dsize`, `ttl`.
*   **Narration Script:**
    "To effectively use Snort or Suricata, we need to understand how to configure them and write rules. The main configuration files are located in `/etc/snort` or `/etc/suricata`, depending on which one you're using. Key configuration options include `HOME_NET`, which defines your internal network, `EXTERNAL_NET`, usually the internet, `RULE_PATH`, specifying where your rules are stored, and `INTERFACE`, the network interface to monitor. The rules themselves follow a specific syntax: `action protocol src_ip src_port -> dest_ip dest_port (options)`. The *action* determines what happens when a rule is matched. Common options allow you to specify details like the alert message (`msg`), specific content to look for (`content`), a unique rule ID (`sid`), and other criteria like TCP flags, packet size, and Time-To-Live."

---

**Slide 5: Snort/Suricata - Rule Examples**

*   **Title:** Snort/Suricata - Rule Examples
*   **Bullet Points:**
    *   Detecting ICMP Traffic: `alert icmp any any -> any any (msg:"ICMP Traffic Detected"; sid:1000001; rev:1;)`.
    *   HTTP with "malware.exe": `alert tcp any any -> any 80 (msg:"HTTP Traffic with malware.exe"; content:"malware.exe"; http_uri; sid:1000002; rev:1;)`.
    *   Suspicious User-Agent: `alert tcp any any -> any 80 (msg:"Suspicious User-Agent"; content:"BadBot/1.0"; http_header; sid:1000003; rev:1;)`.
*   **Narration Script:**
    "Let's look at some examples of Snort/Suricata rules. This first rule alerts on all ICMP traffic, a simple but useful starting point. The second rule looks for HTTP traffic going to port 80 that contains the string "malware.exe" in the URI, which could indicate a malware download. The third rule flags any HTTP request with the User-Agent string "BadBot/1.0" in the header, potentially indicating a malicious bot. By crafting rules like these, you can tailor your NIDS to detect specific threats relevant to your environment."

---

**Slide 6: NTA with Wireshark - Introduction**

*   **Title:** NTA with Wireshark - Introduction
*   **Bullet Points:**
    *   Wireshark: A powerful network packet analyzer.
    *   Captures and analyzes network traffic in real-time.
    *   Provides detailed packet information (protocol headers, data, timestamps).
    *   Essential for troubleshooting, security analysis, and threat hunting.
*   **Narration Script:**
    "Now we'll introduce Wireshark, a powerful and versatile network packet analyzer. Wireshark allows you to capture and analyze network traffic in real-time, providing incredibly detailed information about each packet. This includes protocol headers, the actual data being transmitted, and precise timestamps. Wireshark is an essential tool not only for network troubleshooting but also for security analysis and, of course, threat hunting."

---

**Slide 7: Wireshark - Filters: Capture and Display**

*   **Title:** Wireshark - Filters: Capture and Display
*   **Bullet Points:**
    *   **Capture Filters:** Filter traffic *before* capture (e.g., `tcp port 80`, `host 192.168.1.100`).  Reduces data volume.
    *   **Display Filters:** Filter traffic *after* capture (e.g., `http.request.method == "GET"`, `ip.src == 10.0.0.1 && tcp.port == 443`, `http contains "password"`).  More flexible.
*   **Narration Script:**
    "Wireshark offers two types of filters: capture filters and display filters. Capture filters are applied *before* the traffic is captured, allowing you to reduce the amount of data collected. For example, you can capture only HTTP traffic or traffic to/from a specific host. Display filters, on the other hand, are applied *after* the capture, giving you more flexibility to analyze the data you've already collected. You can filter based on HTTP request methods, IP addresses and ports, or even search for specific strings within the traffic. Understanding and using these filters effectively is crucial for efficient network traffic analysis."

---

**Slide 8: NTA with Zeek (Bro) - Introduction**

*   **Title:** NTA with Zeek (Bro) - Introduction
*   **Bullet Points:**
    *   Zeek (Bro): Network security monitoring framework.
    *   Analyzes network traffic and generates detailed logs.
    *   Provides a high-level view of network activity.
    *   Scriptable and extensible for custom analysis.
    *   Focuses on context-rich logs, not just alerting.
*   **Narration Script:**
    "Next, we'll explore Zeek, formerly known as Bro, a powerful network security monitoring framework. Unlike Snort/Suricata, which primarily focus on alerting, Zeek analyzes network traffic and generates detailed logs of events, providing a high-level view of network activity. Zeek is highly scriptable and extensible, allowing you to customize its behavior to fit your specific needs. It's designed to create context-rich logs, providing a wealth of information for threat hunting and incident response."

---

**Slide 9: Zeek (Bro) - Key Log Files**

*   **Title:** Zeek (Bro) - Key Log Files
*   **Bullet Points:**
    *   `conn.log`: Network connections.
    *   `dns.log`: DNS queries.
    *   `http.log`: HTTP requests.
    *   `ssl.log`: SSL/TLS connections.
    *   `files.log`: Extracted files.
    *   `notice.log`: Notices generated by Zeek scripts.
    *   `software.log`: Detected software versions.
*   **Narration Script:**
    "Zeek generates a variety of log files, each providing different insights into network activity. The `conn.log` contains information about network connections, while `dns.log` tracks DNS queries. The `http.log` records HTTP requests, and `ssl.log` details SSL/TLS connections. The `files.log` keeps track of any files that were extracted from the network traffic. The `notice.log` contains notices generated by Zeek scripts, and finally, `software.log` detects software versions running on the network. By analyzing these log files, you can gain a comprehensive understanding of network behavior and identify potential threats."

---

**Slide 10: Module 4 - Network Forensics Challenge**

*   **Title:** Module 4 - Network Forensics Challenge
*   **Bullet Points:**
    *   Analyze a PCAP file to identify malicious activity.
    *   Use Wireshark, Zeek, Snort/Suricata to analyze PCAP file.
    *   Look for suspicious traffic patterns, malicious domains, malware signatures.
    *   Document your findings in a report and provide recommendations.
*   **Narration Script:**
    "To put everything we've learned into practice, we'll conclude Module 4 with a Network Forensics Challenge. You'll be provided with a PCAP file and tasked with analyzing it to identify any malicious activity. You'll use the tools and techniques we've covered, including Wireshark, Zeek, and potentially Snort/Suricata, to look for suspicious traffic patterns, malicious domains, and malware signatures. The goal is to document your findings in a comprehensive report, outlining the incident, the tools you used, the malicious activity you identified, and your recommendations for remediation. This challenge will solidify your understanding of network threat hunting and prepare you for more advanced topics in the course."

---