Okay, let's dive deep into **Module 5: Threat Hunting Tools and Techniques (Part 2: Endpoint & Logs)**. This module is crucial because endpoints are often the first point of entry for attackers, and logs provide a treasure trove of information about their activities. We'll cover how to effectively use tools and techniques to hunt for threats on endpoints and within logs.  I'll try to break it down in a way that's both comprehensive and easy to follow.

**Module 5: Threat Hunting Tools and Techniques (Part 2: Endpoint & Logs)**

**Module Objective:** Learn to leverage endpoint-based tools and techniques for detecting malicious activity.

**Subtopics:**

1.  **Endpoint Detection and Response (EDR) Solutions:**
    *   Overview of EDR capabilities.
    *   Using EDR tools for threat hunting.
2.  **Sysmon:**
    *   Configuring Sysmon for detailed logging.
    *   Analyzing Sysmon logs for suspicious activity.
3.  **Windows Event Logs:**
    *   Understanding Windows Event Log structure.
    *   Using PowerShell for Event Log analysis.
4.  **Linux Audit Logs:**
    *   Configuring auditd.
    *   Analyzing audit logs for suspicious activity.
5.  **SIEM (Security Information and Event Management) Systems:**
    *   Overview of SIEM architecture.
    *   Using SIEM for threat hunting.
6.  **Practical Exercises:**
    *   Analyzing Sysmon logs to detect malware execution.
    *   Using PowerShell to query Windows Event Logs.

**1. Endpoint Detection and Response (EDR) Solutions**

*   **Overview of EDR Capabilities:**

    *   **What is EDR?**  EDR solutions are advanced security tools designed to detect and respond to threats on endpoints. They go beyond traditional antivirus by providing real-time monitoring, behavioral analysis, and automated response capabilities.
    *   **Key Features:**
        *   **Real-time Monitoring:** Continuously monitors endpoint activity (processes, network connections, file changes, registry modifications).
        *   **Behavioral Analysis:**  Identifies suspicious behavior based on predefined rules and machine learning algorithms.  This helps detect anomalies that traditional signature-based AV might miss.
        *   **Threat Intelligence Integration:** Correlates endpoint activity with known threat intelligence to identify potential threats.
        *   **Automated Response:**  Automatically isolates infected endpoints, terminates malicious processes, and removes malicious files.
        *   **Forensic Analysis:**  Provides tools for investigating security incidents and understanding the root cause of attacks.
        *   **Endpoint Isolation:** Ability to quickly isolate a compromised endpoint from the network to prevent further spread.
    *   **Popular EDR Solutions:** CrowdStrike Falcon, SentinelOne, Carbon Black, Microsoft Defender for Endpoint.  (Note: Access to a full EDR solution requires licensing. We'll focus on techniques applicable even without a full EDR deployment.)

*   **Using EDR Tools for Threat Hunting:**

    *   **Searching for Indicators of Compromise (IoCs):**  EDR tools allow you to search for specific IoCs (IP addresses, domain names, file hashes, registry keys) across all endpoints.
    *   **Behavioral Hunting:**  Identify suspicious behavior by searching for specific events or sequences of events.  For example, you might look for processes that are creating child processes with suspicious names or network connections.
    *   **Threat Intelligence Integration:**  Leverage the EDR's threat intelligence feeds to identify potential threats that are targeting your organization.
    *   **Example Scenarios:**
        *   **Hunting for Lateral Movement:** Look for processes that are accessing network shares or attempting to authenticate to other systems.
        *   **Hunting for Malware Execution:**  Look for processes that are creating or modifying files in suspicious locations (e.g., the Startup folder) or that are injecting code into other processes.
        *   **Hunting for Command and Control (C2) Activity:**  Look for processes that are communicating with known C2 servers.
    *   **Limitations:**  EDR solutions can be expensive and require significant expertise to configure and manage. They also rely on accurate threat intelligence and behavioral analysis rules.

**2. Sysmon**

*   **Configuring Sysmon for Detailed Logging:**

    *   **What is Sysmon?** Sysmon (System Monitor) is a free Windows system service that logs detailed information about system activity to the Windows Event Log.  It's a powerful tool for threat hunting and incident response.
    *   **Download and Installation:** Download Sysmon from the Microsoft Sysinternals website ([https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)).
    *   **Configuration File:** Sysmon is configured using an XML configuration file.  This file specifies which events to log and how to filter them.
    *   **Sample Configuration File (sysmonconfig.xml):**  This is a basic example.  You'll need to customize it for your specific needs.

    ```xml
    <Sysmon schemaversion="4.82">
      <EventFiltering>
        <RuleGroup name="" groupRelation="or">
          <ProcessCreate onmatch="include">
            <Image condition="end with">powershell.exe</Image>
          </ProcessCreate>
          <FileCreateTime onmatch="include">
            <Image condition="end with">powershell.exe</Image>
          </FileCreateTime>
          <NetworkConnect onmatch="include">
            <Image condition="end with">powershell.exe</Image>
            <SourcePort condition="is">443</SourcePort>
          </NetworkConnect>
        </RuleGroup>
      </EventFiltering>
    </Sysmon>
    ```

    *   **Explanation:**
        *   `schemaversion`: Specifies the Sysmon schema version.
        *   `EventFiltering`:  Defines the rules for filtering events.
        *   `RuleGroup`:  Groups related rules together.  `groupRelation="or"` means that any rule in the group can trigger a match.
        *   `ProcessCreate`:  Logs when a new process is created.
        *   `FileCreateTime`: Logs when a file create time is changed. This can be useful for detecting malware that's trying to hide its presence.
        *   `NetworkConnect`:  Logs when a process makes a network connection.
        *   `Image`:  Specifies the process image name.  `condition="end with"` means that the rule will match if the image name ends with the specified value.
        *   `SourcePort`: Specifies the source port of the network connection.

    *   **Installing Sysmon with the Configuration File:**

    ```powershell
    Sysmon64.exe -i sysmonconfig.xml -accepteula
    ```

    *   **Key Event Types to Log:**
        *   **Event ID 1 (Process Create):**  Logs when a new process is created.  This is essential for tracking process execution and identifying suspicious processes.
        *   **Event ID 3 (Network Connection):**  Logs when a process makes a network connection.  This is essential for tracking network communication and identifying C2 activity.
        *   **Event ID 5 (Process Terminate):** Logs when a process terminates.  Useful for correlating process creation and termination events.
        *   **Event ID 7 (Image Load):** Logs when a driver or DLL is loaded. Useful for detecting malware that is injecting code into other processes.
        *   **Event ID 8 (CreateRemoteThread):** Logs when a process creates a thread in another process.  This is often used by malware for code injection.
        *   **Event ID 9 (RawAccessRead):** Logs when a process reads directly from the drive. Useful for detecting data exfiltration.
        *   **Event ID 10 (ProcessAccess):** Logs when a process access another process.
        *   **Event ID 11 (FileCreate):** Logs when a file is created.
        *   **Event ID 12, 13, 14 (Registry Events):** Logs registry modifications.  Useful for detecting malware that is modifying registry keys to achieve persistence.
        *   **Event ID 15 (FileCreateStreamHash):** Logs the hash of files created.

*   **Analyzing Sysmon Logs for Suspicious Activity:**

    *   **Location of Sysmon Logs:**  Sysmon logs are stored in the Windows Event Log under `Applications and Services Logs\Microsoft\Windows\Sysmon\Operational`.
    *   **Tools for Analyzing Sysmon Logs:**
        *   **Event Viewer:**  The built-in Windows Event Viewer can be used to view and filter Sysmon logs.
        *   **PowerShell:**  PowerShell can be used to query and analyze Sysmon logs.
        *   **SIEM Systems:**  Sysmon logs can be forwarded to a SIEM system for centralized analysis.
        *   **Elasticsearch/Kibana:**  Sysmon logs can be ingested into Elasticsearch and visualized using Kibana.
    *   **Example Threat Hunting Scenarios:**
        *   **Detecting PowerShell Obfuscation:**  Look for PowerShell processes that are executing commands with unusual characters or that are using the `-EncodedCommand` parameter.
        *   **Detecting Process Injection:**  Look for processes that are creating remote threads in other processes.
        *   **Detecting Lateral Movement:**  Look for processes that are accessing network shares or attempting to authenticate to other systems.
        *   **Detecting Malware Persistence:**  Look for processes that are creating or modifying registry keys in the `Run` or `RunOnce` keys.

**3. Windows Event Logs**

*   **Understanding Windows Event Log Structure:**

    *   **What are Windows Event Logs?** Windows Event Logs are a record of system events, including application errors, security events, and system events. They are a valuable source of information for troubleshooting, auditing, and security monitoring.
    *   **Key Event Logs:**
        *   **Application:**  Logs events related to applications.
        *   **Security:**  Logs security-related events, such as logon attempts, account management events, and object access events.  This is the *most* relevant log for threat hunting.
        *   **System:**  Logs events related to the operating system.
    *   **Event Log Structure:** Each event log entry contains the following information:
        *   **Event ID:**  A unique identifier for the event.
        *   **Source:**  The component that generated the event.
        *   **Time Generated:**  The date and time when the event occurred.
        *   **User:**  The user account that was associated with the event.
        *   **Computer:**  The computer on which the event occurred.
        *   **Description:**  A detailed description of the event.
        *   **EventData:**  Structured data associated with the event (e.g., user account names, file paths, IP addresses).

*   **Using PowerShell for Event Log Analysis:**

    *   **`Get-WinEvent` Cmdlet:**  The `Get-WinEvent` cmdlet is used to query Windows Event Logs.

    *   **Example: Get Security Events:**

    ```powershell
    Get-WinEvent -LogName Security -MaxEvents 10
    ```

    *   **Example: Filter by Event ID:**

    ```powershell
    Get-WinEvent -LogName Security -FilterXPath "//Event[System[EventID=4624]]" -MaxEvents 10
    ```

    *   **Explanation:**
        *   `-LogName`: Specifies the name of the event log to query.
        *   `-FilterXPath`: Specifies an XPath query to filter the events.
        *   `//Event[System[EventID=4624]]`:  An XPath query that selects all events with Event ID 4624 (an account successfully logged on).
        *   `-MaxEvents`: Specifies the maximum number of events to retrieve.

    *   **Example: Extract Specific Data:**

    ```powershell
    Get-WinEvent -LogName Security -FilterXPath "//Event[System[EventID=4624]]" -MaxEvents 10 | ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            AccountName = $_.Properties[5].Value
            SourceNetworkAddress = $_.Properties[8].Value
        }
    }
    ```

    *   **Explanation:**
        *   `ForEach-Object`: Iterates over each event.
        *   `[PSCustomObject]`:  Creates a custom object with the specified properties.
        *   `$_.TimeCreated`:  Gets the time the event was created.
        *   `$_.Properties[5].Value`:  Gets the value of the 6th property (Account Name).  **Important:** The property index may vary depending on the Event ID.  Inspect the raw event data to determine the correct index.
        *   `$_.Properties[8].Value`: Gets the value of the 9th property (Source Network Address).

    *   **Common Event IDs for Threat Hunting:**
        *   **4624:**  An account was successfully logged on. (Success Audit)
        *   **4625:**  An account failed to log on. (Failure Audit)  Monitor for repeated failed logon attempts, which could indicate a brute-force attack.
        *   **4672:**  Special privileges assigned to new logon. (Success Audit)
        *   **4688:**  A new process has been created. (Success Audit)  (Similar to Sysmon's Event ID 1, but less detailed).
        *   **4776:**  The domain controller attempted to validate the credentials for an account. (Success Audit) (Kerberos authentication).
        *   **4769:**  A Kerberos service ticket was requested. (Success Audit)

    *   **Example Threat Hunting Scenarios:**

        *   **Detecting Brute-Force Attacks:**  Look for a large number of failed logon attempts (Event ID 4625) from the same source IP address.
        *   **Detecting Lateral Movement:**  Look for successful logon events (Event ID 4624) where the logon type is "Network" (LogonType = 3) and the source IP address is different from the user's usual IP address.
        *   **Detecting Account Impersonation:**  Look for successful logon events (Event ID 4624) where the "Logon ID" is the same as a previous failed logon event (Event ID 4625).

**4. Linux Audit Logs**

*   **Configuring `auditd`:**

    *   **What is `auditd`?**  `auditd` (Audit Daemon) is a Linux subsystem that logs system calls and other security-related events.  It's the primary source of audit information on Linux systems.
    *   **Installation:**  `auditd` is usually installed by default on most Linux distributions. If not, install it using your distribution's package manager (e.g., `apt-get install auditd` on Debian/Ubuntu, `yum install auditd` on CentOS/RHEL).
    *   **Configuration File:** The main configuration file for `auditd` is `/etc/audit/auditd.conf`.
    *   **Audit Rules:**  Audit rules are defined in `/etc/audit/rules.d/audit.rules` (or similar location, depending on the distribution).  These rules specify which events to log and how to filter them.
    *   **Basic Audit Rule Syntax:**

    ```
    -w <path> -p <permissions> -k <key>
    ```

    *   `-w <path>`:  Specifies the path to the file or directory to monitor.
    *   `-p <permissions>`:  Specifies the permissions to monitor (e.g., `r` for read, `w` for write, `x` for execute, `a` for attribute changes).
    *   `-k <key>`:  Specifies a keyword to associate with the rule.  This makes it easier to filter audit logs.

    *   **Example: Monitor `/etc/passwd` for Write Access:**

    ```
    -w /etc/passwd -p wa -k passwd_changes
    ```

    *   **Example: Monitor Executions of `ssh`:**

    ```
    -a always,exit -F arch=b64 -S execve -F path=/usr/bin/ssh -k ssh_exec
    ```

    *   **Explanation:**
        *   `-a always,exit`:  Log the event on every execution and on exit.
        *   `-F arch=b64`:  Specifies the architecture (64-bit).
        *   `-S execve`:  Specifies the system call (execve is used to execute programs).
        *   `-F path=/usr/bin/ssh`:  Specifies the path to the executable.
        *   `-k ssh_exec`:  Specifies the keyword.

    *   **Reloading Audit Rules:** After modifying the audit rules, reload them using the following command:

    ```
    auditctl -R /etc/audit/rules.d/audit.rules
    ```

*   **Analyzing Audit Logs for Suspicious Activity:**

    *   **Location of Audit Logs:**  Audit logs are typically stored in `/var/log/audit/audit.log`.
    *   **`ausearch` Utility:** The `ausearch` utility is used to query and analyze audit logs.
    *   **Example: Search for Events with a Specific Keyword:**

    ```
    ausearch -k passwd_changes
    ```

    *   **Example: Search for Failed Login Attempts:**

    ```
    ausearch -m auid!=4294967295 -m user_login,user_auth,user_acct -sc auth
    ```

    *   **Example: Search for Executions of `ssh`:**

    ```
    ausearch -k ssh_exec
    ```

    *   **Example Threat Hunting Scenarios:**

        *   **Detecting Unauthorized File Modifications:**  Look for events that indicate that a critical system file (e.g., `/etc/passwd`, `/etc/shadow`) has been modified.
        *   **Detecting Suspicious Process Executions:**  Look for events that indicate that a suspicious process has been executed (e.g., a process that is not normally run by a particular user).
        *   **Detecting Privilege Escalation Attempts:**  Look for events that indicate that a user has attempted to use the `sudo` command or has changed their user ID.
        *   **Detecting SSH Brute-Force Attacks:**  Analyze the logs for failed SSH login attempts.

**5. SIEM (Security Information and Event Management) Systems**

*   **Overview of SIEM Architecture:**

    *   **What is a SIEM?**  A SIEM system is a centralized platform for collecting, analyzing, and managing security logs and events from various sources across an organization.  It provides real-time threat detection, incident response, and compliance reporting.
    *   **Key Components:**
        *   **Log Collection:**  Collects logs from various sources (e.g., firewalls, intrusion detection systems, servers, endpoints).
        *   **Log Parsing and Normalization:**  Parses logs and normalizes the data into a consistent format.
        *   **Correlation Engine:**  Analyzes logs and events to identify potential threats.
        *   **Alerting:**  Generates alerts when suspicious activity is detected.
        *   **Incident Management:**  Provides tools for managing security incidents.
        *   **Reporting:**  Generates reports for compliance and security monitoring.
    *   **Popular SIEM Solutions:** Splunk, QRadar, ArcSight, Microsoft Sentinel, Sumo Logic.

*   **Using SIEM for Threat Hunting:**

    *   **Centralized Log Management:**  SIEM systems provide a centralized repository for all security logs, making it easier to search for and analyze data.
    *   **Correlation Rules:**  SIEM systems allow you to create correlation rules that identify suspicious activity based on patterns of events.
    *   **Threat Intelligence Integration:**  SIEM systems integrate with threat intelligence feeds to identify potential threats that are targeting your organization.
    *   **Behavioral Analysis:**  Some SIEM systems provide behavioral analysis capabilities that can identify anomalies in user and system behavior.
    *   **Example Threat Hunting Scenarios:**
        *   **Detecting Lateral Movement:**  Look for users who are logging in to multiple systems in a short period of time.
        *   **Detecting Data Exfiltration:**  Look for large amounts of data being transferred to external IP addresses.
        *   **Detecting Malware Infections:**  Look for processes that are communicating with known C2 servers.

**6. Practical Exercises**

*   **Analyzing Sysmon Logs to Detect Malware Execution:**

    *   **Scenario:** A user has reported that their computer is behaving strangely. You suspect that it may be infected with malware.
    *   **Steps:**
        1.  **Examine Sysmon Event ID 1 (Process Create):**  Look for processes that are being created from unusual locations (e.g., the Temp folder) or that have suspicious names.
        2.  **Examine Sysmon Event ID 7 (Image Load):** Look for processes loading DLLs from unusual locations.
        3.  **Examine Sysmon Event ID 3 (Network Connection):**  Look for processes that are making network connections to suspicious IP addresses or domain names.
        4.  **Correlate Events:**  Correlate events to identify patterns of activity that may indicate malware execution. For example, look for a process that is created from the Temp folder, loads a DLL from a suspicious location, and then makes a network connection to a known C2 server.
        5.  **Investigate:** If you find suspicious activity, investigate the process further to determine if it is malicious. You can use tools like VirusTotal to check the file hash of the process.

*   **Using PowerShell to Query Windows Event Logs:**

    *   **Scenario:** You want to identify all users who have logged in to a specific computer in the last 24 hours.
    *   **Steps:**

        ```powershell
        $StartTime = (Get-Date).AddDays(-1)
        Get-WinEvent -LogName Security -FilterXPath "//Event[System[EventID=4624 and TimeCreated >= '$($StartTime.ToString('yyyy-MM-ddTHH:mm:ss'))']]" | ForEach-Object {
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                AccountName = $_.Properties[5].Value
            }
        }
        ```

    *   **Explanation:**
        1.  `$StartTime = (Get-Date).AddDays(-1)`:  Calculates the start time (24 hours ago).
        2.  `Get-WinEvent -LogName Security -FilterXPath "//Event[System[EventID=4624 and TimeCreated >= '$($StartTime.ToString('yyyy-MM-ddTHH:mm:ss'))']]"`:  Queries the Security event log for successful logon events (Event ID 4624) that occurred within the last 24 hours.  The `TimeCreated` comparison in the XPath query is crucial for filtering by time.
        3.  `ForEach-Object { ... }`: Iterates through the results and creates a custom object for each event, displaying the TimeCreated and AccountName.

**Key Takeaways for Module 5:**

*   Endpoints and logs are crucial sources of information for threat hunting.
*   EDR solutions provide advanced capabilities for detecting and responding to threats on endpoints.
*   Sysmon is a powerful tool for logging detailed system activity on Windows systems.
*   Windows Event Logs and Linux Audit Logs provide a wealth of information about system events.
*   SIEM systems provide a centralized platform for collecting, analyzing, and managing security logs and events.
*   PowerShell and `ausearch` are valuable tools for querying and analyzing event logs.
*   Understanding common threat hunting scenarios and techniques is essential for effective threat hunting.

This detailed breakdown should give you a solid understanding of Module 5. Remember to practice these techniques in a lab environment to gain hands-on experience. Good luck, and happy hunting! Let me know if you want more details on any of these topics.