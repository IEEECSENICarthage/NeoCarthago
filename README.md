# NeoCarthago

**NeoCarthgo** is an advanced cybersecurity solution designed to mitigate a wide range of cyber threats by integrating cutting-edge tools like **Wazuh**, **VirusTotal**, and AI-driven technologies. The platform leverages Wazuh for monitoring and managing cyberattacks, gathering critical log data for enhanced threat detection and response. Additionally, it incorporates a sophisticated AI model to analyze and address specific attack patterns, providing an extra layer of defense against emerging threats. Cyber Shield offers a comprehensive, automated approach to cybersecurity, ensuring real-time protection and proactive threat mitigation.

---

## Table of Contents

- [NeoCarthago](#neocarthago)
- [Infrastructure Setup](#infrastructure-setup)
  - [Installation of Wazuh](#installation-of-wazuh)
    - [Installation on Ubuntu](#installation-on-ubuntu)
    - [Installation on Windows](#installation-on-windows)
- [Wazuh Usage](#wazuh-usage)
  - [Monitoring and Alerts](#monitoring-and-alerts)
  - [Log Collection](#log-collection)
  - [Wazuh and VirusTotal Integration for Malicious File Detection](#wazuh-and-virustotal-integration-for-malicious-file-detection)
  - [Wazuh Dashboard Configuration](#wazuh-dashboard-configuration)
- [NeoCarthago's AI](#neocarthagos-ai)
  - [Supported Attacks](#supported-attacks)
- [Nmap and Gemini in Cybersecurity](#nmap-and-gemini-in-cybersecurity)
  - [Nmap](#nmap)
  - [Gemini](#gemini)
- [Resources](#Resources)
- [Contributing](#contributing)
- [Credits](#credits)
- [Contact](#contact)


---

## Infrastructure Setup

### Installation of Wazuh

Wazuh is a powerful security monitoring tool that provides threat detection, integrity monitoring, incident response, and compliance management. Cyber Shield uses Wazuh as its core for log collection and threat monitoring. The following subsections describe how to install Wazuh on different platforms.

#### Installation on Ubuntu
To install Wazuh on Ubuntu:

1. **Update your system packages:**
   ```bash
   sudo apt-get update && sudo apt-get upgrade
   ```
2. **Add the Wazuh repository:**
   ```bash
   curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
   echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
   ```
3. **Install the Wazuh manager and dependencies:**
   ```bash
   sudo apt-get install wazuh-manager
   ```
4. **Configure the Wazuh manager:**
   - Modify the `/var/ossec/etc/ossec.conf` file for custom settings like log monitoring and alerts.

5. **Start the Wazuh manager:**
   ```bash
   sudo systemctl start wazuh-manager
   ```

#### Installation on Windows

To install Wazuh on Windows:

1. **Download the Wazuh agent installer** from the official Wazuh website.
2. **Run the installer** and follow the setup wizard to install the agent on your Windows system.
3. **Configure the Wazuh agent**:
   - Modify the `ossec.conf` file located in the Wazuh installation directory to point to your Wazuh server.
   - Example configuration:
     ```xml
     <server>
       <address>YourWazuhManagerIP</address>
       <port>1514</port>
     </server>
     ```
4. **Start the Wazuh agent**:
   ```cmd
   net start WazuhSvc
   ```
5. **Verify the connection** to the Wazuh manager by checking the logs.

---

## Wazuh Usage

### Monitoring and Alerts

Wazuh continuously monitors your system for potential threats and anomalies by analyzing log data. It generates real-time alerts based on predefined rules, which can be customized to fit your security needs.

- **Access the Wazuh dashboard** by navigating to:
  ```bash
  http://localhost:5601
  ```
  Here, you can view alerts, monitor system status, and configure custom alerting rules.
  
- Wazuh integrates with **Elasticsearch** and **Kibana** for advanced log analysis and visualization.

### Log Collection

Wazuh collects logs from various sources, including operating systems, applications, and network devices. The logs are analyzed using predefined rules to detect suspicious activity.

- **Supported log types**: system logs, firewall logs, application logs, and more.
  
- Logs are stored in the Wazuh manager and can be visualized through the **Kibana** interface.

- **Custom log collection**: Configure Wazuh to collect specific logs by editing the `ossec.conf` file and defining the paths for the logs you want to monitor.

### Wazuh and VirusTotal Integration for Malicious File Detection

In NeoCarthago, Wazuh is integrated with VirusTotal to enhance security by identifying and responding to potentially malicious files within the environment. VirusTotal is a well-known online platform that aggregates data from multiple antivirus vendors, providing comprehensive insights about files' safety based on industry-wide detection metrics. 

This integration enables Wazuh to:

1. **Identify Suspicious Files**: Wazuh collects and analyzes file data, such as hashes and file signatures, from endpoints and network traffic. If a file appears unusual or originates from an unknown or suspicious source, Wazuh flags it for further analysis.

2. **Send File Hashes to VirusTotal**: Rather than sending the entire file, Wazuh securely sends hashes of the files to VirusTotal’s API. VirusTotal cross-references these hashes against its extensive database of known threats and benign files.

3. **Retrieve and Analyze Results**: Based on VirusTotal's response, Wazuh can assess the file’s risk level. If the file is determined to be malicious or potentially dangerous, Wazuh can trigger alerts, notify administrators, and initiate predefined response actions to contain the threat.

4. **Automate Threat Responses**: In cases where malicious files are detected, Cyber Shield can implement automatic responses, such as isolating infected endpoints or removing malicious files, reducing potential damage and enhancing overall security.

By leveraging Wazuh's monitoring capabilities with VirusTotal's vast malware database, Cyber Shield provides an efficient, scalable solution for identifying and managing cyber threats in real time. 

### Wazuh Dashboard Configuration

The Wazuh dashboard is a powerful tool for monitoring and managing security events. Here’s how to configure it effectively:

1. **Access the Dashboard**: Open your web browser and navigate to the dashboard URL (`http://localhost:5601`).

2. **Initial Setup**: If this is your first time accessing the dashboard, complete the initial setup wizard to connect it to your Wazuh manager and Elasticsearch.

3. **Customize Alerts**:
   - Go to the **Management** tab.
   - Navigate to **Rules** to customize existing rules or add new ones based on your environment's needs.

4. **Dashboards and Visualizations**:
   - Explore predefined dashboards for quick insights.
   - Create custom visualizations using the **Visualize** tab to focus on specific data points relevant to your organization.

5. **User Management**: Set up user roles and permissions under the **Management** section to control access to the dashboard.

---

## NeoCarthago's AI

### Supported Attacks

NeoCarthago's AI solution is designed to detect and mitigate several types of common cyberattacks. The model is pre-trained to identify patterns associated with the following attack types:

- **DCSync attack**: Detects malicious SQL queries attempting to manipulate databases.
- **Kerberoasting Attack**: Identifies abnormal traffic patterns indicative of DDoS attacks.
- **Brute Force Attack**: Flags multiple failed login attempts that suggest a brute force attack.
- **LLMNR Attack**: Detects file encryption behaviors commonly associated with ransomware.

### Nmap and Gemini in Cybersecurity

### Nmap
**Nmap** (Network Mapper) is a powerful, open-source network scanning tool widely used in cybersecurity for network discovery, security auditing, and vulnerability assessment. It allows security professionals to detect live hosts, open ports, running services, and system details on networks, providing a clear picture of an environment's security posture. Nmap can be used to identify misconfigurations, weak points, and vulnerabilities in a network, making it an invaluable tool for proactive threat management and incident response.

**Common Uses of Nmap in Cybersecurity**:
- **Network Discovery**: Identifying active devices and services on the network.
- **Port Scanning**: Detecting open and closed ports for potential entry points.
- **Service and Version Detection**: Gathering information on software versions to check for known vulnerabilities.
- **Vulnerability Scanning**: Highlighting insecure configurations and services, allowing teams to address issues before exploitation.
  
### Gemini
**Gemini** is a conversational AI model by Google that assists cybersecurity teams by providing quick insights, explanations, and recommendations for complex security topics and workflows. Its language-based understanding and versatility make it useful for generating scripts, automating documentation, and providing real-time guidance in incident response scenarios. Gemini can be a powerful assistant for interpreting log data, suggesting remediation steps, or acting as a knowledge base to support less experienced team members.

**Common Uses of Gemini in Cybersecurity**:
- **Threat Intelligence**: Quickly reviewing and interpreting threat feeds, providing context to logs or alerts.
- **Script Generation**: Assisting in writing scripts for automated tasks like log parsing, file scanning, or data filtering.
- **Incident Response**: Offering actionable insights and structured steps for common incident types, which can speed up the response process.
- **Documentation**: Streamlining the creation of detailed reports, readme files, or guidelines for cybersecurity processes.

Combining **Nmap** for network security assessment and **Gemini** for contextual insights and automation enables security teams to streamline processes, reduce response time, and strengthen defenses against evolving cyber threats.

---

## Contributing

We welcome contributions! To contribute to Cyber Shield:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature-name`).
3. Commit your changes (`git commit -m 'Add new feature'`).
4. Push to the branch (`git push origin feature-name`).
5. Open a pull request.

---

## Resources

tHE Following ressources may help you during the configuration of different aspects of this solution:

- **VirusTotal** - https://documentation.wazuh.com/current/proof-of-concept-guide/detect-remove-malware-virustotal.html
- **Nmap/Chatgpt** - https://wazuh.com/blog/nmap-and-chatgpt-security-auditing/?fbclid=IwY2xjawGQrn9leHRuA2FlbQIxMAABHVBjCIFMQUj-yL_LemN1DL3kjdNQu-i5dT1x6DCZ_C6XBWKZULStNvnh9Q_aem_6mCpWvQziBX_rJEhjd2fSA

## Credits

NeoCarthago is developed and maintained by CS_IEE_ENICAR. We would like to acknowledge the following tools and libraries used in this project:

- **Wazuh** - For providing core monitoring and alerting capabilities.
- **VirusTotal** - For file and URL threat detection.
- Contributors: @username1, @username2

---

## Contact

For any inquiries or support, please reach out to us via:

- Email: enicarthage.ieee.cs@gmail.com
- GitHub Issues: [https://github.com/IEEE_CS_ENICAR/cyber-shield/issues](https://github.com/IEEE_CS_ENICAR/cyber-shield/issues)
