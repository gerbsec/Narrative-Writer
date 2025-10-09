#!/usr/bin/env python3
"""
Penetration Testing Narrative Generator

This tool helps generate comprehensive penetration testing narratives
for external and internal assessments. It guides through the testing
process and creates detailed reports with screenshot placeholders.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any


class PenTestNarrativeGenerator:
    def __init__(self):
        self.testing_company = ""
        self.client_company = ""
        self.test_type = ""
        self.selected_techniques = []
        self.narrative_blocks = self._load_narrative_blocks()
        
    def _load_narrative_blocks(self) -> Dict[str, Any]:
        """Load narrative blocks for different test types"""
        return {
            "external": {
                "osint": [
                    {
                        "title": "Company Information Gathering",
                        "question": "Did you perform OSINT research using search engines, company websites, and public databases?",
                        "content": "{testing_company} initiated the assessment by conducting open-source intelligence (OSINT) gathering on {client_company}. This phase involved collecting publicly available information about the organization, including employee details, technology stack, infrastructure, and potential attack vectors. {testing_company} utilized various OSINT techniques including search engine queries, social media analysis, and public database searches to build a comprehensive profile of {client_company}'s digital footprint.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: OSINT Research Results]",
                            "caption": "Screenshot showing OSINT research findings including company information, employee details, and technology stack discovered through public sources."
                        }
                    },
                    {
                        "title": "LinkedIn and Social Media Reconnaissance",
                        "question": "Did you research employees on LinkedIn and social media platforms?",
                        "content": "{testing_company} conducted targeted reconnaissance on {client_company} employees through LinkedIn and other social media platforms. This research identified key personnel, organizational structure, and potential social engineering targets. {testing_company} analyzed employee profiles, job descriptions, and company updates to understand the organization's culture and identify potential attack vectors.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: LinkedIn Research]",
                            "caption": "Screenshot of LinkedIn search results showing {client_company} employee profiles and organizational structure."
                        }
                    },
                    {
                        "title": "Email Address Enumeration",
                        "question": "Did you use tools like theHarvester to find employee email addresses?",
                        "content": "{testing_company} performed email address enumeration to identify potential targets for social engineering attacks and credential stuffing. This process involved searching public sources, company websites, and social media platforms for email patterns and employee information. {testing_company} compiled a comprehensive list of email addresses following {client_company}'s naming conventions.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Email Enumeration]",
                            "caption": "Command: theHarvester -d {client_company}.com -b google - Screenshot showing discovered email addresses and employee information."
                        }
                    },
                    {
                        "title": "Technology Stack Identification",
                        "question": "Did you identify technologies and frameworks used by analyzing job postings and documentation?",
                        "content": "{testing_company} conducted technology stack identification to understand {client_company}'s infrastructure and potential attack vectors. This process involved analyzing job postings, social media posts, and public documentation to identify technologies, frameworks, and services in use. {testing_company} documented the technology stack to inform subsequent testing phases.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Technology Stack]",
                            "caption": "Screenshot showing identified technologies, frameworks, and infrastructure components used by {client_company}."
                        }
                    }
                ],
                "dns": [
                    {
                        "title": "DNS Enumeration",
                        "question": "Did you use dig, nslookup, or similar tools to query DNS records (A, AAAA, MX, NS, TXT)?",
                        "content": "{testing_company} performed comprehensive DNS enumeration against {client_company}'s infrastructure to identify all associated domains and subdomains. This process involved querying various DNS records including A, AAAA, MX, NS, TXT, and CNAME records. {testing_company} utilized multiple DNS enumeration techniques including zone transfers, reverse DNS lookups, and subdomain brute-forcing to map the complete attack surface.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: DNS Enumeration Results]",
                            "caption": "Command: dig @8.8.8.8 {client_company}.com ANY - Screenshot showing DNS enumeration results including discovered subdomains and DNS records."
                        }
                    },
                    {
                        "title": "Subdomain Discovery",
                        "question": "Did you use tools like subfinder, amass, or sublist3r to discover subdomains?",
                        "content": "{testing_company} conducted extensive subdomain discovery to identify all publicly accessible endpoints associated with {client_company}. This process utilized multiple techniques including certificate transparency logs, search engine queries, and automated subdomain enumeration tools. {testing_company} identified numerous subdomains that expanded the attack surface and revealed additional services and applications.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Subdomain Discovery]",
                            "caption": "Command: subfinder -d {client_company}.com - Screenshot showing discovered subdomains and associated services."
                        }
                    },
                    {
                        "title": "Certificate Transparency Logs",
                        "question": "Did you search crt.sh or other CT logs for SSL certificates and subdomains?",
                        "content": "{testing_company} searched certificate transparency logs to identify additional subdomains and domains associated with {client_company}. This technique revealed subdomains that may not be publicly advertised but have valid SSL certificates. {testing_company} utilized multiple CT log sources to ensure comprehensive coverage of certificate-issued domains.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Certificate Transparency]",
                            "caption": "Command: curl -s 'https://crt.sh/?q={client_company}.com&output=json' - Screenshot showing certificate transparency log results."
                        }
                    },
                    {
                        "title": "DNS Zone Transfer Attempts",
                        "question": "Did you attempt DNS zone transfers using dig AXFR or similar commands?",
                        "content": "{testing_company} attempted DNS zone transfers against {client_company}'s DNS servers to identify all records within the domain. While zone transfers are typically restricted, {testing_company} tested multiple DNS servers and techniques to identify any misconfigured servers that might allow unauthorized zone transfers.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Zone Transfer Attempt]",
                            "caption": "Command: dig @{dns_server} {client_company}.com AXFR - Screenshot showing zone transfer attempt results."
                        }
                    }
                ],
                "web_app": [
                    {
                        "title": "Web Application Discovery",
                        "question": "Did you use nmap, gobuster, or similar tools to discover web applications and directories?",
                        "content": "{testing_company} identified and catalogued all web applications within {client_company}'s scope. This process involved port scanning, service enumeration, and web application fingerprinting. {testing_company} documented the technology stack, frameworks, and potential vulnerabilities for each discovered application. The assessment covered both primary websites and discovered subdomain applications.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Web Application Discovery]",
                            "caption": "Command: nmap -sV -p 80,443,8080,8443 {target} - Screenshot showing discovered web services and their versions."
                        }
                    },
                    {
                        "title": "Cross-Site Scripting (XSS) Testing",
                        "question": "Did you test for XSS vulnerabilities using payloads like <script>alert(1)</script>?",
                        "content": "{testing_company} conducted comprehensive Cross-Site Scripting (XSS) testing across all identified web applications. This testing included reflected, stored, and DOM-based XSS assessments. {testing_company} utilized both automated scanning tools and manual testing techniques to identify input validation weaknesses. Multiple payloads were tested to determine the extent of XSS vulnerabilities and their potential impact.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: XSS Vulnerability]",
                            "caption": "Screenshot showing XSS payload execution demonstrating the vulnerability and its impact on user sessions."
                        }
                    },
                    {
                        "title": "SQL Injection Testing",
                        "question": "Did you test for SQL injection using tools like sqlmap or manual payloads like ' OR '1'='1?",
                        "content": "{testing_company} performed thorough SQL injection testing across all web applications and database interfaces. This assessment included union-based, boolean-based, and time-based blind SQL injection techniques. {testing_company} tested various input parameters including forms, URL parameters, and HTTP headers to identify database interaction vulnerabilities.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: SQL Injection]",
                            "caption": "Command: sqlmap -u '{target_url}' --batch - Screenshot showing SQL injection detection and database enumeration results."
                        }
                    },
                    {
                        "title": "Authentication Bypass Testing",
                        "question": "Did you test for authentication bypass vulnerabilities?",
                        "content": "{testing_company} conducted authentication bypass testing to identify weaknesses in login mechanisms and session management. This testing included SQL injection in login forms, session fixation, weak session tokens, and direct object references. {testing_company} tested various bypass techniques to determine the security of authentication systems.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Authentication Bypass]",
                            "caption": "Screenshot demonstrating successful authentication bypass and unauthorized access to protected resources."
                        }
                    },
                    {
                        "title": "Directory Traversal Testing",
                        "question": "Did you test for directory traversal vulnerabilities?",
                        "content": "{testing_company} performed directory traversal testing to identify file system access vulnerabilities. This testing involved attempting to access files outside the web root directory using various traversal techniques. {testing_company} tested multiple payloads and encoding methods to bypass input validation and access sensitive system files.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Directory Traversal]",
                            "caption": "Command: curl '{target}/file.php?file=../../../etc/passwd' - Screenshot showing successful directory traversal and file access."
                        }
                    },
                    {
                        "title": "File Upload Testing",
                        "question": "Did you test for file upload vulnerabilities?",
                        "content": "{testing_company} conducted file upload testing to identify weaknesses in file handling mechanisms. This testing included uploading malicious files, bypassing file type restrictions, and testing for remote code execution through uploaded files. {testing_company} tested various file types and upload techniques to identify potential security issues.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: File Upload]",
                            "caption": "Screenshot showing successful malicious file upload and potential code execution."
                        }
                    },
                    {
                        "title": "Cross-Site Request Forgery (CSRF) Testing",
                        "question": "Did you test for CSRF vulnerabilities?",
                        "content": "{testing_company} performed Cross-Site Request Forgery (CSRF) testing to identify state-changing operations that lack proper CSRF protection. This testing involved creating malicious requests that could be executed by authenticated users without their knowledge. {testing_company} tested various CSRF techniques and payloads to identify vulnerable operations.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: CSRF Vulnerability]",
                            "caption": "Screenshot showing CSRF proof-of-concept demonstrating unauthorized state changes."
                        }
                    },
                    {
                        "title": "Server-Side Request Forgery (SSRF) Testing",
                        "question": "Did you test for SSRF vulnerabilities?",
                        "content": "{testing_company} conducted Server-Side Request Forgery (SSRF) testing to identify applications that make requests to external resources based on user input. This testing involved attempting to access internal services, cloud metadata endpoints, and external resources. {testing_company} tested various SSRF techniques to identify potential security issues.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: SSRF Vulnerability]",
                            "caption": "Screenshot showing SSRF proof-of-concept accessing internal services or cloud metadata."
                        }
                    },
                    {
                        "title": "XML External Entity (XXE) Testing",
                        "question": "Did you test for XXE vulnerabilities?",
                        "content": "{testing_company} performed XML External Entity (XXE) testing to identify applications that process XML input without proper validation. This testing involved attempting to read local files, perform SSRF attacks, and cause denial of service through XML processing. {testing_company} tested various XXE payloads and techniques to identify potential vulnerabilities.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: XXE Vulnerability]",
                            "caption": "Screenshot showing XXE proof-of-concept demonstrating file access or SSRF capabilities."
                        }
                    },
                    {
                        "title": "Insecure Direct Object References",
                        "question": "Did you test for insecure direct object references?",
                        "content": "{testing_company} tested for insecure direct object references by attempting to access resources using predictable identifiers. This testing involved manipulating URLs, form parameters, and API endpoints to access unauthorized resources. {testing_company} tested various enumeration techniques to identify accessible resources and potential data exposure.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: IDOR Vulnerability]",
                            "caption": "Screenshot showing successful access to unauthorized resources through direct object reference manipulation."
                        }
                    }
                ],
                "network": [
                    {
                        "title": "Port Scanning and Service Enumeration",
                        "question": "Did you perform port scanning and service enumeration?",
                        "content": "{testing_company} conducted comprehensive port scanning against {client_company}'s external infrastructure to identify open ports and running services. This process utilized both TCP and UDP scanning techniques to ensure complete coverage. {testing_company} performed service enumeration on discovered ports to identify software versions and potential vulnerabilities.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Port Scan Results]",
                            "caption": "Command: nmap -sS -sV -O {target_range} - Screenshot showing port scan results with discovered services and versions."
                        }
                    },
                    {
                        "title": "Banner Grabbing and Service Fingerprinting",
                        "question": "Did you perform banner grabbing and service fingerprinting?",
                        "content": "{testing_company} performed banner grabbing and service fingerprinting on all discovered services to identify software versions and configurations. This process involved connecting to services and analyzing response headers and banners to determine the technology stack and potential vulnerabilities. {testing_company} documented all discovered services and their versions for further analysis.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Banner Grabbing]",
                            "caption": "Command: nc -nv {target} {port} - Screenshot showing service banners and version information."
                        }
                    },
                    {
                        "title": "SSL/TLS Configuration Analysis",
                        "question": "Did you analyze SSL/TLS configurations?",
                        "content": "{testing_company} conducted comprehensive SSL/TLS configuration analysis on all HTTPS services to identify cryptographic weaknesses and misconfigurations. This testing included cipher suite analysis, certificate validation, and protocol version testing. {testing_company} identified various SSL/TLS issues that could impact the security of encrypted communications.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: SSL Analysis]",
                            "caption": "Command: sslscan {target}:443 - Screenshot showing SSL/TLS configuration analysis results."
                        }
                    },
                    {
                        "title": "Email Server Testing",
                        "question": "Did you test email servers and configurations?",
                        "content": "{testing_company} tested email servers and configurations to identify potential security issues and information disclosure. This testing included SMTP enumeration, email spoofing tests, and configuration analysis. {testing_company} identified various email-related security issues that could be exploited for social engineering or information gathering.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Email Server Testing]",
                            "caption": "Command: smtp-user-enum -M VRFY -U users.txt -t {mail_server} - Screenshot showing email server enumeration results."
                        }
                    }
                ],
                "vulnerability_assessment": [
                    {
                        "title": "Nessus Vulnerability Scanning",
                        "question": "Did you perform Nessus vulnerability scanning against the target infrastructure?",
                        "content": "{testing_company} conducted comprehensive Nessus vulnerability scanning against {client_company}'s external infrastructure to identify known security vulnerabilities. This scanning covered network services, web applications, and system configurations. {testing_company} analyzed scan results to identify high-priority vulnerabilities and potential attack vectors for further exploitation.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Nessus Scan Results]",
                            "caption": "Screenshot showing Nessus vulnerability scan results with identified CVEs and risk ratings."
                        }
                    },
                    {
                        "title": "Burp Suite Web Application Scanning",
                        "question": "Did you perform Burp Suite automated scanning of web applications?",
                        "content": "{testing_company} utilized Burp Suite Professional to perform automated web application vulnerability scanning against {client_company}'s web applications. This scanning identified various web application vulnerabilities including injection flaws, authentication bypasses, and configuration issues. {testing_company} analyzed scan results and performed manual verification of identified issues.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Burp Suite Scan]",
                            "caption": "Screenshot showing Burp Suite scan results with identified web application vulnerabilities."
                        }
                    },
                    {
                        "title": "Manual Vulnerability Verification",
                        "question": "Did you manually verify and exploit identified vulnerabilities?",
                        "content": "{testing_company} performed manual verification and exploitation of all identified vulnerabilities to confirm their existence and assess their actual impact. This process involved reproducing vulnerabilities, testing exploitability, and determining the business impact. {testing_company} provided detailed proof-of-concept demonstrations for all confirmed vulnerabilities.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Manual Exploitation]",
                            "caption": "Screenshot showing manual vulnerability exploitation and proof-of-concept demonstration."
                        }
                    },
                    {
                        "title": "CVE Exploit Enumeration and Testing",
                        "question": "Did you enumerate and test CVE exploits against discovered services?",
                        "content": "{testing_company} performed CVE enumeration and exploit testing against all discovered services and applications within {client_company}'s scope. This process involved identifying known vulnerabilities for discovered software versions and testing available exploits. {testing_company} documented all exploitable CVEs and their potential impact on the organization's security posture.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: CVE Exploitation]",
                            "caption": "Command: searchsploit {service_name} {version} - Screenshot showing CVE enumeration and successful exploit execution."
                        }
                    }
                ],
                "credential_testing": [
                    {
                        "title": "Default Credential Testing",
                        "question": "Did you test for default credentials on discovered services?",
                        "content": "{testing_company} conducted default credential testing against all discovered services and applications within {client_company}'s infrastructure. This testing involved attempting to authenticate using common default usernames and passwords for various services including web applications, network devices, and management interfaces. {testing_company} documented any successful default credential authentications.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Default Credential Success]",
                            "caption": "Screenshot showing successful authentication using default credentials on a discovered service."
                        }
                    },
                    {
                        "title": "Leaked Credential Testing",
                        "question": "Did you test for leaked credentials from data breaches?",
                        "content": "{testing_company} performed leaked credential testing by searching for {client_company} credentials in known data breach databases and paste sites. This testing involved checking employee email addresses and usernames against compromised credential databases. {testing_company} tested any discovered credentials against {client_company}'s systems to identify potential account compromises.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Leaked Credentials]",
                            "caption": "Command: dehashed -q '{client_company}.com' - Screenshot showing discovered leaked credentials and successful authentication attempts."
                        }
                    },
                    {
                        "title": "Two-Factor Authentication (2FA) Bypass Testing",
                        "question": "Did you test for 2FA bypass vulnerabilities?",
                        "content": "{testing_company} conducted two-factor authentication (2FA) bypass testing to identify weaknesses in multi-factor authentication implementations. This testing included session fixation attacks, response manipulation, and social engineering techniques. {testing_company} tested various 2FA bypass methods to determine the effectiveness of multi-factor authentication controls.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: 2FA Bypass]",
                            "caption": "Screenshot demonstrating successful 2FA bypass and unauthorized access to protected accounts."
                        }
                    },
                    {
                        "title": "Password Policy and Brute Force Testing",
                        "question": "Did you test password policies and perform brute force attacks?",
                        "content": "{testing_company} tested password policies and performed controlled brute force attacks against {client_company}'s authentication systems. This testing involved analyzing password complexity requirements, account lockout policies, and rate limiting mechanisms. {testing_company} documented any weak password policies or successful brute force attacks.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Brute Force Attack]",
                            "caption": "Command: hydra -L users.txt -P passwords.txt {target} ssh - Screenshot showing successful brute force attack results."
                        }
                    },
                    {
                        "title": "Two-Factor Authentication (2FA) Enabled Checking",
                        "question": "Did you check if 2FA is enabled on discovered services and applications?",
                        "content": "{testing_company} performed comprehensive checking to determine if two-factor authentication (2FA) is enabled on {client_company}'s services and applications. This testing involved attempting to authenticate to various services and analyzing login flows to identify which systems have 2FA protection enabled. {testing_company} documented the 2FA implementation status across all discovered services.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: 2FA Status Check]",
                            "caption": "Screenshot showing 2FA status check results indicating which services have 2FA enabled or disabled."
                        }
                    }
                ]
            },
            "internal": {
                "network_discovery": [
                    {
                        "title": "Network Discovery and Host Enumeration",
                        "question": "Did you perform network discovery and host enumeration?",
                        "content": "{testing_company} initiated the internal assessment by performing comprehensive network discovery to map {client_company}'s internal infrastructure. This process involved identifying active hosts, network segments, and network topology. {testing_company} utilized various discovery techniques including ARP scanning, ping sweeps, and network service enumeration to build a complete picture of the internal environment.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Network Discovery]",
                            "caption": "Command: nmap -sn {network_range} - Screenshot showing discovered hosts and network topology."
                        }
                    },
                    {
                        "title": "Network Segmentation Analysis",
                        "question": "Did you analyze network segmentation and VLANs?",
                        "content": "{testing_company} analyzed network segmentation to identify VLANs, subnets, and network boundaries within {client_company}'s infrastructure. This analysis involved mapping network topology, identifying routing configurations, and testing for potential segmentation bypasses. {testing_company} documented the network architecture and identified potential security issues.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Network Segmentation]",
                            "caption": "Command: nmap -sn --script broadcast-dhcp-discover - Screenshot showing network segmentation analysis and VLAN discovery."
                        }
                    },
                    {
                        "title": "Active Directory Enumeration",
                        "question": "Did you enumerate Active Directory and domain information using ldapsearch, PowerView, or similar tools?",
                        "content": "{testing_company} performed comprehensive Active Directory enumeration to identify domain structure, users, groups, and policies within {client_company}'s environment. This process involved querying domain controllers, enumerating user accounts, and analyzing group memberships. {testing_company} identified potential attack vectors and privilege escalation opportunities.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: AD Enumeration]",
                            "caption": "Command: ldapsearch -x -H ldap://{dc} -b 'DC={domain},DC=com' - Screenshot showing Active Directory enumeration results."
                        }
                    },
                    {
                        "title": "BloodHound Active Directory Analysis",
                        "question": "Did you run BloodHound to analyze Active Directory attack paths and privilege escalation opportunities?",
                        "content": "{testing_company} utilized BloodHound to perform comprehensive Active Directory analysis and identify attack paths within {client_company}'s environment. This testing involved collecting Active Directory data, analyzing relationships between users and systems, and identifying potential privilege escalation paths. {testing_company} documented discovered attack paths and high-value targets.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: BloodHound Analysis]",
                            "caption": "Command: bloodhound-python -d {domain} -u {user} -p {password} -gc {dc} -c all - Screenshot showing BloodHound analysis results and attack paths."
                        }
                    },
                    {
                        "title": "PingCastle Active Directory Assessment",
                        "question": "Did you run PingCastle to assess Active Directory security posture and identify vulnerabilities?",
                        "content": "{testing_company} utilized PingCastle to perform comprehensive Active Directory security assessment within {client_company}'s environment. This testing involved analyzing Active Directory configuration, identifying security misconfigurations, and assessing the overall security posture. {testing_company} documented discovered vulnerabilities and security recommendations.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: PingCastle Assessment]",
                            "caption": "Command: pingcastle.exe --server {dc} --user {user} --password {password} - Screenshot showing PingCastle assessment results and security findings."
                        }
                    }
                ],
                "privilege_escalation": [
                    {
                        "title": "Local Privilege Escalation",
                        "question": "Did you attempt local privilege escalation?",
                        "content": "{testing_company} conducted local privilege escalation testing on compromised systems within {client_company}'s environment. This assessment involved identifying misconfigurations, weak permissions, and vulnerable services that could be exploited to gain elevated privileges. {testing_company} tested various escalation vectors including kernel exploits, service misconfigurations, and credential harvesting techniques.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Privilege Escalation]",
                            "caption": "Screenshot showing successful privilege escalation and access to administrative privileges."
                        }
                    },
                    {
                        "title": "Windows Privilege Escalation",
                        "question": "Did you attempt Windows privilege escalation?",
                        "content": "{testing_company} performed Windows-specific privilege escalation testing to identify misconfigurations and vulnerabilities that could lead to elevated privileges. This testing included service enumeration, registry analysis, and kernel exploit testing. {testing_company} identified various Windows-specific security issues and potential escalation paths.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Windows Privilege Escalation]",
                            "caption": "Command: winPEAS.bat - Screenshot showing Windows privilege escalation enumeration and successful escalation."
                        }
                    },
                    {
                        "title": "Linux Privilege Escalation",
                        "question": "Did you attempt Linux privilege escalation?",
                        "content": "{testing_company} conducted Linux-specific privilege escalation testing to identify system misconfigurations and vulnerabilities. This testing included SUID/SGID analysis, cron job enumeration, and kernel exploit testing. {testing_company} identified various Linux-specific security issues and potential escalation vectors.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Linux Privilege Escalation]",
                            "caption": "Command: linPEAS.sh - Screenshot showing Linux privilege escalation enumeration and successful escalation."
                        }
                    }
                ],
                "lateral_movement": [
                    {
                        "title": "Lateral Movement and Credential Harvesting",
                        "question": "Did you perform lateral movement and credential harvesting?",
                        "content": "{testing_company} performed lateral movement testing to demonstrate how an attacker could traverse {client_company}'s network after initial compromise. This process involved credential harvesting, pass-the-hash attacks, and network service exploitation. {testing_company} demonstrated the potential for attackers to move between systems and escalate their access across the network.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Lateral Movement]",
                            "caption": "Command: psexec.py {domain}/{user}:{password}@{target} - Screenshot showing successful lateral movement to additional systems."
                        }
                    },
                    {
                        "title": "Pass-the-Hash Attacks",
                        "question": "Did you perform pass-the-hash attacks?",
                        "content": "{testing_company} conducted pass-the-hash attacks to demonstrate how compromised credentials could be used to access additional systems within {client_company}'s network. This testing involved using harvested password hashes to authenticate to remote systems without cracking the actual passwords. {testing_company} demonstrated the effectiveness of this attack technique across the network.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Pass-the-Hash]",
                            "caption": "Command: pth-winexe -U {domain}/{user}%{hash} //{target} cmd - Screenshot showing successful pass-the-hash attack."
                        }
                    },
                    {
                        "title": "Kerberos Attacks",
                        "question": "Did you perform Kerberos-based attacks including golden ticket and silver ticket attacks?",
                        "content": "{testing_company} performed Kerberos-based attacks including golden ticket and silver ticket attacks to demonstrate advanced persistence techniques within {client_company}'s Active Directory environment. This testing involved exploiting Kerberos authentication mechanisms to maintain access and escalate privileges across the domain.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Kerberos Attack]",
                            "caption": "Command: ticketer.py -nthash {hash} -domain-sid {sid} -domain {domain} krbtgt - Screenshot showing Kerberos ticket generation and usage."
                        }
                    },
                    {
                        "title": "Kerberoasting Attacks",
                        "question": "Did you perform Kerberoasting attacks to crack service account passwords?",
                        "content": "{testing_company} performed Kerberoasting attacks to extract and crack service account password hashes within {client_company}'s Active Directory environment. This testing involved requesting service tickets for service accounts and extracting password hashes for offline cracking. {testing_company} documented successful Kerberoasting attacks and cracked service account passwords.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Kerberoasting]",
                            "caption": "Command: GetUserSPNs.py -request -dc-ip {dc_ip} {domain}/{user}:{password} - Screenshot showing Kerberoasting attack and extracted password hashes."
                        }
                    },
                    {
                        "title": "ASREPRoasting Attacks",
                        "question": "Did you perform ASREPRoasting attacks to crack user account passwords?",
                        "content": "{testing_company} performed ASREPRoasting attacks to extract and crack user account password hashes within {client_company}'s Active Directory environment. This testing involved identifying users with Kerberos pre-authentication disabled and requesting AS-REP responses for offline cracking. {testing_company} documented successful ASREPRoasting attacks and cracked user passwords.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: ASREPRoasting]",
                            "caption": "Command: GetNPUsers.py {domain}/{user}:{password} -dc-ip {dc_ip} - Screenshot showing ASREPRoasting attack and extracted password hashes."
                        }
                    },
                    {
                        "title": "SMB and RPC Enumeration",
                        "question": "Did you enumerate SMB and RPC services using smbclient, rpcclient, or similar tools?",
                        "content": "{testing_company} conducted SMB and RPC enumeration to identify file shares, user accounts, and system information within {client_company}'s network. This testing involved querying SMB shares, enumerating user accounts, and identifying potential attack vectors. {testing_company} documented discovered shares and user information for further exploitation.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: SMB Enumeration]",
                            "caption": "Command: smbclient -L //{target} -N - Screenshot showing SMB share enumeration and user account discovery."
                        }
                    },
                    {
                        "title": "SMB Signing Check",
                        "question": "Did you check if SMB signing is enabled on discovered systems?",
                        "content": "{testing_company} performed SMB signing checks to determine if SMB message signing is enabled on discovered systems within {client_company}'s network. This testing involved using tools like nmap and smbclient to check SMB signing requirements. {testing_company} documented systems with SMB signing disabled, which could be vulnerable to NTLM relay attacks.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: SMB Signing Check]",
                            "caption": "Command: nmap --script smb-security-mode.nse {target} - Screenshot showing SMB signing status on discovered systems."
                        }
                    },
                    {
                        "title": "Responder and LLMNR/NBT-NS Poisoning",
                        "question": "Did you run Responder to capture NTLM hashes through LLMNR/NBT-NS poisoning?",
                        "content": "{testing_company} deployed Responder to perform LLMNR and NBT-NS poisoning attacks within {client_company}'s network. This testing involved capturing NTLM authentication attempts and hashes when systems attempted to resolve non-existent hostnames. {testing_company} documented captured hashes and potential credential compromise opportunities.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Responder Capture]",
                            "caption": "Command: responder -I eth0 -rdwv - Screenshot showing Responder capturing NTLM hashes through LLMNR/NBT-NS poisoning."
                        }
                    },
                    {
                        "title": "mitm6 and IPv6 DNS Takeover",
                        "question": "Did you perform mitm6 attacks to capture credentials through IPv6 DNS takeover?",
                        "content": "{testing_company} conducted mitm6 attacks to exploit IPv6 DNS takeover vulnerabilities within {client_company}'s network. This testing involved setting up rogue IPv6 DNS servers to capture authentication attempts and NTLM hashes. {testing_company} documented successful credential captures and potential lateral movement opportunities.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: mitm6 Attack]",
                            "caption": "Command: mitm6 -d {domain} -i eth0 - Screenshot showing mitm6 successfully capturing credentials through IPv6 DNS takeover."
                        }
                    },
                    {
                        "title": "NTLM Relay Attacks",
                        "question": "Did you perform NTLM relay attacks using ntlmrelayx or similar tools?",
                        "content": "{testing_company} performed NTLM relay attacks to demonstrate how captured authentication attempts could be relayed to other systems within {client_company}'s network. This testing involved using ntlmrelayx to relay NTLM authentication to SMB, LDAP, and HTTP services. {testing_company} documented successful relay attacks and potential privilege escalation opportunities.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: NTLM Relay]",
                            "caption": "Command: ntlmrelayx.py -tf targets.txt -smb2support - Screenshot showing successful NTLM relay attack and system compromise."
                        }
                    }
                ],
                "persistence": [
                    {
                        "title": "Persistence Mechanism Testing",
                        "question": "Did you test persistence mechanisms?",
                        "content": "{testing_company} tested various persistence mechanisms to demonstrate how attackers could maintain access to {client_company}'s systems after initial compromise. This testing included scheduled tasks, service installation, registry modifications, and startup programs. {testing_company} identified potential persistence vectors and demonstrated their effectiveness.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Persistence]",
                            "caption": "Screenshot showing successful persistence mechanism installation and execution."
                        }
                    },
                    {
                        "title": "Backdoor Installation",
                        "question": "Did you test backdoor installation techniques?",
                        "content": "{testing_company} tested backdoor installation techniques to demonstrate how attackers could maintain persistent access to {client_company}'s systems. This testing included web shells, reverse shells, and custom backdoors. {testing_company} demonstrated various backdoor techniques and their detection evasion capabilities.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Backdoor]",
                            "caption": "Screenshot showing successful backdoor installation and remote access demonstration."
                        }
                    }
                ],
                "data_exfiltration": [
                    {
                        "title": "Data Exfiltration Testing",
                        "question": "Did you test data exfiltration using tools like SCP, FTP, or HTTP POST requests?",
                        "content": "{testing_company} conducted data exfiltration testing to demonstrate how attackers could steal sensitive information from {client_company}'s systems. This testing included file transfer techniques, data encoding, and network tunneling. {testing_company} demonstrated various exfiltration methods and their detection evasion capabilities.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Data Exfiltration]",
                            "caption": "Screenshot showing successful data exfiltration and file transfer demonstration."
                        }
                    },
                    {
                        "title": "Sensitive Data Discovery",
                        "question": "Did you search for passwords, certificates, and confidential files on compromised systems?",
                        "content": "{testing_company} searched for sensitive data including passwords, certificates, and confidential documents on compromised systems within {client_company}'s environment. This testing involved file system searches, registry analysis, and memory dumps. {testing_company} identified various types of sensitive information that could be valuable to attackers.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Sensitive Data]",
                            "caption": "Screenshot showing discovered sensitive data including passwords and certificates."
                        }
                    }
                ],
                "credential_harvesting": [
                    {
                        "title": "Credential Harvesting and Dumping",
                        "question": "Did you harvest credentials using tools like mimikatz, secretsdump, or hashdump?",
                        "content": "{testing_company} performed credential harvesting and dumping on compromised systems within {client_company}'s environment. This testing involved extracting password hashes, plaintext credentials, and authentication tokens from memory, registry, and file systems. {testing_company} utilized various credential harvesting techniques to demonstrate the potential for credential theft.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Credential Harvesting]",
                            "caption": "Command: mimikatz.exe 'sekurlsa::logonpasswords' - Screenshot showing harvested credentials and password hashes."
                        }
                    },
                    {
                        "title": "Impacket Credential Dumping",
                        "question": "Did you use impacket tools like secretsdump.py to dump credentials from domain controllers?",
                        "content": "{testing_company} utilized impacket tools to perform credential dumping from domain controllers and other systems within {client_company}'s environment. This testing involved using secretsdump.py to extract password hashes, cached credentials, and domain secrets from compromised systems. {testing_company} documented all extracted credentials for further exploitation.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Impacket Dumping]",
                            "caption": "Command: secretsdump.py {domain}/{user}:{password}@{dc} - Screenshot showing impacket credential dumping results."
                        }
                    },
                    {
                        "title": "CrackMapExec (nxc) Credential Dumping",
                        "question": "Did you use CrackMapExec (nxc) to dump credentials and perform lateral movement?",
                        "content": "{testing_company} utilized CrackMapExec (nxc) to perform credential dumping and lateral movement testing within {client_company}'s environment. This testing involved using nxc to dump credentials, execute commands, and perform various attack techniques across the network. {testing_company} documented successful credential dumps and lateral movement opportunities.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: nxc Dumping]",
                            "caption": "Command: nxc smb {target} -u {user} -p {password} --sam - Screenshot showing nxc credential dumping results."
                        }
                    },
                    {
                        "title": "PowerShell History and Credential Extraction",
                        "question": "Did you search PowerShell history files for credentials and sensitive information?",
                        "content": "{testing_company} searched PowerShell history files and command logs for credentials and sensitive information within {client_company}'s environment. This testing involved examining PowerShell execution history, command logs, and script files to identify stored credentials, API keys, and other sensitive data. {testing_company} documented discovered credentials and sensitive information.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: PowerShell History]",
                            "caption": "Command: Get-Content $env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt - Screenshot showing PowerShell history with discovered credentials."
                        }
                    },
                    {
                        "title": "LSA and LSASS Memory Dumping",
                        "question": "Did you dump LSA secrets and LSASS memory for credential extraction?",
                        "content": "{testing_company} performed LSA secrets and LSASS memory dumping to extract credentials from compromised systems within {client_company}'s environment. This testing involved using tools like mimikatz, lsassy, and pypykatz to extract stored credentials, password hashes, and authentication tokens from system memory. {testing_company} documented all extracted credentials.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: LSA/LSASS Dump]",
                            "caption": "Command: mimikatz.exe 'lsadump::secrets' - Screenshot showing LSA secrets and LSASS memory dump results."
                        }
                    },
                    {
                        "title": "Keylogger and Credential Capture",
                        "question": "Did you deploy keyloggers or capture credentials through network sniffing?",
                        "content": "{testing_company} tested credential capture techniques including keyloggers and network sniffing to demonstrate how attackers could intercept user credentials within {client_company}'s environment. This testing involved deploying keylogging software and capturing network traffic to identify authentication credentials in transit.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Credential Capture]",
                            "caption": "Screenshot showing captured credentials through keylogging or network sniffing."
                        }
                    }
                ],
                "defense_evasion": [
                    {
                        "title": "Antivirus and EDR Evasion",
                        "question": "Did you test for antivirus and EDR evasion techniques?",
                        "content": "{testing_company} tested antivirus and Endpoint Detection and Response (EDR) evasion techniques to demonstrate how attackers could bypass security controls within {client_company}'s environment. This testing included payload obfuscation, process injection, and living-off-the-land techniques to avoid detection by security software.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: AV Evasion]",
                            "caption": "Screenshot showing successful antivirus evasion and payload execution."
                        }
                    },
                    {
                        "title": "Log Clearing and Artifact Removal",
                        "question": "Did you test log clearing and artifact removal techniques?",
                        "content": "{testing_company} tested log clearing and artifact removal techniques to demonstrate how attackers could cover their tracks within {client_company}'s environment. This testing included clearing event logs, deleting files, and modifying system artifacts to avoid forensic detection.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Log Clearing]",
                            "caption": "Command: wevtutil cl System - Screenshot showing successful log clearing and artifact removal."
                        }
                    }
                ],
                "adcs_vulnerabilities": [
                    {
                        "title": "Active Directory Certificate Services (ADCS) Vulnerability Assessment",
                        "question": "Did you test for ADCS vulnerabilities including ESC1-ESC8 attack techniques?",
                        "content": "{testing_company} performed comprehensive Active Directory Certificate Services (ADCS) vulnerability assessment within {client_company}'s environment. This testing involved identifying ADCS infrastructure, analyzing certificate templates, and testing for ESC1-ESC8 attack techniques. {testing_company} documented discovered ADCS vulnerabilities and potential privilege escalation opportunities.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: ADCS Assessment]",
                            "caption": "Command: certipy find -u {user} -p {password} -dc-ip {dc_ip} - Screenshot showing ADCS vulnerability assessment results."
                        }
                    },
                    {
                        "title": "ESC1 - Misconfigured Certificate Template",
                        "question": "Did you test for ESC1 vulnerabilities with misconfigured certificate templates?",
                        "content": "{testing_company} tested for ESC1 vulnerabilities involving misconfigured certificate templates that allow domain users to request certificates with domain admin privileges within {client_company}'s ADCS environment. This testing involved identifying vulnerable certificate templates and demonstrating privilege escalation through certificate enrollment.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: ESC1 Exploitation]",
                            "caption": "Command: certipy req -u {user} -p {password} -dc-ip {dc_ip} -ca {ca} -template {template} - Screenshot showing ESC1 exploitation and privilege escalation."
                        }
                    },
                    {
                        "title": "ESC2 - Certificate Template with Any Purpose EKU",
                        "question": "Did you test for ESC2 vulnerabilities with certificate templates allowing any purpose EKU?",
                        "content": "{testing_company} tested for ESC2 vulnerabilities involving certificate templates with Any Purpose EKU that can be used for authentication within {client_company}'s ADCS environment. This testing involved identifying vulnerable certificate templates and demonstrating authentication bypass through certificate enrollment.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: ESC2 Exploitation]",
                            "caption": "Screenshot showing ESC2 exploitation and authentication bypass through certificate enrollment."
                        }
                    },
                    {
                        "title": "ESC3 - Certificate Template with Certificate Request Agent EKU",
                        "question": "Did you test for ESC3 vulnerabilities with Certificate Request Agent EKU?",
                        "content": "{testing_company} tested for ESC3 vulnerabilities involving certificate templates with Certificate Request Agent EKU that can be used to request certificates on behalf of other users within {client_company}'s ADCS environment. This testing involved identifying vulnerable certificate templates and demonstrating privilege escalation through certificate enrollment.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: ESC3 Exploitation]",
                            "caption": "Screenshot showing ESC3 exploitation and privilege escalation through certificate enrollment."
                        }
                    },
                    {
                        "title": "ESC4 - Certificate Template with Vulnerable ACL",
                        "question": "Did you test for ESC4 vulnerabilities with certificate templates having vulnerable ACLs?",
                        "content": "{testing_company} tested for ESC4 vulnerabilities involving certificate templates with vulnerable Access Control Lists (ACLs) that allow unauthorized certificate enrollment within {client_company}'s ADCS environment. This testing involved identifying vulnerable certificate templates and demonstrating unauthorized certificate enrollment.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: ESC4 Exploitation]",
                            "caption": "Screenshot showing ESC4 exploitation and unauthorized certificate enrollment."
                        }
                    },
                    {
                        "title": "ESC5 - Vulnerable PKI Object ACL",
                        "question": "Did you test for ESC5 vulnerabilities with vulnerable PKI object ACLs?",
                        "content": "{testing_company} tested for ESC5 vulnerabilities involving vulnerable PKI object Access Control Lists (ACLs) that allow unauthorized modification of certificate templates within {client_company}'s ADCS environment. This testing involved identifying vulnerable PKI objects and demonstrating certificate template modification.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: ESC5 Exploitation]",
                            "caption": "Screenshot showing ESC5 exploitation and certificate template modification."
                        }
                    },
                    {
                        "title": "ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 Enabled",
                        "question": "Did you test for ESC6 vulnerabilities with EDITF_ATTRIBUTESUBJECTALTNAME2 enabled?",
                        "content": "{testing_company} tested for ESC6 vulnerabilities involving the EDITF_ATTRIBUTESUBJECTALTNAME2 flag being enabled on the Certificate Authority within {client_company}'s ADCS environment. This testing involved identifying the vulnerable configuration and demonstrating privilege escalation through certificate enrollment.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: ESC6 Exploitation]",
                            "caption": "Screenshot showing ESC6 exploitation and privilege escalation through certificate enrollment."
                        }
                    },
                    {
                        "title": "ESC7 - Vulnerable Certificate Authority ACL",
                        "question": "Did you test for ESC7 vulnerabilities with vulnerable Certificate Authority ACLs?",
                        "content": "{testing_company} tested for ESC7 vulnerabilities involving vulnerable Certificate Authority Access Control Lists (ACLs) that allow unauthorized certificate enrollment within {client_company}'s ADCS environment. This testing involved identifying vulnerable CA ACLs and demonstrating unauthorized certificate enrollment.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: ESC7 Exploitation]",
                            "caption": "Screenshot showing ESC7 exploitation and unauthorized certificate enrollment."
                        }
                    },
                    {
                        "title": "ESC8 - NTLM Relay to ADCS HTTP Endpoints",
                        "question": "Did you test for ESC8 vulnerabilities with NTLM relay to ADCS HTTP endpoints?",
                        "content": "{testing_company} tested for ESC8 vulnerabilities involving NTLM relay attacks to ADCS HTTP endpoints within {client_company}'s environment. This testing involved identifying ADCS HTTP endpoints and demonstrating privilege escalation through NTLM relay attacks.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: ESC8 Exploitation]",
                            "caption": "Command: ntlmrelayx.py -t http://{ca}/certsrv/certfnsh.asp - Screenshot showing ESC8 exploitation and privilege escalation."
                        }
                    }
                ],
                "internal_vulnerability_assessment": [
                    {
                        "title": "Internal Nessus Vulnerability Scanning",
                        "question": "Did you perform Nessus vulnerability scanning against internal infrastructure?",
                        "content": "{testing_company} conducted comprehensive Nessus vulnerability scanning against {client_company}'s internal infrastructure to identify known security vulnerabilities. This scanning covered internal network services, systems, and configurations. {testing_company} analyzed scan results to identify high-priority vulnerabilities and potential attack vectors for further exploitation.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Internal Nessus Scan]",
                            "caption": "Screenshot showing internal Nessus vulnerability scan results with identified CVEs and risk ratings."
                        }
                    },
                    {
                        "title": "Internal CVE Exploit Enumeration and Testing",
                        "question": "Did you enumerate and test CVE exploits against internal systems and services?",
                        "content": "{testing_company} performed CVE enumeration and exploit testing against all internal systems and services within {client_company}'s environment. This process involved identifying known vulnerabilities for discovered software versions and testing available exploits. {testing_company} documented all exploitable CVEs and their potential impact on the organization's internal security posture.",
                        "screenshot": {
                            "placeholder": "[SCREENSHOT: Internal CVE Exploitation]",
                            "caption": "Command: searchsploit {service_name} {version} - Screenshot showing internal CVE enumeration and successful exploit execution."
                        }
                    }
                ]
            }
        }
    
    def get_user_input(self):
        """Collect initial user input for the assessment"""
        print("=" * 60)
        print("PENETRATION TESTING NARRATIVE GENERATOR")
        print("=" * 60)
        print()
        
        # Get testing company
        self.testing_company = input("What company is performing the test? (e.g., {testing_company}): ").strip()
        if not self.testing_company:
            self.testing_company = "{testing_company}"
        
        # Get client company
        self.client_company = input("What company are you testing against? (Client name): ").strip()
        if not self.client_company:
            print("Error: Client company name is required!")
            return False
        
        # Get test type
        print("\nWhat type of assessment is this?")
        print("1. External only")
        print("2. Internal only") 
        print("3. Both external and internal")
        
        while True:
            choice = input("Enter your choice (1-3): ").strip()
            if choice == "1":
                self.test_type = "external"
                break
            elif choice == "2":
                self.test_type = "internal"
                break
            elif choice == "3":
                self.test_type = "both"
                break
            else:
                print("Invalid choice. Please enter 1, 2, or 3.")
        
        return True
    
    def select_techniques(self):
        """Allow user to select which techniques were performed"""
        print(f"\n{'='*60}")
        print(f"TECHNIQUE SELECTION FOR {self.test_type.upper()} ASSESSMENT")
        print(f"{'='*60}")
        print()
        
        if self.test_type in ["external", "both"]:
            print("EXTERNAL ASSESSMENT TECHNIQUES:")
            print("-" * 40)
            self._select_category_techniques("external")
        
        if self.test_type in ["internal", "both"]:
            print("\nINTERNAL ASSESSMENT TECHNIQUES:")
            print("-" * 40)
            self._select_category_techniques("internal")
    
    def _select_category_techniques(self, category: str):
        """Select techniques for a specific category"""
        for category_name, techniques in self.narrative_blocks[category].items():
            print(f"\n{category_name.upper().replace('_', ' ')}:")
            for technique in techniques:
                while True:
                    response = input(f"  {technique['question']} (y/n): ").strip().lower()
                    if response in ['y', 'yes']:
                        self.selected_techniques.append({
                            'category': category,
                            'subcategory': category_name,
                            'technique': technique
                        })
                        break
                    elif response in ['n', 'no']:
                        break
                    else:
                        print("    Please enter 'y' for yes or 'n' for no.")
    
    def generate_narrative(self) -> str:
        """Generate the final narrative document"""
        narrative = []
        
        # Header
        narrative.append(f"# PENETRATION TESTING NARRATIVE")
        narrative.append(f"**Client:** {self.client_company}")
        narrative.append(f"**Testing Company:** {self.testing_company}")
        narrative.append(f"**Assessment Type:** {self.test_type.title()}")
        narrative.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d')}")
        narrative.append("")
        narrative.append("---")
        narrative.append("")
        
        # Assessment Introduction
        if self.test_type == "external":
            narrative.append("## EXTERNAL PENETRATION TESTING")
            narrative.append(f"An external penetration test simulates an attack from outside {self.client_company}'s network perimeter, testing the security of publicly accessible systems and services. This type of assessment is crucial for identifying vulnerabilities that could be exploited by external attackers without any prior access to the organization's internal network. External testing helps organizations understand their attack surface from an outsider's perspective and identify potential entry points that malicious actors could exploit.")
            narrative.append("")
        elif self.test_type == "internal":
            narrative.append("## INTERNAL PENETRATION TESTING")
            narrative.append(f"An internal penetration test simulates an attack from within {self.client_company}'s network perimeter, testing the security of internal systems and the organization's ability to detect and respond to insider threats. This type of assessment is essential for identifying vulnerabilities that could be exploited by malicious insiders or attackers who have already gained initial access to the network. Internal testing helps organizations understand their security posture from an insider's perspective and identify potential lateral movement paths and privilege escalation opportunities.")
            narrative.append("")
        else:  # both
            narrative.append("## COMBINED PENETRATION TESTING")
            narrative.append(f"This assessment combines both external and internal penetration testing methodologies to provide a comprehensive evaluation of {self.client_company}'s security posture. External testing simulates attacks from outside the network perimeter, while internal testing simulates attacks from within the network. This combined approach provides a complete picture of the organization's security vulnerabilities and helps identify potential attack paths from initial compromise through to data exfiltration.")
            narrative.append("")
        
        # Methodology
        narrative.append("## METHODOLOGY")
        narrative.append(f"{self.testing_company} followed industry-standard penetration testing methodologies including OWASP Testing Guide, NIST SP 800-115, and PTES (Penetration Testing Execution Standard). The assessment was conducted in phases to ensure comprehensive coverage of all potential attack vectors. Each phase built upon the previous findings to create a realistic attack scenario that demonstrates the potential impact of identified vulnerabilities.")
        narrative.append("")
        
        # Detailed findings
        narrative.append("")
        
        # Group techniques by category
        categories = {}
        for technique in self.selected_techniques:
            cat = technique['category']
            subcat = technique['subcategory']
            if cat not in categories:
                categories[cat] = {}
            if subcat not in categories[cat]:
                categories[cat][subcat] = []
            categories[cat][subcat].append(technique['technique'])
        
        # Generate content for each category
        for category, subcategories in categories.items():
            narrative.append(f"### {category.upper()} ASSESSMENT")
            narrative.append("")
            
            for subcategory, techniques in subcategories.items():
                narrative.append(f"#### {subcategory.replace('_', ' ').title()}")
                narrative.append("")
                
                for technique in techniques:
                    # Add technique content
                    content = technique['content'].format(
                        testing_company=self.testing_company,
                        client_company=self.client_company
                    )
                    narrative.append(content)
                    narrative.append("")
                    
                    # Add screenshot placeholder
                    if 'screenshot' in technique:
                        screenshot = technique['screenshot']
                        narrative.append(screenshot['placeholder'])
                        narrative.append("")
                        narrative.append(f"*{screenshot['caption']}*")
                        narrative.append("")
        
        # Conclusion
        narrative.append("## CONCLUSION")
        narrative.append(f"The comprehensive assessment conducted by {self.testing_company} against {self.client_company} revealed various security findings and provided valuable insights into the organization's security posture. The detailed methodology and findings presented in this narrative demonstrate the thoroughness of the assessment and provide a foundation for security improvements.")
        narrative.append("")
        narrative.append(f"{self.testing_company} recommends that {self.client_company} prioritize the remediation of identified vulnerabilities and implement the security recommendations provided in the detailed findings section of this report.")
        
        return "\n".join(narrative)
    
    def save_narrative(self, narrative: str):
        """Save the narrative to a file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"pen_test_narrative_{self.client_company.replace(' ', '_')}_{timestamp}.md"
        filepath = os.path.join(os.getcwd(), filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(narrative)
        
        print(f"\n{'='*60}")
        print(f"NARRATIVE SAVED SUCCESSFULLY!")
        print(f"File: {filename}")
        print(f"Location: {filepath}")
        print(f"{'='*60}")
    
    def run(self):
        """Main execution function"""
        if not self.get_user_input():
            return
        
        self.select_techniques()
        
        if not self.selected_techniques:
            print("\nNo techniques selected. Exiting.")
            return
        
        print(f"\nGenerating narrative for {self.client_company}...")
        narrative = self.generate_narrative()
        self.save_narrative(narrative)
        
        print(f"\nNarrative generation complete!")
        print(f"Selected {len(self.selected_techniques)} techniques")
        print(f"Assessment type: {self.test_type}")


def main():
    """Main entry point"""
    generator = PenTestNarrativeGenerator()
    generator.run()


if __name__ == "__main__":
    main()