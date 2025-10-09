# Penetration Testing Narrative Generator

A comprehensive Python tool for generating detailed penetration testing narratives for external and internal assessments.

## Features

- **Interactive Questionnaire**: Guides you through the assessment setup with clear, specific questions
- **Comprehensive Technique Coverage**: Covers 60+ techniques including OSINT, DNS enumeration, web application testing, vulnerability scanning, credential testing, privilege escalation, lateral movement, defense evasion, ADCS vulnerabilities, and advanced Active Directory attacks
- **Enhanced External Testing**: Includes Burp Suite scanning, Nessus scanning, leaked credential testing, 2FA bypass, default credential testing, and CVE exploitation
- **Advanced Internal Testing**: Includes BloodHound, PingCastle, Responder, mitm6, NTLM relay, SMB signing checks, Kerberoasting, ASREPRoasting, impacket/nxc credential dumping, PowerShell history extraction, LSA/LSASS dumping, ADCS vulnerabilities (ESC1-ESC8), and internal vulnerability scanning
- **Screenshot Placeholders**: Automatically includes screenshot placeholders with captions and commands
- **Flexible Assessment Types**: Supports external-only, internal-only, or combined assessments
- **Professional Output**: Generates well-formatted markdown narratives ready for report inclusion

## Quick Start

1. Clone or download this repository
2. Run the script:
   ```bash
   python3 pen_test_narrative_generator.py
   ```

3. Follow the interactive prompts:
   - Enter your testing company name (e.g., WKL)
   - Enter the client company name
   - Select assessment type (external, internal, or both)
   - Answer yes/no for each technique you performed

4. The tool will generate a comprehensive narrative with screenshot placeholders

## Assessment Types

### External Assessment
- **OSINT**: Company research, LinkedIn reconnaissance, email enumeration, technology stack identification
- **DNS Enumeration**: DNS queries, subdomain discovery, certificate transparency logs, zone transfers
- **Web Application Testing**: XSS, SQL injection, authentication bypass, directory traversal, file upload, CSRF, SSRF, XXE, IDOR
- **Network Testing**: Port scanning, banner grabbing, SSL/TLS analysis, email server testing
- **Vulnerability Assessment**: Nessus scanning, Burp Suite scanning, CVE exploitation, manual verification
- **Credential Testing**: Default credentials, leaked credentials, 2FA bypass, 2FA enabled checking, brute force attacks

### Internal Assessment
- **Network Discovery**: Host enumeration, segmentation analysis, Active Directory enumeration, BloodHound analysis, PingCastle assessment
- **Privilege Escalation**: Local, Windows, and Linux privilege escalation techniques
- **Lateral Movement**: Credential harvesting, pass-the-hash, Kerberos attacks, SMB enumeration, SMB signing checks, Responder, mitm6, NTLM relay attacks
- **Persistence**: Persistence mechanisms, backdoor installation
- **Data Exfiltration**: Data exfiltration testing, sensitive data discovery
- **Credential Harvesting**: Mimikatz, secretsdump, keyloggers, network sniffing, impacket dumping, nxc dumping, PowerShell history extraction, LSA/LSASS dumping
- **Defense Evasion**: Antivirus evasion, log clearing, artifact removal
- **Kerberos Attacks**: Kerberoasting, ASREPRoasting, golden ticket, silver ticket attacks
- **ADCS Vulnerabilities**: ESC1-ESC8 attack techniques, certificate template vulnerabilities
- **Internal Vulnerability Assessment**: Internal Nessus scanning, internal CVE exploitation

## Output

The tool generates a markdown file with:
- Assessment type explanation (External/Internal/Combined)
- Detailed methodology
- Comprehensive technique descriptions
- Screenshot placeholders with captions and commands
- Professional formatting ready for reports

## Future Enhancements

- ChatGPT API integration for enhanced narrative generation
- Custom technique templates
- Report export to multiple formats (PDF, Word, etc.)
- Integration with popular penetration testing tools

## Usage Example

```
$ python3 pen_test_narrative_generator.py

============================================================
PENETRATION TESTING NARRATIVE GENERATOR
============================================================

What company is performing the test? (e.g., WKL): WKL
What company are you testing against? (Client name): Acme Corp

What type of assessment is this?
1. External only
2. Internal only
3. Both external and internal
Enter your choice (1-3): 1

============================================================
TECHNIQUE SELECTION FOR EXTERNAL ASSESSMENT
============================================================

EXTERNAL ASSESSMENT TECHNIQUES:
----------------------------------------

OSINT:
  Did you perform OSINT research on the target company? (y/n): y
  Did you perform LinkedIn and social media reconnaissance? (y/n): y

DNS:
  Did you perform DNS enumeration and subdomain discovery? (y/n): y
  Did you perform subdomain discovery and enumeration? (y/n): y

[... continues with all techniques ...]
```

## License

This project is open source and available under the MIT License.
