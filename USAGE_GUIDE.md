# Penetration Testing Narrative Generator - Usage Guide

## Quick Start

1. **Run the main script:**
   ```bash
   python3 pen_test_narrative_generator.py
   ```

2. **Follow the interactive prompts:**
   - Enter your testing company name (e.g., WKL)
   - Enter the client company name
   - Select assessment type (1=External, 2=Internal, 3=Both)
   - Answer yes/no for each technique you performed

3. **Get your narrative:**
   - The tool generates a timestamped markdown file
   - Ready for inclusion in penetration testing reports

## Available Techniques

### External Assessment Techniques

#### OSINT (Open Source Intelligence)
- Company Information Gathering
- LinkedIn and Social Media Reconnaissance  
- Email Address Enumeration
- Technology Stack Identification

#### DNS Enumeration
- DNS Enumeration and Subdomain Discovery
- Certificate Transparency Logs
- DNS Zone Transfer Attempts

#### Web Application Testing
- Web Application Discovery
- Cross-Site Scripting (XSS) Testing
- SQL Injection Testing
- Authentication Bypass Testing
- Directory Traversal Testing
- File Upload Testing
- Cross-Site Request Forgery (CSRF) Testing
- Server-Side Request Forgery (SSRF) Testing
- XML External Entity (XXE) Testing
- Insecure Direct Object References

#### Network Testing
- Port Scanning and Service Enumeration
- Banner Grabbing and Service Fingerprinting
- SSL/TLS Configuration Analysis
- Email Server Testing

#### Vulnerability Assessment
- Automated Vulnerability Scanning
- Manual Vulnerability Verification

### Internal Assessment Techniques

#### Network Discovery
- Network Discovery and Host Enumeration
- Network Segmentation Analysis
- Active Directory Enumeration

#### Privilege Escalation
- Local Privilege Escalation
- Windows Privilege Escalation
- Linux Privilege Escalation

#### Lateral Movement
- Lateral Movement and Credential Harvesting
- Pass-the-Hash Attacks
- Kerberos Attacks
- SMB and RPC Enumeration

#### Persistence
- Persistence Mechanism Testing
- Backdoor Installation

#### Data Exfiltration
- Data Exfiltration Testing
- Sensitive Data Discovery

## Sample Output Structure

The generated narrative includes:

1. **Header Information**
   - Client name
   - Testing company
   - Assessment type
   - Date

2. **Executive Summary**
   - Overview of methodology and scope

3. **Methodology**
   - Standards followed (OWASP, NIST, PTES)

4. **Detailed Assessment Findings**
   - Organized by assessment type and technique category
   - Professional descriptions of each technique
   - Screenshot placeholders with captions
   - Command examples where applicable

5. **Conclusion**
   - Summary and recommendations

## Screenshot Placeholders

Each technique includes:
- `[SCREENSHOT: Description]` placeholder
- Detailed caption with command examples
- Professional formatting for report inclusion

## Customization

The tool automatically:
- Replaces `{client_company}` with your client's name
- Replaces `{testing_company}` with your company name
- Formats content professionally
- Includes relevant commands and examples

## Demo Files

Run the comprehensive demo to see full capabilities:
```bash
python3 demo_comprehensive.py
```

This generates three example narratives:
- `comprehensive_external_narrative.md`
- `comprehensive_internal_narrative.md`
- `comprehensive_combined_narrative.md`

## Tips for Best Results

1. **Be Selective**: Only select techniques you actually performed
2. **Review Output**: The generated narrative is a starting point - customize as needed
3. **Add Screenshots**: Replace placeholders with actual screenshots
4. **Customize Commands**: Update command examples with your actual tools/parameters
5. **Edit Content**: Tailor the narrative to your specific findings and methodology

## Future Enhancements

- ChatGPT API integration for enhanced narrative generation
- Custom technique templates
- Report export to multiple formats (PDF, Word, etc.)
- Integration with popular penetration testing tools
