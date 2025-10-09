#!/usr/bin/env python3
"""
Comprehensive demonstration of the Penetration Testing Narrative Generator
This script shows the full capabilities with multiple techniques selected
"""

from pen_test_narrative_generator import PenTestNarrativeGenerator

def demo_comprehensive_external():
    """Demonstrate comprehensive external assessment"""
    generator = PenTestNarrativeGenerator()
    
    # Set demo data
    generator.testing_company = "WKL"
    generator.client_company = "TechCorp Solutions"
    generator.test_type = "external"
    
    # Add comprehensive external techniques
    generator.selected_techniques = [
        # OSINT techniques
        {
            'category': 'external',
            'subcategory': 'osint',
            'technique': generator.narrative_blocks['external']['osint'][0]  # Company Information Gathering
        },
        {
            'category': 'external',
            'subcategory': 'osint',
            'technique': generator.narrative_blocks['external']['osint'][1]  # LinkedIn and Social Media
        },
        {
            'category': 'external',
            'subcategory': 'osint',
            'technique': generator.narrative_blocks['external']['osint'][2]  # Email Address Enumeration
        },
        
        # DNS techniques
        {
            'category': 'external',
            'subcategory': 'dns',
            'technique': generator.narrative_blocks['external']['dns'][0]  # DNS Enumeration
        },
        {
            'category': 'external',
            'subcategory': 'dns',
            'technique': generator.narrative_blocks['external']['dns'][1]  # Subdomain Discovery
        },
        {
            'category': 'external',
            'subcategory': 'dns',
            'technique': generator.narrative_blocks['external']['dns'][2]  # Certificate Transparency
        },
        
        # Web application techniques
        {
            'category': 'external',
            'subcategory': 'web_app',
            'technique': generator.narrative_blocks['external']['web_app'][0]  # Web Application Discovery
        },
        {
            'category': 'external',
            'subcategory': 'web_app',
            'technique': generator.narrative_blocks['external']['web_app'][1]  # XSS Testing
        },
        {
            'category': 'external',
            'subcategory': 'web_app',
            'technique': generator.narrative_blocks['external']['web_app'][2]  # SQL Injection
        },
        {
            'category': 'external',
            'subcategory': 'web_app',
            'technique': generator.narrative_blocks['external']['web_app'][3]  # Authentication Bypass
        },
        {
            'category': 'external',
            'subcategory': 'web_app',
            'technique': generator.narrative_blocks['external']['web_app'][4]  # Directory Traversal
        },
        
        # Network techniques
        {
            'category': 'external',
            'subcategory': 'network',
            'technique': generator.narrative_blocks['external']['network'][0]  # Port Scanning
        },
        {
            'category': 'external',
            'subcategory': 'network',
            'technique': generator.narrative_blocks['external']['network'][1]  # Banner Grabbing
        },
        {
            'category': 'external',
            'subcategory': 'network',
            'technique': generator.narrative_blocks['external']['network'][2]  # SSL/TLS Analysis
        },
        
        # Vulnerability assessment
        {
            'category': 'external',
            'subcategory': 'vulnerability_assessment',
            'technique': generator.narrative_blocks['external']['vulnerability_assessment'][0]  # Automated Scanning
        },
        {
            'category': 'external',
            'subcategory': 'vulnerability_assessment',
            'technique': generator.narrative_blocks['external']['vulnerability_assessment'][1]  # Manual Verification
        }
    ]
    
    # Generate narrative
    narrative = generator.generate_narrative()
    
    # Save comprehensive output
    with open('comprehensive_external_narrative.md', 'w') as f:
        f.write(narrative)
    
    print("Comprehensive External Assessment Narrative Generated!")
    print("File: comprehensive_external_narrative.md")
    print(f"Selected {len(generator.selected_techniques)} techniques")
    
    return narrative

def demo_comprehensive_internal():
    """Demonstrate comprehensive internal assessment"""
    generator = PenTestNarrativeGenerator()
    
    # Set demo data
    generator.testing_company = "WKL"
    generator.client_company = "Enterprise Systems Inc"
    generator.test_type = "internal"
    
    # Add comprehensive internal techniques
    generator.selected_techniques = [
        # Network discovery
        {
            'category': 'internal',
            'subcategory': 'network_discovery',
            'technique': generator.narrative_blocks['internal']['network_discovery'][0]  # Network Discovery
        },
        {
            'category': 'internal',
            'subcategory': 'network_discovery',
            'technique': generator.narrative_blocks['internal']['network_discovery'][1]  # Network Segmentation
        },
        {
            'category': 'internal',
            'subcategory': 'network_discovery',
            'technique': generator.narrative_blocks['internal']['network_discovery'][2]  # Active Directory
        },
        
        # Privilege escalation
        {
            'category': 'internal',
            'subcategory': 'privilege_escalation',
            'technique': generator.narrative_blocks['internal']['privilege_escalation'][0]  # Local Privilege Escalation
        },
        {
            'category': 'internal',
            'subcategory': 'privilege_escalation',
            'technique': generator.narrative_blocks['internal']['privilege_escalation'][1]  # Windows Privilege Escalation
        },
        {
            'category': 'internal',
            'subcategory': 'privilege_escalation',
            'technique': generator.narrative_blocks['internal']['privilege_escalation'][2]  # Linux Privilege Escalation
        },
        
        # Lateral movement
        {
            'category': 'internal',
            'subcategory': 'lateral_movement',
            'technique': generator.narrative_blocks['internal']['lateral_movement'][0]  # Lateral Movement
        },
        {
            'category': 'internal',
            'subcategory': 'lateral_movement',
            'technique': generator.narrative_blocks['internal']['lateral_movement'][1]  # Pass-the-Hash
        },
        {
            'category': 'internal',
            'subcategory': 'lateral_movement',
            'technique': generator.narrative_blocks['internal']['lateral_movement'][2]  # Kerberos Attacks
        },
        {
            'category': 'internal',
            'subcategory': 'lateral_movement',
            'technique': generator.narrative_blocks['internal']['lateral_movement'][3]  # SMB Enumeration
        },
        
        # Persistence
        {
            'category': 'internal',
            'subcategory': 'persistence',
            'technique': generator.narrative_blocks['internal']['persistence'][0]  # Persistence Mechanisms
        },
        {
            'category': 'internal',
            'subcategory': 'persistence',
            'technique': generator.narrative_blocks['internal']['persistence'][1]  # Backdoor Installation
        },
        
        # Data exfiltration
        {
            'category': 'internal',
            'subcategory': 'data_exfiltration',
            'technique': generator.narrative_blocks['internal']['data_exfiltration'][0]  # Data Exfiltration
        },
        {
            'category': 'internal',
            'subcategory': 'data_exfiltration',
            'technique': generator.narrative_blocks['internal']['data_exfiltration'][1]  # Sensitive Data Discovery
        }
    ]
    
    # Generate narrative
    narrative = generator.generate_narrative()
    
    # Save comprehensive output
    with open('comprehensive_internal_narrative.md', 'w') as f:
        f.write(narrative)
    
    print("Comprehensive Internal Assessment Narrative Generated!")
    print("File: comprehensive_internal_narrative.md")
    print(f"Selected {len(generator.selected_techniques)} techniques")
    
    return narrative

def demo_combined_assessment():
    """Demonstrate combined external and internal assessment"""
    generator = PenTestNarrativeGenerator()
    
    # Set demo data
    generator.testing_company = "WKL"
    generator.client_company = "Global Financial Corp"
    generator.test_type = "both"
    
    # Add techniques from both external and internal
    generator.selected_techniques = [
        # External techniques
        {
            'category': 'external',
            'subcategory': 'osint',
            'technique': generator.narrative_blocks['external']['osint'][0]  # Company Information Gathering
        },
        {
            'category': 'external',
            'subcategory': 'dns',
            'technique': generator.narrative_blocks['external']['dns'][0]  # DNS Enumeration
        },
        {
            'category': 'external',
            'subcategory': 'web_app',
            'technique': generator.narrative_blocks['external']['web_app'][1]  # XSS Testing
        },
        {
            'category': 'external',
            'subcategory': 'web_app',
            'technique': generator.narrative_blocks['external']['web_app'][2]  # SQL Injection
        },
        {
            'category': 'external',
            'subcategory': 'network',
            'technique': generator.narrative_blocks['external']['network'][0]  # Port Scanning
        },
        
        # Internal techniques
        {
            'category': 'internal',
            'subcategory': 'network_discovery',
            'technique': generator.narrative_blocks['internal']['network_discovery'][0]  # Network Discovery
        },
        {
            'category': 'internal',
            'subcategory': 'network_discovery',
            'technique': generator.narrative_blocks['internal']['network_discovery'][2]  # Active Directory
        },
        {
            'category': 'internal',
            'subcategory': 'privilege_escalation',
            'technique': generator.narrative_blocks['internal']['privilege_escalation'][0]  # Local Privilege Escalation
        },
        {
            'category': 'internal',
            'subcategory': 'lateral_movement',
            'technique': generator.narrative_blocks['internal']['lateral_movement'][0]  # Lateral Movement
        },
        {
            'category': 'internal',
            'subcategory': 'lateral_movement',
            'technique': generator.narrative_blocks['internal']['lateral_movement'][1]  # Pass-the-Hash
        }
    ]
    
    # Generate narrative
    narrative = generator.generate_narrative()
    
    # Save comprehensive output
    with open('comprehensive_combined_narrative.md', 'w') as f:
        f.write(narrative)
    
    print("Comprehensive Combined Assessment Narrative Generated!")
    print("File: comprehensive_combined_narrative.md")
    print(f"Selected {len(generator.selected_techniques)} techniques")
    
    return narrative

def main():
    """Run all demonstrations"""
    print("=" * 80)
    print("PENETRATION TESTING NARRATIVE GENERATOR - COMPREHENSIVE DEMO")
    print("=" * 80)
    print()
    
    print("1. Generating Comprehensive External Assessment...")
    demo_comprehensive_external()
    print()
    
    print("2. Generating Comprehensive Internal Assessment...")
    demo_comprehensive_internal()
    print()
    
    print("3. Generating Combined Assessment...")
    demo_combined_assessment()
    print()
    
    print("=" * 80)
    print("ALL DEMONSTRATIONS COMPLETE!")
    print("=" * 80)
    print("Generated files:")
    print("- comprehensive_external_narrative.md")
    print("- comprehensive_internal_narrative.md") 
    print("- comprehensive_combined_narrative.md")
    print()
    print("These files demonstrate the full capabilities of the narrative generator")
    print("with comprehensive technique coverage and professional formatting.")

if __name__ == "__main__":
    main()
