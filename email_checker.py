#!/usr/bin/env python3
"""
Email Validator - Comprehensive Email Validation Tool
Run multiple validation methods and generate a detailed report
"""

import re
import sys
import time
import smtplib
import socket
import hashlib
from typing import Tuple, Dict, Any

# Try to import optional dependencies
try:
    from email_validator import validate_email, EmailNotValidError
    HAS_EMAIL_VALIDATOR = True
except ImportError:
    HAS_EMAIL_VALIDATOR = False

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class EmailValidator:
    def __init__(self, email: str):
        self.email = email
        self.results = {}
        
    def validate_basic_regex(self) -> Tuple[bool, str]:
        """Basic regex validation"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        is_valid = bool(re.match(pattern, self.email))
        message = "Valid format" if is_valid else "Invalid format"
        return is_valid, message
    
    def validate_rfc5322(self) -> Tuple[bool, str]:
        """RFC 5322 compliant validation"""
        pattern = r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        is_valid = bool(re.match(pattern, self.email))
        message = "RFC 5322 compliant" if is_valid else "Not RFC 5322 compliant"
        return is_valid, message
    
    def validate_with_library(self) -> Tuple[bool, str]:
        """Validate using email-validator library"""
        if not HAS_EMAIL_VALIDATOR:
            return None, "email-validator library not installed"
        
        try:
            validation = validate_email(self.email, check_deliverability=False)
            return True, f"Valid (normalized: {validation.normalized})"
        except EmailNotValidError as e:
            return False, f"Invalid: {str(e)}"
    
    def check_dns_mx(self) -> Tuple[bool, str]:
        """Check if domain has MX records"""
        if not HAS_DNS:
            return None, "dnspython library not installed"
        
        try:
            domain = self.email.split('@')[1]
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_hosts = [str(r.exchange) for r in mx_records]
            return True, f"Found {len(mx_records)} MX record(s): {', '.join(mx_hosts[:3])}"
        except dns.resolver.NXDOMAIN:
            return False, "Domain does not exist"
        except dns.resolver.NoAnswer:
            return False, "No MX records found"
        except dns.resolver.NoNameservers:
            return False, "No nameservers available"
        except IndexError:
            return False, "Invalid email format (no @ symbol)"
        except Exception as e:
            return False, f"DNS error: {str(e)}"
    
    def check_dns_a(self) -> Tuple[bool, str]:
        """Check if domain has A records (fallback for mail)"""
        if not HAS_DNS:
            return None, "dnspython library not installed"
        
        try:
            domain = self.email.split('@')[1]
            a_records = dns.resolver.resolve(domain, 'A')
            ips = [str(r) for r in a_records]
            return True, f"Found {len(a_records)} A record(s): {', '.join(ips[:3])}"
        except Exception as e:
            return False, f"No A records found: {str(e)}"
    
    def verify_smtp(self) -> Tuple[bool, str]:
        """SMTP verification (may not work with many providers)"""
        if not HAS_DNS:
            return None, "dnspython library required for SMTP check"
        
        try:
            domain = self.email.split('@')[1]
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_host = str(mx_records[0].exchange)
            
            # Connect to mail server
            server = smtplib.SMTP(timeout=10)
            server.set_debuglevel(0)
            server.connect(mx_host)
            server.helo(socket.getfqdn())
            server.mail('verify@example.com')
            code, message = server.rcpt(self.email)
            server.quit()
            
            if code == 250:
                return True, f"Mailbox verified (code {code})"
            elif code == 251:
                return True, f"User not local, will forward (code {code})"
            else:
                return False, f"Verification failed (code {code}): {message.decode()}"
                
        except Exception as e:
            return False, f"SMTP verification failed: {str(e)}"
    
    def run_all_validations(self) -> Dict[str, Any]:
        """Run all validation methods"""
        print(f"\n{'='*70}")
        print(f"EMAIL VALIDATION REPORT")
        print(f"{'='*70}")
        print(f"Email Address: {self.email}")
        print(f"{'='*70}\n")
        
        tests = [
            ("Basic Regex", self.validate_basic_regex),
            ("RFC 5322", self.validate_rfc5322),
            ("Email Validator Library", self.validate_with_library),
            ("DNS MX Records", self.check_dns_mx),
            ("DNS A Records", self.check_dns_a),
            ("SMTP Verification", self.verify_smtp),
        ]
        
        for test_name, test_func in tests:
            print(f"[{test_name}]")
            start_time = time.time()
            
            try:
                is_valid, message = test_func()
                elapsed = time.time() - start_time
                
                if is_valid is None:
                    status = "⊘ SKIPPED"
                    color = "\033[93m"  # Yellow
                elif is_valid:
                    status = "✓ PASSED"
                    color = "\033[92m"  # Green
                else:
                    status = "✗ FAILED"
                    color = "\033[91m"  # Red
                
                reset = "\033[0m"
                
                print(f"  Status: {color}{status}{reset}")
                print(f"  Result: {message}")
                print(f"  Time: {elapsed:.3f}s")
                
                self.results[test_name] = {
                    'valid': is_valid,
                    'message': message,
                    'time': elapsed
                }
                
            except Exception as e:
                print(f"  Status: \033[91m✗ ERROR\033[0m")
                print(f"  Result: Unexpected error: {str(e)}")
                self.results[test_name] = {
                    'valid': False,
                    'message': f"Error: {str(e)}",
                    'time': time.time() - start_time
                }
            
            print()
        
        self.print_summary()
        return self.results
    
    def print_summary(self):
        """Print validation summary"""
        print(f"{'='*70}")
        print("SUMMARY")
        print(f"{'='*70}")
        
        passed = sum(1 for r in self.results.values() if r['valid'] is True)
        failed = sum(1 for r in self.results.values() if r['valid'] is False)
        skipped = sum(1 for r in self.results.values() if r['valid'] is None)
        
        print(f"Tests Passed:  \033[92m{passed}\033[0m")
        print(f"Tests Failed:  \033[91m{failed}\033[0m")
        print(f"Tests Skipped: \033[93m{skipped}\033[0m")
        print(f"Total Tests:   {len(self.results)}")
        
        # Overall verdict
        print(f"\n{'='*70}")

        if passed >= 4 and failed == 0:
            print("Overall Verdict: \033[92m✓ EMAIL IS VALID AND SECURE\033[0m")
        elif passed >= 2 and failed <= 2:
            print("Overall Verdict: \033[93m⚠ EMAIL MAY BE VALID (mixed results)\033[0m")
        else:
            print("Overall Verdict: \033[91m✗ EMAIL IS LIKELY INVALID\033[0m")
        
        print(f"{'='*70}\n")
        
        # Missing dependencies warning
        if not HAS_EMAIL_VALIDATOR or not HAS_DNS or not HAS_REQUESTS:
            print("\033[93m⚠ MISSING DEPENDENCIES:\033[0m")
            if not HAS_EMAIL_VALIDATOR:
                print("  - Install email-validator: pip install email-validator")
            if not HAS_DNS:
                print("  - Install dnspython: pip install dnspython")
            if not HAS_REQUESTS:
                print("  - Install requests: pip install requests")
            print()


def main():
    """Main entry point"""
    print("\033[96m")
    print("╔════════════════════════════════════════════════════════════════════╗")
    print("║           EMAIL CHECKER - Comprehensive Validation Tool            ║")
    print("╚════════════════════════════════════════════════════════════════════╝")
    print("\033[0m")
    
    if len(sys.argv) > 1:
        email = sys.argv[1]
    else:
        email = input("Enter email address to validate: ").strip()
    
    if not email:
        print("\033[91mError: No email address provided\033[0m")
        sys.exit(1)
    
    validator = EmailValidator(email)
    validator.run_all_validations()


if __name__ == "__main__":
    main()