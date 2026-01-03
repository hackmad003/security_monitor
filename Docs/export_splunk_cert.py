"""
Export Splunk SSL Certificate
Run this once to save Splunk's self-signed certificate
"""

import ssl
import socket

def export_splunk_certificate():
    hostname = 'localhost'
    port = 8088
    output_file = 'splunk_cert.pem'
    
    print(f"Connecting to Splunk at {hostname}:{port}...")
    
    try:
        # Create SSL context that doesn't verify (just for export)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Connect and get certificate
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                print(f"✓ Connected to Splunk")
                
                # Get certificate in DER format
                cert_der = ssock.getpeercert(binary_form=True)
                
                # Convert to PEM format
                cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
                
                # Save to file
                with open(output_file, 'w') as f:
                    f.write(cert_pem)
                
                print(f"✓ Certificate saved to: {output_file}")
                print(f"\nCertificate Info:")
                
                # Show certificate details
                cert_info = ssock.getpeercert()
                if cert_info:
                    print(f"  Subject: {dict(x[0] for x in cert_info['subject'])}")
                    print(f"  Issuer: {dict(x[0] for x in cert_info['issuer'])}")
                    print(f"  Valid from: {cert_info['notBefore']}")
                    print(f"  Valid until: {cert_info['notAfter']}")
                
                # Get absolute path
                import os
                abs_path = os.path.abspath(output_file)
                print(f"\n✓ Full path: {abs_path}")
                print(f"\nAdd this to your main script:")
                print(f"monitor.splunk_config['verify_ssl'] = r'{abs_path}'")
                
                return abs_path
                
    except socket.timeout:
        print(f"❌ Connection timeout - Is Splunk running?")
        return None
    except ConnectionRefusedError:
        print(f"❌ Connection refused - Is Splunk running on port {port}?")
        print(f"   Check if HEC is enabled in Splunk")
        return None
    except Exception as e:
        print(f"❌ Error: {e}")
        return None

if __name__ == "__main__":
    print("="*60)
    print("Splunk Certificate Export Tool")
    print("="*60)
    print()
    
    cert_path = export_splunk_certificate()
    
    print()
    print("="*60)
    if cert_path:
        print("SUCCESS - Certificate exported!")
    else:
        print("FAILED - Check errors above")
    print("="*60)