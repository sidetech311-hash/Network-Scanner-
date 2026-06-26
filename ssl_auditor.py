"""
SSL/TLS Configuration Auditor for Network Scanner.
Audits HTTPS hosts for TLS/SSL certificate parameters, key strengths, and deprecated protocols.
"""

import socket
import ssl
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec

def audit_ssl_tls(host, port=443, timeout=3.0):
    """
    Connects to the target host and port to audit SSL/TLS parameters.
    Returns a dict containing the audit results or an error message.
    """
    result = {
        "host": host,
        "port": port,
        "connected": False,
        "cert_info": {},
        "warnings": [],
        "supported_protocols": []
    }
    
    # 1. SSL Handshake and Cert extraction
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        ssl_sock = context.wrap_socket(sock, server_hostname=host)
        ssl_sock.connect((host, port))
        result["connected"] = True
        
        # Get TLS Protocol version used for this connection
        conn_proto = ssl_sock.version()
        result["supported_protocols"].append(conn_proto)
        
        # Extract Binary DER encoded certificate
        der_cert = ssl_sock.getpeercert(binary_form=True)
        ssl_sock.close()
        
        if der_cert:
            cert = x509.load_der_x509_certificate(der_cert, default_backend())
            
            # Subject and Issuer
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            
            # Subject Alt Names (SAN)
            sans = []
            try:
                ext = cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
                sans = ext.value.get_values_for_type(x509.DNSName)
            except Exception:
                pass
                
            # Expiration
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
            now = datetime.datetime.now(datetime.timezone.utc)
            expired = now > not_after
            days_left = (not_after - now).days
            
            # Key strength & Algorithm
            pub_key = cert.public_key()
            key_size = 0
            key_algo = "Unknown"
            if isinstance(pub_key, rsa.RSAPublicKey):
                key_size = pub_key.key_size
                key_algo = "RSA"
            elif isinstance(pub_key, dsa.DSAPublicKey):
                key_size = pub_key.key_size
                key_algo = "DSA"
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                key_size = pub_key.curve.key_size
                key_algo = "ECDSA"
                
            sig_algo = cert.signature_algorithm_oid._name
            
            result["cert_info"] = {
                "subject": subject,
                "issuer": issuer,
                "dns_names": sans,
                "not_before": not_before.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "not_after": not_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "days_left": days_left,
                "expired": expired,
                "key_size": key_size,
                "key_algo": key_algo,
                "signature_algorithm": sig_algo
            }
            
            # Evaluate Cert warnings
            if expired:
                result["warnings"].append(f"Certificate expired on {not_after.strftime('%Y-%m-%d')}.")
            elif days_left < 30:
                result["warnings"].append(f"Certificate expires soon in {days_left} days.")
                
            if key_algo in ("RSA", "DSA") and key_size < 2048:
                result["warnings"].append(f"Weak Key Strength: {key_algo} key size is {key_size} bits (minimum recommended: 2048 bits).")
                
            if "sha1" in sig_algo.lower() or "md5" in sig_algo.lower():
                result["warnings"].append(f"Weak Signature Algorithm: Cert uses deprecated {sig_algo}.")
    except Exception as e:
        result["error"] = str(e)
        return result
        
    # 2. Audit supported / deprecated protocols
    protocols_to_test = [
        ("SSLv3", ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None),
        ("TLSv1.0", ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None),
        ("TLSv1.1", ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None),
        ("TLSv1.2", ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None),
    ]
    
    for label, proto_const in protocols_to_test:
        if proto_const is None:
            continue
        try:
            ctx = ssl.SSLContext(proto_const)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            wrapped = ctx.wrap_socket(s, server_hostname=host)
            wrapped.connect((host, port))
            if label not in result["supported_protocols"]:
                result["supported_protocols"].append(label)
            wrapped.close()
        except Exception:
            pass
            
    # Raise warning for weak protocols
    for label in ["SSLv3", "TLSv1.0", "TLSv1.1"]:
        if label in result["supported_protocols"]:
            result["warnings"].append(f"Insecure TLS Protocol Supported: host supports legacy {label} handshake protocol.")
            
    return result
