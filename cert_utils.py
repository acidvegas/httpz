#!/usr/bin/env python3
# Hyperfast Scalable HTTP Scanner - Developed by acidvegas (https://github.com/acidvegas)

import hashlib
import logging

try:
    from cryptography                 import x509
    from cryptography.hazmat.backends import default_backend
except ImportError:
    raise ImportError('missing cryptography library (pip install cryptography)')

try:
    from OpenSSL import crypto
except ImportError:
    raise ImportError('missing OpenSSL library (pip install pyOpenSSL)')


def extract_cert_info(certificate: x509.Certificate) -> dict:
    '''
    Extract and format certificate information
    
    :param certificate: Certificate object
    '''

    try:
        cert_der = crypto.dump_certificate(crypto.FILETYPE_ASN1, certificate)
        cert     = x509.load_der_x509_certificate(cert_der, default_backend())
        
        cert_info = {
            'fingerprint' : hashlib.sha256(cert_der).hexdigest(),
            'common_name' : next((attr.value for attr in cert.subject if isinstance(attr, x509.NameAttribute) and attr.oid == x509.NameOID.COMMON_NAME),   None),
            'email'       : next((attr.value for attr in cert.subject if isinstance(attr, x509.NameAttribute) and attr.oid == x509.NameOID.EMAIL_ADDRESS), None),
            'issuer'      : next((attr.value for attr in cert.issuer  if isinstance(attr, x509.NameAttribute) and attr.oid == x509.NameOID.COMMON_NAME),   None),
            'sans'        : [],
            'subject'     : cert.subject.rfc4514_string()
        }
        
        # Get SANs
        try:
            cert_info['sans'] = [ext.value.get_values_for_type(x509.DNSName) for ext in cert.extensions if ext.oid == x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME][0]
        except:
            pass

        # Remove empty values
        cert_info = {k: v for k, v in cert_info.items() if v}

        return cert_info

    except Exception as e:
        logging.debug(f'Error extracting certificate info: {str(e)}')
        return {}