import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_private_key():
    """
    Cette fonction génère une clée privée.

    :param encoding: Nom de l'encodage

    :param keyname: Nom de la clé à enregistrer

    :param passphrase: Mot de passe de la clé

    :return:
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key


def generate_cert(subject_cert: x509.Name, issuer_cert: x509.Name, key_to_sign: rsa.RSAPrivateKey,
                  public_key: rsa.RSAPublicKey, add_client_auth: bool = False):
    if add_client_auth:
        cert = x509.CertificateBuilder().subject_name(

            subject_cert
        ).issuer_name(

            issuer_cert
        ).public_key(

            public_key
        ).serial_number(

            x509.random_serial_number()
        ).not_valid_before(

            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=1000)
        ).add_extension(

            x509.SubjectAlternativeName([x509.DNSName(u"localhost"), x509.DNSName(u"cy-tech.fr")]),
            critical=False,
            # Sign our certificate with our private key
        ).sign(key_to_sign, hashes.SHA256())

    else:
        cert = x509.CertificateBuilder().subject_name(

            subject_cert
        ).issuer_name(

            issuer_cert
        ).public_key(

            public_key
        ).serial_number(

            x509.random_serial_number()
        ).not_valid_before(

            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=1000)
        ).add_extension(

            x509.SubjectAlternativeName([x509.DNSName(u"localhost"), x509.DNSName(u"cy-tech.fr")]),
            critical=False,
            # Sign our certificate with our private key
        ).add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        ).sign(key_to_sign, hashes.SHA256())

    return cert


def generate_CA(subject_cert, issuer_cert):
    key = generate_private_key()
    # Write our key to disk for safe keeping
    cert = generate_cert(subject_cert=subject_cert, issuer_cert=issuer_cert, key_to_sign=key,
                         public_key=key.public_key())

    # Various details about who we are. For a self-signed certificate the
    # subject and issuer are always the same.

    # Write our certificate out to disk.

    return cert, key


def generate_csr(subject_cert: x509.Name, issuer_cert: x509.Name, ):
    key_priv = generate_private_key()

    # Generate a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject_cert).add_extension(
        x509.SubjectAlternativeName([
            # Describe what sites we want this certificate for.
            x509.DNSName(u"localhost"),
            x509.DNSName(u"cy-tech.fr"),
        ]),
        critical=False
    ).add_extension(
        x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
    ).sign(key_priv, hashes.SHA256())

    return csr, key_priv


def sign_csr(csr_cert: x509.CertificateSigningRequest, issuername: x509.Name, key_to_sign: rsa.RSAPrivateKey,
             add_client_auth=True):
    return generate_cert(subject_cert=csr_cert.subject, issuer_cert=issuername, key_to_sign=key_to_sign,
                         public_key=csr_cert.public_key(), add_client_auth=add_client_auth)
