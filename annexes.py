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
                  public_key: rsa.RSAPublicKey, add_client_auth: bool = False, add_server_auth=False, is_CA=False,
                  is_Intermediate=False, is_ROOT=False):
    cert = x509.CertificateBuilder()

    cert = x509.CertificateBuilder(
        subject_name=subject_cert, issuer_name=issuer_cert, public_key=public_key,
        serial_number=x509.random_serial_number(), not_valid_before=datetime.datetime.utcnow(),
        not_valid_after=datetime.datetime.utcnow() + datetime.timedelta(days=1000)
        # Sign our certificate with our private key
    ).add_extension(

        x509.SubjectAlternativeName([x509.DNSName(u"localhost"), x509.DNSName(u"cy-tech.fr")]),
        critical=False,
        # Sign our certificate with our private key
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key), critical=True
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key), critical=True
    )

    if is_ROOT or (not is_CA and not is_Intermediate):
        cert = cert.add_extension(
            x509.BasicConstraints(ca=is_CA, path_length=None), critical=True
        )

    elif is_CA and is_Intermediate:
        cert = cert.add_extension(
            x509.BasicConstraints(ca=is_CA, path_length=0), critical=True
            # Attention à adapter path_length en fonction du nombre d'intermédiaires
        )

    if is_CA:
        cert = cert.add_extension(
            x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                          data_encipherment=False,
                          key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False,
                          decipher_only=False), critical=True
        )
    else:
        cert = cert.add_extension(
            x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                          data_encipherment=False,
                          key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False,
                          decipher_only=False), critical=True
        )

    if add_client_auth and not is_CA:
        cert = cert.add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH, x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION
            ]), critical=True
        )
    elif add_server_auth and not is_CA:
        cert = cert.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=True
        )

    cert = cert.sign(key_to_sign, hashes.SHA512())

    return cert


def generate_root_CA(subject_cert, issuer_cert):
    key = generate_private_key()
    # Write our key to disk for safe keeping
    cert = generate_cert(subject_cert=subject_cert, issuer_cert=issuer_cert, key_to_sign=key,
                         public_key=key.public_key(), is_CA=True, add_client_auth=False, add_server_auth=False,
                         is_Intermediate=False, is_ROOT=True)

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
    ).sign(key_priv, hashes.SHA512())

    return csr, key_priv


def sign_csr(csr_cert: x509.CertificateSigningRequest, issuername: x509.Name, key_to_sign: rsa.RSAPrivateKey,
             add_client_auth=False, add_server_auth=False, is_CA=False, is_Intermediate=False):

    return generate_cert(subject_cert=csr_cert.subject, issuer_cert=issuername, key_to_sign=key_to_sign,
                         public_key=csr_cert.public_key(), add_client_auth=add_client_auth,
                         add_server_auth=add_server_auth, is_CA=is_CA, is_Intermediate=is_Intermediate, is_ROOT=False)
