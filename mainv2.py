import asyncio
import datetime
import types

import colorama
import cryptography.x509
from colorama import Fore
from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature


def generate_private_key(keyname: str, passphrase: bytes, encoding: serialization.Encoding):
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
    with open(keyname, "wb") as file:
        file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
        ))
    return private_key


if __name__ == "__main__":
    # Generate our key
    key = generate_private_key("key.pem", b"passphrase", serialization.Encoding.PEM)
    # Write our key to disk for safe keeping

    # Various details about who we are. For a self-signed certificate the
    # subject and issuer are always the same.
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Val d'Oise"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Cergy"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"CY TECH"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"cy-tech.fr"),
    ])
    cert = x509.CertificateBuilder().subject_name(

        subject
    ).issuer_name(

        issuer
    ).public_key(

        key.public_key()
    ).serial_number(

        x509.random_serial_number()
    ).not_valid_before(

        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=1000)
    ).add_extension(

        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
        # Sign our certificate with our private key
    ).sign(key, hashes.SHA256())
    # Write our certificate out to disk.
    with open("certificate.pem", "wb") as pub_key:
        pub_key.write(cert.public_bytes(serialization.Encoding.PEM))

    ## CSR

    # Generate our key
    key = generate_private_key("sub_key.pem", b"passphrase", serialization.Encoding.PEM)

    # Generate a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
    ])).add_extension(
        x509.SubjectAlternativeName([
            # Describe what sites we want this certificate for.
            x509.DNSName(u"mysite.com"),
            x509.DNSName(u"www.mysite.com"),
            x509.DNSName(u"subdomain.mysite.com"),
        ]),
        critical=False,
        # Sign the CSR with our private key.
    ).sign(key, hashes.SHA256())
    # Write our CSR out to disk.
    with open("sub_csr.pem", "wb") as pub_key:
        pub_key.write(csr.public_bytes(serialization.Encoding.PEM))

    ## signature du certificat CSR par le root

    cert_root = open("certificate.pem", 'rb').read()
    cert_root_pkey = open("key.pem", 'rb').read()
    cert_root_pkey = cryptography.x509.base.serialization.load_pem_private_key(cert_root_pkey, b"passphrase")

    csr_sub = open("sub_csr.pem", 'rb').read()
    csr_sub_pkey = open("sub_key.pem", 'rb').read()
    csr_sub_pkey = cryptography.x509.base.serialization.load_pem_private_key(csr_sub_pkey, b"passphrase")

    csr = cryptography.x509.load_pem_x509_csr(bytes(csr_sub))
    root = cryptography.x509.load_pem_x509_certificate(bytes(cert_root))

    # signing csr

    key = csr_sub_pkey

    # Various details about who we are. For a self-signed certificate the
    # subject and issuer are always the same.
    issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, root.issuer.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,
                           root.issuer.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value),
        x509.NameAttribute(NameOID.LOCALITY_NAME, root.issuer.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                           root.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value),
        x509.NameAttribute(NameOID.COMMON_NAME, root.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value),
    ])
    subject = csr.subject
    cert = x509.CertificateBuilder().subject_name(

        subject
    ).issuer_name(

        issuer
    ).public_key(

        key.public_key()
    ).serial_number(

        x509.random_serial_number()
    ).not_valid_before(

        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=1000)
    ).add_extension(

        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
        # Sign our certificate with our private key ?
    ).sign(cert_root_pkey, hashes.SHA256())
    # Write our certificate out to disk.
    with open("certificate_signed.pem", "wb") as pub_key:
        pub_key.write(cert.public_bytes(serialization.Encoding.PEM))

    print(cert.public_key().public_bytes(
        cryptography.x509.base.serialization.Encoding.PEM,
        cryptography.x509.base.serialization.PublicFormat.PKCS1
    ))
    print(colorama.Fore.LIGHTCYAN_EX)
    print("SUJET SUJET", cert.subject)
    print("SUJET ROOT ", cert.issuer)
    print(colorama.Fore.RESET)

    # verification :
    print("Verification de la hiérarchie du certificat... ", end="")

    try:
        root.public_key().verify(
            signature=cert.signature,
            data=cert.tbs_certificate_bytes,
            padding=cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(),
            algorithm=cert.signature_hash_algorithm
        )
    except InvalidSignature as exc:
        print(Fore.LIGHTRED_EX + "Erreur !" + Fore.RESET)
        exit(InvalidSignature("Le certificat n'a pas pu être validé. Il y a une erreur."))
    else:
        print(Fore.LIGHTGREEN_EX + "Succès!" + Fore.RESET)
