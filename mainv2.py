import colorama
import cryptography.x509
from colorama import Fore
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from cryptography.x509.base import serialization
from cryptography.x509.oid import NameOID

from annexes import *


if __name__ == "__main__":
    print("Génération du CA root...", end="")
    # Generate our key

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Val d'Oise"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Cergy"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"CY TECH"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"cy-tech.fr"),
    ])

    certificate, priv_key = generate_CA(subject, issuer)

    with open("certificate.pem", "wb") as pub_key:
        pub_key.write(certificate.public_bytes(serialization.Encoding.PEM))

    with open("key.pem", "wb") as file:
        file.write(priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))

    print(Fore.LIGHTGREEN_EX, "Terminé!", Fore.RESET, end=None)

    ## CSR



    print("Génération du CA intermédiaire...", end="")
    # Generate our key

    subject = x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
    ])

    csr, priv_key_csr = generate_csr(subject_cert=subject, issuer_cert=subject)

    # Write our CSR out to disk.
    with open("sub_csr.pem", "wb") as pub_key:
        pub_key.write(csr.public_bytes(serialization.Encoding.PEM))

    print(Fore.LIGHTGREEN_EX, "Terminé!", Fore.RESET, end=None)
    ## signature du certificat CSR par le root


    # signing csr

    print("Signature du sub CA par le CA Root...", end="")

    cert_root = open("certificate.pem", 'rb').read()
    cert_root_pkey = open("key.pem", 'rb').read()
    cert_root_pkey = cryptography.x509.base.serialization.load_pem_private_key(cert_root_pkey, b"passphrase")

    csr_sub = open("sub_csr.pem", 'rb').read()
    csr_sub_pkey = open("sub_key.pem", 'rb').read()
    csr_sub_pkey = cryptography.x509.base.serialization.load_pem_private_key(csr_sub_pkey, b"passphrase")

    csr = cryptography.x509.load_pem_x509_csr(bytes(csr_sub))
    root = cryptography.x509.load_pem_x509_certificate(bytes(cert_root))

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

    cert = sign_csr(csr_cert=csr, issuername=issuer, key_to_sign=cert_root_pkey)

    # Write our certificate out to disk.
    with open("certificate_signed.pem", "wb") as pub_key:
        pub_key.write(cert.public_bytes(serialization.Encoding.PEM))
    print(Fore.LIGHTGREEN_EX, "Terminé!", Fore.RESET, end=None)

    # print(cert.public_key().public_bytes(
    #     cryptography.x509.base.serialization.Encoding.PEM,
    #     cryptography.x509.base.serialization.PublicFormat.PKCS1
    # ))

    print("SUJET ROOT ", colorama.Fore.LIGHTCYAN_EX, root.issuer, colorama.Fore.RESET)
    print("SUJET SUJET", colorama.Fore.LIGHTCYAN_EX, cert.subject, colorama.Fore.RESET)

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
