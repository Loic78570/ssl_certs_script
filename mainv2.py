import contextlib
import os

import colorama
from colorama import Fore
from cryptography import x509, hazmat
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives._serialization import PublicFormat, Encoding, PrivateFormat
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.base import serialization
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates

from annexes import *

if __name__ == "__main__":
    print("Génération du CA root...", end="")
    # Generate our key

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Val d'Oise"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Cergy"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"CY TECH"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"CY TECH"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"ROOT CY TECH"),
    ])

    root_cert, root_privatekey = generate_root_CA(subject, issuer)

    os.makedirs("CA_ROOT_DEV", exist_ok=True)

    with open("CA_ROOT_DEV/certificate.pem", "wb") as pub_key:
        pub_key.write(root_cert.public_bytes(serialization.Encoding.PEM))

    with open("CA_ROOT_DEV/key.pem", "wb") as file:
        file.write(root_privatekey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))

    print(Fore.LIGHTGREEN_EX, "Terminé!", Fore.RESET, end=None)

    ## CSR

    print("Génération du CA intermédiaire (Client)...", end="")
    # Generate our key

    subject = x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"VAL D'OISE"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"CERGY"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"CLIENTS CY TECH"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"CLIENTS CY TECH"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"CLIENT CY TECH"),
    ])

    client_csr, client_privatekey = generate_csr(subject_cert=subject, issuer_cert=subject)

    # Write our CSR out to disk.

    os.makedirs("CA_ROOT_DEV/CA_CLIENT/", exist_ok=True)

    with open("CA_ROOT_DEV/CA_CLIENT/sub_csr.pem", "wb") as pub_key:
        pub_key.write(client_csr.public_bytes(serialization.Encoding.PEM))

    with open("CA_ROOT_DEV/CA_CLIENT/sub_key.pem", "wb") as pub_key:
        pub_key.write(client_privatekey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))

    print(Fore.LIGHTGREEN_EX, "Terminé!", Fore.RESET, end=None)

    print("Génération du CA intermédiaire (Serveur)...", end="")
    # Generate our key

    subject = x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"VAL D'OISE"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"CERGY"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SERVEUR CY TECH"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"SERVEUR CY TECH"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"SERVEUR CY TECH"),
    ])

    serveur_csr, serveur_privatekey = generate_csr(subject_cert=subject, issuer_cert=subject)

    # Write our CSR out to disk.

    os.makedirs("CA_ROOT_DEV/CA_SERVER/", exist_ok=True)

    with open("CA_ROOT_DEV/CA_SERVER/sub_csr.pem", "wb") as pub_key:
        pub_key.write(serveur_csr.public_bytes(serialization.Encoding.PEM))

    with open("CA_ROOT_DEV/CA_SERVER/sub_key.pem", "wb") as pub_key:
        pub_key.write(serveur_privatekey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))

    print(Fore.LIGHTGREEN_EX, "Terminé!", Fore.RESET, end=None)
    print("Génération du certificat (prof@cy-tech.fr)...", end="")
    # Generate our key

    subject = x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"VAL D'OISE"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"CERGY"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"prof"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"prof"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"PROF cy tech"),
    ])

    prof_csr, prof_privatekey = generate_csr(subject_cert=subject, issuer_cert=subject)

    # Write our CSR out to disk.

    os.makedirs("CA_ROOT_DEV/CA_CLIENT/PROF/", exist_ok=True)

    with open("CA_ROOT_DEV/CA_CLIENT/PROF/sub_csr.pem", "wb") as pub_key:
        pub_key.write(prof_csr.public_bytes(serialization.Encoding.PEM))

    with open("CA_ROOT_DEV/CA_CLIENT/PROF/sub_key.pem", "wb") as pub_key:
        pub_key.write(prof_privatekey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))

    print(Fore.LIGHTGREEN_EX, "Terminé!", Fore.RESET, end=None)

    print("Génération du certificat (student@cy-tech.fr)...", end="")
    # Generate our key

    subject = x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"VAL D'OISE"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"CERGY"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"student"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"student"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"STUDENT cy tech"),
        # x509.NameAttribute(NameOID.EMAIL_ADDRESS, u"student@cy-tech.fr"),
    ])

    student_csr, student_privatekey = generate_csr(subject_cert=subject, issuer_cert=subject)

    # Write our CSR out to disk.

    os.makedirs("CA_ROOT_DEV/CA_CLIENT/STUDENT/", exist_ok=True)

    with open("CA_ROOT_DEV/CA_CLIENT/STUDENT/sub_csr.pem", "wb") as pub_key:
        pub_key.write(prof_csr.public_bytes(serialization.Encoding.PEM))

    with open("CA_ROOT_DEV/CA_CLIENT/STUDENT/sub_key.pem", "wb") as pub_key:
        pub_key.write(prof_privatekey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))

    print(Fore.LIGHTGREEN_EX, "Terminé!", Fore.RESET, end=None)
    ## signature du certificat CSR par le root

    # signing csr

    print("Signature du CSR Client par le CA Root...", end="")

    issuer = root_cert.subject

    subject = serveur_csr.subject

    print(211, root_cert, root_cert.__class__.__name__)

    # client
    client_cert = sign_csr(csr_cert=client_csr, issuer_certificate=root_cert, key_to_sign=root_privatekey,
                           add_client_auth=True, add_server_auth=False, is_CA=True, is_Intermediate=True)

    os.remove("CA_ROOT_DEV/CA_CLIENT/sub_csr.pem")
    os.remove("CA_ROOT_DEV/CA_CLIENT/sub_key.pem")

    # Write our certificate out to disk.
    with open("CA_ROOT_DEV/CA_CLIENT/certificate_signed.pem", "wb") as pub_key:
        pub_key.write(client_cert.public_bytes(serialization.Encoding.PEM))

        pub_key.write(b"\n" + root_cert.public_bytes(
            x509.base.serialization.Encoding.PEM
        ))

    with open("CA_ROOT_DEV/CA_CLIENT/sub_key.pem", "wb") as pub_key:
        pub_key.write(client_privatekey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))

    # génère un certificate chain
    print(Fore.LIGHTGREEN_EX, "Terminé!", Fore.RESET, end=None)

    print("Signature du CSR Serveur par le CA Root...", end="")

    subject = serveur_csr.subject

    # client
    serveur_cert = sign_csr(csr_cert=serveur_csr, issuer_certificate=root_cert, key_to_sign=root_privatekey,
                            add_server_auth=True, add_client_auth=False, is_CA=False, is_Intermediate=False, is_for_web=True)

    with contextlib.suppress(FileNotFoundError):
        os.remove("CA_ROOT_DEV/CA_SERVER/sub_key.pem")
        os.remove("CA_ROOT_DEV/CA_SERVER/sub_csr.pem")

    # Write our certificate out to disk.
    with open("CA_ROOT_DEV/CA_SERVER/certificate_signed.pem", "wb") as pub_key:
        pub_key.write(serveur_cert.public_bytes(serialization.Encoding.PEM))

    with open("CA_ROOT_DEV/CA_SERVER/sub_key.pem", "wb") as pub_key:
        pub_key.write(serveur_privatekey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))

    # génère un certificate chain
    print(Fore.LIGHTGREEN_EX, "Terminé!", Fore.RESET, end=None)

    print("Signature du CSR Prof par le CA Client...", end="")

    issuer = client_cert.subject

    # client
    prof_cert = sign_csr(csr_cert=prof_csr, issuer_certificate=client_cert, key_to_sign=client_privatekey,
                         add_client_auth=True, add_server_auth=False, is_CA=False, is_Intermediate=False)

    with contextlib.suppress(FileNotFoundError):
        os.remove("CA_ROOT_DEV/CA_CLIENT/PROF/sub_csr.pem")
        os.remove("CA_ROOT_DEV/CA_CLIENT/PROF/sub_key.pem")

    # Write our certificate out to disk.
    with open("CA_ROOT_DEV/CA_CLIENT/PROF/certificate_signed.pem", "wb") as pub_key:
        pub_key.write(prof_cert.public_bytes(serialization.Encoding.PEM))

        pub_key.write(b"\n" + client_cert.public_bytes(
            x509.base.serialization.Encoding.PEM
        ))
        pub_key.write(b"\n" + root_cert.public_bytes(
            x509.base.serialization.Encoding.PEM
        ))

    with open("CA_ROOT_DEV/CA_CLIENT/PROF/sub_key.pem", "wb") as pub_key:
        pub_key.write(prof_privatekey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # génère un certificate chain
    print(Fore.LIGHTGREEN_EX, "Terminé!", Fore.RESET, end=None)

    print("Signature du CSR Student par le CA Client...", end="")

    # client
    student_cert = sign_csr(csr_cert=student_csr, issuer_certificate=client_cert, key_to_sign=client_privatekey,
                            add_client_auth=True, add_server_auth=False, is_CA=False, is_Intermediate=False)

    with contextlib.suppress(FileNotFoundError):
        os.remove("CA_ROOT_DEV/CA_CLIENT/STUDENT/sub_csr.pem")
        os.remove("CA_ROOT_DEV/CA_CLIENT/STUDENT/sub_key.pem")

    # Write our certificate out to disk.
    with open("CA_ROOT_DEV/CA_CLIENT/STUDENT/certificate_signed.pem", "wb") as pub_key:
        pub_key.write(student_cert.public_bytes(serialization.Encoding.PEM))

        pub_key.write(b"\n" + client_cert.public_bytes(
            x509.base.serialization.Encoding.PEM
        ))
        pub_key.write(b"\n" + root_cert.public_bytes(
            x509.base.serialization.Encoding.PEM
        ))

    with open("CA_ROOT_DEV/CA_CLIENT/STUDENT/sub_key.pem", "wb") as pub_key:
        pub_key.write(student_privatekey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # génère un certificate chain
    print(Fore.LIGHTGREEN_EX, "Terminé!", Fore.RESET, end=None)

    # print(cert.public_key().public_bytes(
    #     Encoding.PEM,
    #     PublicFormat.PKCS1
    # ))

    print("\nSUJET ROOT ", colorama.Fore.LIGHTCYAN_EX, root_cert.issuer, colorama.Fore.RESET)

    # verification :

    try:
        print("SUJET CLIENT", colorama.Fore.LIGHTCYAN_EX, client_cert.subject, colorama.Fore.RESET)
        print("Verification de la hiérarchie de (ROOT > CLIENT)... ", end="")
        root_cert.public_key().verify(
            signature=client_cert.signature,
            data=client_cert.tbs_certificate_bytes,
            padding=hazmat.primitives.asymmetric.padding.PKCS1v15(),
            algorithm=client_cert.signature_hash_algorithm
        )
        print(Fore.LIGHTGREEN_EX + "Succès!" + Fore.RESET)
        print("SUJET SERVER", colorama.Fore.LIGHTCYAN_EX, serveur_cert.subject, colorama.Fore.RESET)
        print("Verification de la hiérarchie de (ROOT > SERVEUR)... ", end="")
        root_cert.public_key().verify(
            signature=serveur_cert.signature,
            data=serveur_cert.tbs_certificate_bytes,
            padding=hazmat.primitives.asymmetric.padding.PKCS1v15(),
            algorithm=serveur_cert.signature_hash_algorithm
        )
        print(Fore.LIGHTGREEN_EX + "Succès!" + Fore.RESET)
        print("SUJET PROF", colorama.Fore.LIGHTCYAN_EX, prof_cert.subject, colorama.Fore.RESET)
        print("Verification de la hiérarchie de (ROOT > CLIENT > PROF)... ", end="")
        client_cert.public_key().verify(
            signature=prof_cert.signature,
            data=prof_cert.tbs_certificate_bytes,
            padding=hazmat.primitives.asymmetric.padding.PKCS1v15(),
            algorithm=prof_cert.signature_hash_algorithm
        )
        print(Fore.LIGHTGREEN_EX + "Succès!" + Fore.RESET)
        print("SUJET CLIENT", colorama.Fore.LIGHTCYAN_EX, student_cert.subject, colorama.Fore.RESET)
        print("Verification de la hiérarchie de (ROOT > CLIENT > STUDENT)... ", end="")
        client_cert.public_key().verify(
            signature=student_cert.signature,
            data=student_cert.tbs_certificate_bytes,
            padding=hazmat.primitives.asymmetric.padding.PKCS1v15(),
            algorithm=student_cert.signature_hash_algorithm
        )
    except Exception as exc:
        print(Fore.LIGHTRED_EX + "Erreur !" + Fore.RESET)
        exit(exc)
        # exit(InvalidSignature("Le certificat n'a pas pu être validé. Il y a une erreur."))
    else:
        print(Fore.LIGHTGREEN_EX + "Succès!\n" + Fore.RESET)

    # génération des pkcs12
    print("Génération du PKCS12 du prof... ", end="")

    # On génère le PKCS12 du prof

    prof_pkcs12 = serialize_key_and_certificates(name=b"prof",
                                                 key=prof_privatekey,
                                                 cert=prof_cert,
                                                 cas=(root_cert, client_cert),
                                                 encryption_algorithm=serialization.BestAvailableEncryption(
                                                     b"passphrase"))

    with open("CA_ROOT_DEV/CA_CLIENT/PROF/prof.p12", "wb") as f:
        f.write(prof_pkcs12)

    print(Fore.LIGHTGREEN_EX, "Terminé!", Fore.RESET, end=None)
    print("Génération du PKCS12 de l'étudiant... ", end="")

    # On génère le PKCS12 de l'étudiant
    student_pkcs12 = serialize_key_and_certificates(name=b"prof",
                                                    key=student_privatekey,
                                                    cert=student_cert,
                                                    cas=(root_cert, client_cert),
                                                    encryption_algorithm=serialization.BestAvailableEncryption(
                                                        b"passphrase"))

    # encryption = (
    #     PrivateFormat.PKCS12.encryption_builder().kdf_rounds(50000).
    #     key_cert_algorithm(pkcs12.PBES.PBESv2SHA256AndAES256CBC).
    #     hmac_hash(hashes.SHA1()).build(b"passphrase")
    # )
    # cert = student_cert
    # key = student_privatekey
    # p12 = pkcs12.serialize_key_and_certificates(b"friendlyname", key, None, None, encryption)

    with open("CA_ROOT_DEV/CA_CLIENT/STUDENT/student.p12", "wb") as f:
        f.write(student_pkcs12)

    #problème sur macOS. faire :
    # openssl pkcs12 -export -out /Users/loic2/PycharmProjects/ssl_certs_script/CA_ROOT/CA_CLIENT/STUDENT/pfx.p12 -inkey /Users/loic2/PycharmProjects/ssl_certs_script/CA_ROOT/CA_CLIENT/STUDENT/sub_key.pem -in /Users/loic2/PycharmProjects/ssl_certs_script/CA_ROOT/CA_CLIENT/STUDENT/certificate_signed.pem -certfile /Users/loic2/PycharmProjects/ssl_certs_script/CA_ROOT/CA_CLIENT/certificate_signed.pem

    print(Fore.LIGHTGREEN_EX, "Terminé!", Fore.RESET, end=None)
