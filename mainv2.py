import contextlib
import os

from colorama import Fore
from cryptography import hazmat
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
from cryptography.x509.base import serialization
from cryptography.x509.oid import NameOID

from annexes import *

debug = False

if __name__ == "__main__":
    # ----------------------- START - Génération du CA root ------------------------- #
    print("Génération du CA root...", end="")

    subject = issuer = x509.Name([  # Create subject
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Val d'Oise"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Cergy"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"CY TECH"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"CY TECH"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"ROOT CY TECH"),
    ])

    root_cert, root_private_key = generate_root_CA(subject,
                                                   issuer)  # Generate Root CA certificate and private key

    os.makedirs("CA_ROOT_DEV", exist_ok=True)  # Create directory for Root CA

    with open("CA_ROOT_DEV/certificate.pem", "wb") as pub_key:  # Write Root CA public key
        pub_key.write(root_cert.public_bytes(serialization.Encoding.PEM))

    with open("CA_ROOT_DEV/key.pem", "wb") as file:  # Write Root CA private key
        file.write(root_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))

    print(Fore.LIGHTGREEN_EX, "Terminé!", Fore.RESET, end=None)
    # ----------------------- END - Génération du CA root ------------------------- #

    # ----------------------- START - Génération du CA intermédiaire (Client) ------------------------- #
    print("Génération du CA intermédiaire (Client)...", end="")

    subject = x509.Name([  # Create subject
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"VAL D'OISE"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"CERGY"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"CLIENTS CY TECH"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"CLIENTS CY TECH"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"CLIENT CY TECH"),
    ])

    client_csr, client_private_key = generate_csr(subject_cert=subject,
                                                  issuer_cert=subject)  # Generate CSR and private key

    os.makedirs("CA_ROOT_DEV/CA_CLIENT/", exist_ok=True)  # Create directory for Client CA in Root CA directory

    with open("CA_ROOT_DEV/CA_CLIENT/sub_csr.pem", "wb") as pub_key:  # Write Client CA CSR
        pub_key.write(client_csr.public_bytes(serialization.Encoding.PEM))

    with open("CA_ROOT_DEV/CA_CLIENT/sub_key.pem", "wb") as pub_key:  # Write Client CA private key
        pub_key.write(client_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))

    print(Fore.LIGHTGREEN_EX, "Terminé!", Fore.RESET, end=None)
    # ----------------------- END - Génération du CA intermédiaire (Client) ------------------------- #

    # ----------------------- START - Génération du CA intermédiaire (Serveur) ------------------------- #
    print("Génération du CA intermédiaire (Serveur)...", end="")

    subject = x509.Name([  # Create subject
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"VAL D'OISE"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"CERGY"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SERVEUR CY TECH"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"SERVEUR CY TECH"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"SERVEUR CY TECH"),
    ])

    serveur_csr, serveur_private_key = generate_csr(subject_cert=subject,
                                                    issuer_cert=subject)  # Generate CSR and private key

    os.makedirs("CA_ROOT_DEV/CA_SERVER/", exist_ok=True)  # Create directory for Server CA in Root CA directory

    with open("CA_ROOT_DEV/CA_SERVER/sub_csr.pem", "wb") as pub_key:  # Write Server CA CSR
        pub_key.write(serveur_csr.public_bytes(serialization.Encoding.PEM))

    with open("CA_ROOT_DEV/CA_SERVER/sub_key.pem", "wb") as pub_key:  # Write Server CA private key
        pub_key.write(serveur_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))

    print(Fore.LIGHTGREEN_EX, "Terminé!", Fore.RESET, end=None)
    # ----------------------- END - Génération du CA intermédiaire (Serveur) ------------------------- #

    # ----------------------- START - Génération du certificat (prof@cy-tech.fr) ------------------------- #
    print("Génération du certificat (prof@cy-tech.fr)...", end="")

    subject = x509.Name([  # Create subject
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"VAL D'OISE"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"CERGY"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"prof"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"prof"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"PROF cy tech"),
    ])

    prof_csr, prof_private_key = generate_csr(subject_cert=subject,
                                              issuer_cert=subject)  # Generate CSR and private key

    os.makedirs("CA_ROOT_DEV/CA_CLIENT/PROF/", exist_ok=True)  # Create directory for Prof CA in Client CA directory

    with open("CA_ROOT_DEV/CA_CLIENT/PROF/sub_csr.pem", "wb") as pub_key:  # Write Prof CA CSR
        pub_key.write(prof_csr.public_bytes(serialization.Encoding.PEM))

    with open("CA_ROOT_DEV/CA_CLIENT/PROF/sub_key.pem", "wb") as pub_key:  # Write Prof CA private key
        pub_key.write(prof_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))

    print(Fore.LIGHTGREEN_EX, "Terminé!", Fore.RESET, end=None)
    # ----------------------- END - Génération du certificat (prof@cy-tech.fr) ------------------------- #

    # ----------------------- START - Génération du certificat (student@cy-tech.fr) ------------------------- #
    print("Génération du certificat (student@cy-tech.fr)...", end="")

    subject = x509.Name([  # Create subject
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"VAL D'OISE"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"CERGY"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"student"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"student"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"STUDENT cy tech"),
    ])

    student_csr, student_private_key = generate_csr(subject_cert=subject,
                                                    issuer_cert=subject)  # Generate CSR and private key

    os.makedirs("CA_ROOT_DEV/CA_CLIENT/STUDENT/", exist_ok=True)  # Create directory for Student CA in Client CA
    # directory

    with open("CA_ROOT_DEV/CA_CLIENT/STUDENT/sub_csr.pem", "wb") as pub_key:  # Write Student CA CSR
        pub_key.write(prof_csr.public_bytes(serialization.Encoding.PEM))

    with open("CA_ROOT_DEV/CA_CLIENT/STUDENT/sub_key.pem", "wb") as pub_key:  # Write Student CA private key
        pub_key.write(prof_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))

    print(Fore.LIGHTGREEN_EX, "Terminé!", Fore.RESET, end=None)
    # ----------------------- END - Génération du certificat (student@cy-tech.fr) ------------------------- #

    # ----------------------- START - Signature du CSR Client par le CA Root ------------------------- #
    print("Signature du CSR Client par le CA Root...", end="")

    issuer = root_cert.subject  # Get issuer
    subject = serveur_csr.subject  # Get subject

    print(211, root_cert, root_cert.__class__.__name__)

    client_cert = sign_csr(csr_cert=client_csr, issuer_certificate=root_cert, key_to_sign=root_private_key,
                           add_client_auth=True, add_server_auth=False, is_CA=True, is_Intermediate=True)  # Sign CSR

    os.remove("CA_ROOT_DEV/CA_CLIENT/sub_csr.pem")  # Remove CSR CLIENT
    os.remove("CA_ROOT_DEV/CA_CLIENT/sub_key.pem")  # Remove private key CLIENT

    with open("CA_ROOT_DEV/CA_CLIENT/certificate_signed.pem", "wb") as pub_key:  # Write signed certificate
        pub_key.write(client_cert.public_bytes(serialization.Encoding.PEM))
        pub_key.write(b"\n" + root_cert.public_bytes(
            x509.base.serialization.Encoding.PEM
        ))

    with open("CA_ROOT_DEV/CA_CLIENT/sub_key.pem", "wb") as pub_key:  # Write private key CLIENT
        pub_key.write(client_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))

    print(Fore.LIGHTGREEN_EX, "Terminé!", Fore.RESET, end=None)
    # ----------------------- END - Signature du CSR Client par le CA Root ------------------------- #

    # ----------------------- START - Signature du CSR Serveur par le CA Root ------------------------- #
    print("Signature du CSR Serveur par le CA Root...", end="")

    serveur_cert = sign_csr(csr_cert=serveur_csr, issuer_certificate=root_cert, key_to_sign=root_private_key,
                            add_server_auth=True, add_client_auth=False, is_CA=False, is_Intermediate=False,
                            is_for_web=True)  # Sign CSR

    with contextlib.suppress(FileNotFoundError):  # Remove CSR and private key
        os.remove("CA_ROOT_DEV/CA_SERVER/sub_key.pem")
        os.remove("CA_ROOT_DEV/CA_SERVER/sub_csr.pem")

    with open("CA_ROOT_DEV/CA_SERVER/certificate_signed.pem", "wb") as pub_key:  # Write signed certificate
        pub_key.write(serveur_cert.public_bytes(serialization.Encoding.PEM))

    with open("CA_ROOT_DEV/CA_SERVER/sub_key.pem", "wb") as pub_key:  # Write private key
        pub_key.write(serveur_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))

    print(Fore.LIGHTGREEN_EX, "Terminé!", Fore.RESET, end=None)
    # ----------------------- END - Signature du CSR Serveur par le CA Root ------------------------- #

    # ----------------------- START - Signature du CSR Prof par le CA Client ------------------------- #
    print("Signature du CSR Prof par le CA Client...", end="")

    prof_cert = sign_csr(csr_cert=prof_csr, issuer_certificate=client_cert, key_to_sign=client_private_key,
                         add_client_auth=True, add_server_auth=False, is_CA=False, is_Intermediate=False)  # Sign CSR

    with contextlib.suppress(FileNotFoundError):  # Remove CSR and private key
        os.remove("CA_ROOT_DEV/CA_CLIENT/PROF/sub_csr.pem")
        os.remove("CA_ROOT_DEV/CA_CLIENT/PROF/sub_key.pem")

    with open("CA_ROOT_DEV/CA_CLIENT/PROF/certificate_signed.pem", "wb") as pub_key:  # Write signed certificate
        pub_key.write(prof_cert.public_bytes(serialization.Encoding.PEM))
        pub_key.write(b"\n" + client_cert.public_bytes(
            x509.base.serialization.Encoding.PEM
        ))
        pub_key.write(b"\n" + root_cert.public_bytes(
            x509.base.serialization.Encoding.PEM
        ))

    with open("CA_ROOT_DEV/CA_CLIENT/PROF/sub_key.pem", "wb") as pub_key:  # Write private key
        pub_key.write(prof_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    print(Fore.LIGHTGREEN_EX, "Terminé!", Fore.RESET, end=None)
    # ----------------------- END - Signature du CSR Prof par le CA Client ------------------------- #

    # ----------------------- START - Signature du CSR Student par le CA Client ------------------------- #
    print("Signature du CSR Student par le CA Client...", end="")

    student_cert = sign_csr(csr_cert=student_csr, issuer_certificate=client_cert, key_to_sign=client_private_key,
                            add_client_auth=True, add_server_auth=False, is_CA=False, is_Intermediate=False)  # Sign CSR

    with contextlib.suppress(FileNotFoundError):  # Remove CSR and private key
        os.remove("CA_ROOT_DEV/CA_CLIENT/STUDENT/sub_csr.pem")
        os.remove("CA_ROOT_DEV/CA_CLIENT/STUDENT/sub_key.pem")

    # Write our certificate out to disk.
    with open("CA_ROOT_DEV/CA_CLIENT/STUDENT/certificate_signed.pem", "wb") as pub_key:  # Write signed certificate
        pub_key.write(student_cert.public_bytes(serialization.Encoding.PEM))
        pub_key.write(b"\n" + client_cert.public_bytes(
            x509.base.serialization.Encoding.PEM
        ))
        pub_key.write(b"\n" + root_cert.public_bytes(
            x509.base.serialization.Encoding.PEM
        ))

    with open("CA_ROOT_DEV/CA_CLIENT/STUDENT/sub_key.pem", "wb") as pub_key:  # Write private key
        pub_key.write(student_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    print(Fore.LIGHTGREEN_EX, "Terminé!", Fore.RESET, end=None)
    # ----------------------- END - Signature du CSR Student par le CA Client ------------------------- #

    print("\nSUJET ROOT ", colorama.Fore.LIGHTCYAN_EX, root_cert.issuer, colorama.Fore.RESET)

    # ----------------------- START - Vérification des certificats et des signatures ------------------------- #
    try:
        print("SUJET CLIENT", colorama.Fore.LIGHTCYAN_EX, client_cert.subject, colorama.Fore.RESET)
        print("Verification de la hiérarchie de (ROOT > CLIENT)... ", end="")
        root_cert.public_key().verify(  # Verify signature of client certificate
            signature=client_cert.signature,
            data=client_cert.tbs_certificate_bytes,
            padding=hazmat.primitives.asymmetric.padding.PKCS1v15(),
            algorithm=client_cert.signature_hash_algorithm
        )
        print(Fore.LIGHTGREEN_EX + "Succès!" + Fore.RESET)
        print("SUJET SERVER", colorama.Fore.LIGHTCYAN_EX, serveur_cert.subject, colorama.Fore.RESET)
        print("Verification de la hiérarchie de (ROOT > SERVEUR)... ", end="")
        root_cert.public_key().verify(  # Verify signature of server certificate
            signature=serveur_cert.signature,
            data=serveur_cert.tbs_certificate_bytes,
            padding=hazmat.primitives.asymmetric.padding.PKCS1v15(),
            algorithm=serveur_cert.signature_hash_algorithm
        )
        print(Fore.LIGHTGREEN_EX + "Succès!" + Fore.RESET)
        print("SUJET PROF", colorama.Fore.LIGHTCYAN_EX, prof_cert.subject, colorama.Fore.RESET)
        print("Verification de la hiérarchie de (ROOT > CLIENT > PROF)... ", end="")
        client_cert.public_key().verify(  # Verify signature of prof certificate
            signature=prof_cert.signature,
            data=prof_cert.tbs_certificate_bytes,
            padding=hazmat.primitives.asymmetric.padding.PKCS1v15(),
            algorithm=prof_cert.signature_hash_algorithm
        )
        print(Fore.LIGHTGREEN_EX + "Succès!" + Fore.RESET)
        print("SUJET CLIENT", colorama.Fore.LIGHTCYAN_EX, student_cert.subject, colorama.Fore.RESET)
        print("Verification de la hiérarchie de (ROOT > CLIENT > STUDENT)... ", end="")
        client_cert.public_key().verify(  # Verify signature of student certificate
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

    print("Verification de la validité des certificats... ")
    verify()
    print("Terminé!\n")

    # ----------------------- END - Vérification des certificats et des signatures ------------------------- #
    # ----------------------- START - Génération des PKCS12 (Prof et Student) ------------------------- #
    print("Génération du PKCS12 du prof... ", end="")

    prof_pkcs12 = serialize_key_and_certificates(name=b"prof",
                                                 key=prof_private_key,
                                                 cert=prof_cert,
                                                 cas=(root_cert, client_cert),
                                                 encryption_algorithm=serialization.BestAvailableEncryption(
                                                     b"passphrase"))  # Generate prof PKCS12

    with open("CA_ROOT_DEV/CA_CLIENT/PROF/prof.p12", "wb") as f:  # Write prof PKCS12
        f.write(prof_pkcs12)

    print(Fore.LIGHTGREEN_EX, "Terminé!", Fore.RESET, end=None)
    print("Génération du PKCS12 de l'étudiant... ", end="")

    student_pkcs12 = serialize_key_and_certificates(name=b"prof",
                                                    key=student_private_key,
                                                    cert=student_cert,
                                                    cas=(root_cert, client_cert),
                                                    encryption_algorithm=serialization.BestAvailableEncryption(
                                                        b"passphrase"))  # Generate student PKCS12

    with open("CA_ROOT_DEV/CA_CLIENT/STUDENT/student.p12", "wb") as f:  # Write student PKCS12
        f.write(student_pkcs12)

    # problème sur macOS. faire : openssl pkcs12 -export -out
    # /Users/loic2/PycharmProjects/ssl_certs_script/CA_ROOT/CA_CLIENT/STUDENT/pfx.p12 -inkey
    # /Users/loic2/PycharmProjects/ssl_certs_script/CA_ROOT/CA_CLIENT/STUDENT/sub_key.pem -in
    # /Users/loic2/PycharmProjects/ssl_certs_script/CA_ROOT/CA_CLIENT/STUDENT/certificate_signed.pem -certfile
    # /Users/loic2/PycharmProjects/ssl_certs_script/CA_ROOT/CA_CLIENT/certificate_signed.pem

    print(Fore.LIGHTGREEN_EX, "Terminé!", Fore.RESET, end=None)
    # ----------------------- END - Génération des PKCS12 ------------------------- #
