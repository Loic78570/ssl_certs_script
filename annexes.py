import datetime

import colorama
from OpenSSL.crypto import X509StoreContextError
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from mainv2 import debug


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


def generate_cert(subject_cert: x509.Name | x509.Certificate, issuer_cert: x509.Certificate | x509.Name, key_to_sign: rsa.RSAPrivateKey,
                  public_key: rsa.RSAPublicKey, add_client_auth: bool = False, add_server_auth=False, is_CA=False,
                  is_Intermediate=False, is_ROOT=False, is_for_web_server=False):
    """
    Cette fonction génère un certificat.
    Elle prend en paramètre un certificat sujet, un certificat émetteur, une clé privée et une clé publique.
    :param subject_cert: Certificat sujet
    :param issuer_cert: Certificat émetteur
    :param key_to_sign: Clé privée
    :param public_key: Clé publique
    :param add_client_auth: Booléen pour ajouter l'extension client auth
    :param add_server_auth: Booléen pour ajouter l'extension server auth
    :param is_CA: Booléen pour ajouter qui ajoute l'extension CA et qui indique que le certificat est une CA
    :param is_Intermediate: Booléen pour ajouter qui ajoute l'extension CA et qui indique que le certificat est un intermédiaire
    :param is_ROOT: Booléen pour ajouter qui ajoute l'extension CA et qui indique que le certificat est
    :param is_for_web_server: Booléen pour ajouter l'extension pour un serveur web (sans le client auth)
    :return: Le certificat généré et signé par la clé privée et le certificat émetteur passés en paramètres
    """

    if (type(issuer_cert) is x509.Certificate) or (issuer_cert.__class__.__name__ == "Certificate"):
        print("Issuer cert is a x509.Certificate") if debug else None
        issuer_name = issuer_cert.subject
    elif type(issuer_cert) is x509.Name:
        print("Issuer cert is a x509.Name") if debug else None
        issuer_name = issuer_cert
    else:
        print("issuer_cert is type: %s" % type(issuer_cert)) if debug else None
        print(issuer_cert.subject) if debug else None
        raise TypeError("issuer_cert must be a x509.Certificate or a x509.Name")

    if (type(subject_cert) is x509.Certificate) or subject_cert.__class__.__name__ == "Certificate":
        print("Subject cert is a x509.Certificate") if debug else None
        subject_name = subject_cert.subject
    elif type(subject_cert) is x509.Name:
        print("Subject cert is a x509.Name") if debug else None
        subject_name = subject_cert
    else:
        print("issuer_cert is type: %s" % type(issuer_cert)) if debug else None
        print(issuer_cert.subject) if debug else None
        raise TypeError("issuer_cert must be a x509.Certificate or a x509.Name")

    cert = x509.CertificateBuilder(
        subject_name=subject_name, issuer_name=issuer_name, public_key=public_key,
        serial_number=x509.random_serial_number(), not_valid_before=datetime.datetime.utcnow(),
        not_valid_after=datetime.datetime.utcnow() + datetime.timedelta(days=500)
    )

    if is_ROOT:
        cert = cert.add_extension(
            x509.BasicConstraints(ca=True, path_length=2), critical=True
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
        )

    elif is_Intermediate: # intermediate is obviously a CA
        cert = cert.add_extension(
            x509.BasicConstraints(ca=True, path_length=2), critical=True
            # Attention à adapter path_length en fonction du nombre d'intermédiaires
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
        )

    else:
        cert = cert.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(u"localhost"),
                x509.DNSName(u"cy-tech.fr")
            ]),
            critical=True,
    )

    if is_ROOT:
        cert = cert.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key), critical=False
        )

    else:  # not root -> intermediate pub key
        cert = cert.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()), critical=False
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
            x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True,
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
        x509.ExtendedKeyUsage(
            [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]
        ), critical=False
    ).sign(key_priv, hashes.SHA512())

    return csr, key_priv


def sign_csr(csr_cert: x509.CertificateSigningRequest, issuer_certificate: x509.Certificate,
             key_to_sign: rsa.RSAPrivateKey,
             add_client_auth=False, add_server_auth=False, is_CA=False, is_Intermediate=False, is_for_web=False):
    return generate_cert(subject_cert=csr_cert.subject, issuer_cert=issuer_certificate, key_to_sign=key_to_sign,
                         public_key=csr_cert.public_key(), add_client_auth=add_client_auth,
                         add_server_auth=add_server_auth, is_CA=is_CA, is_Intermediate=is_Intermediate, is_ROOT=False,
                         is_for_web_server=is_for_web)


from OpenSSL import crypto


def verify():
    """
    Programme qui exécute une vérification des certificats créés
    :return:
    """
    with open('./CA_ROOT/CA_SERVER/certificate_signed.pem', 'r') as cert_file:
        serveur_cert = cert_file.read()

    with open('./CA_ROOT/CA_CLIENT/PROF/certificate_signed.pem', 'r') as cert_file:
        prof_cert = cert_file.read()

    with open('./CA_ROOT/CA_CLIENT/STUDENT/certificate_signed.pem', 'r') as cert_file:
        student_cert = cert_file.read()

    with open('./CA_ROOT/CA_CLIENT/certificate_signed.pem', 'r') as int_cert_file:
        client_cert = int_cert_file.read()

    with open('./CA_ROOT/certificate.pem', 'r') as root_cert_file:
        root_cert = root_cert_file .read()

    trusted_certs = (client_cert, root_cert)

    for cert in (serveur_cert, prof_cert, student_cert):
        verified = verify_chain_of_trust(cert, trusted_certs)

        if verified:
            print(colorama.Fore.LIGHTGREEN_EX, f'Certificate verified', colorama.Fore.RESET)
        else:
            print(colorama.Fore.LIGHTRED_EX, f'Certificate not verified', colorama.Fore.RESET, cert)


def verify_chain_of_trust(cert_pem, trusted_cert_pems):
    """
    Vérifie la chaîne de confiance d'un certificat.
    :param cert_pem: Certificat à vérifier
    :param trusted_cert_pems: Liste des certificats de confiance
    :return: True si le certificat est valide, False sinon
    """

    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

    # Create and fill a X509Sore with trusted certs
    store = crypto.X509Store()
    for trusted_cert_pem in trusted_cert_pems:
        trusted_cert = crypto.load_certificate(crypto.FILETYPE_PEM, trusted_cert_pem)
        store.add_cert(trusted_cert)

    # Create a X590StoreContext with the cert and trusted certs
    # and verify the the chain of trust
    store_ctx = crypto.X509StoreContext(store, certificate)
    # Returns None if certificate can be validated

    try:
        store_ctx.verify_certificate()
        print("\t✅", end="")
        val = True
    except X509StoreContextError as e:
        # print(e)
        print("\t❌", end="")
        val = False
    finally:
        print("", certificate.get_issuer().CN, ">", certificate.get_subject().CN, end="")
        return val
