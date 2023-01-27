import colorama
# Following script will create a self signed root ca cert.
from OpenSSL import crypto, SSL
from os.path import join
import random


def generation_x509_autosigné():
    CN = input("Enter the common name of the certificate you want: ")
    pubkey = "%s.crt" % CN  # replace %s with CN
    privkey = "%s.key" % CN  # replcate %s with CN

    pubkey = join(".", pubkey)
    privkey = join(".", privkey)

    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    serialnumber = random.getrandbits(64)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = input("Country: ")
    cert.get_subject().ST = input("State: ")
    cert.get_subject().L = input("City: ")
    cert.get_subject().O = input("Organization: ")
    cert.get_subject().OU = input("Organizational Unit: ")
    cert.get_subject().CN = CN
    cert.set_serial_number(serialnumber)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(31536000)  # 315360000 is in seconds.
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')
    pub = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    priv = crypto.dump_privatekey(crypto.FILETYPE_PEM, k)
    open(pubkey, "wb").write(pub)
    open(privkey, "wb").write(priv)
    return cert, k


def generation_x509():
    CN = input("Enter the common name of the certificate you want: ")
    pubkey = "%s.crt" % CN  # replace %s with CN
    privkey = "%s.key" % CN  # replcate %s with CN

    pubkey = join(".", pubkey)
    privkey = join(".", privkey)

    # k_file = open(privkey, "wb")
    # k = crypto.PKey().from_cryptography_key(privkey)

    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    serialnumber = random.getrandbits(64)

    # create a self-signed cert
    cert = crypto.X509Req()
    cert.get_subject().C = input("Country: ")
    cert.get_subject().ST = input("State: ")
    cert.get_subject().L = input("City: ")
    cert.get_subject().O = input("Organization: ")
    cert.get_subject().OU = input("Organizational Unit: ")
    cert.get_subject().CN = CN
    # cert.set_serial_number(serialnumber)
    # cert.gmtime_adj_notBefore(0)
    # cert.gmtime_adj_notAfter(31536000)  # 315360000 is in seconds.
    # cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    # root_pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, bytes(open("root.key", "wb")))
    cert.sign(k, 'sha256')


    # pub = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    pub = crypto.dump_certificate_request(crypto.FILETYPE_PEM, cert)
    priv = crypto.dump_privatekey(crypto.FILETYPE_PEM, k)
    open(pubkey, "wb").write(pub)
    open(privkey, "wb").write(priv)
    return cert, k


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    # ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, 'root.key')
    pub_root, priv_root = generation_x509_autosigné()

    # crypto.load_privatekey(crypto.FILETYPE_PEM, priv_root)
    # xxxx = open("test.txt", "wb").write(priv_root)
    # crypto.load_privatekey(crypto.FILETYPE_PEM, open("test.txt", "rb").read())

    pub_sub, priv_sub = generation_x509()

    serialnumber = random.getrandbits(64)
    ca_cert = pub_root
    ca_key = priv_root
    certs = crypto.X509()
    csr_req = pub_sub
    certs.set_serial_number(serialnumber)
    certs.gmtime_adj_notBefore(0)
    certs.gmtime_adj_notAfter(31536000)
    certs.set_subject(csr_req.get_subject())
    certs.set_issuer(ca_cert.get_subject())
    # certs.set_pubkey(k)

    certs.sign(ca_key, 'sha256')
    certificate = crypto.dump_certificate(crypto.FILETYPE_PEM, certs)

    open("zzz.pem", "wb").write(certificate)
    open("zzz.txt", "wb").write(crypto.dump_certificate(crypto.FILETYPE_TEXT, certs))
    open("zzz.private.pem", "wb").write(priv_sub.to_cryptography_key().private_bytes())


# See PyCharm help at https://www.jetbrains.com/help/pycharm/
