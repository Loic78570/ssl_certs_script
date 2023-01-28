openssl pkcs12 -export -out /Users/loic2/PycharmProjects/ssl_certs_script/CA_ROOT2/CA_CLIENT/STUDENT/pfx.p12 \
-inkey /Users/loic2/PycharmProjects/ssl_certs_script/CA_ROOT2/CA_CLIENT/STUDENT/sub_key.pem \
-in /Users/loic2/PycharmProjects/ssl_certs_script/CA_ROOT2/CA_CLIENT/STUDENT/certificate_signed.pem \
-certfile /Users/loic2/PycharmProjects/ssl_certs_script/CA_ROOT2/CA_CLIENT/certificate_signed.pem \
-password "pass:passphrase"

openssl pkcs12 -export -out /Users/loic2/PycharmProjects/ssl_certs_script/CA_ROOT2/CA_CLIENT/PROF/pfx.p12 \
-inkey /Users/loic2/PycharmProjects/ssl_certs_script/CA_ROOT2/CA_CLIENT/PROF/sub_key.pem \
-in /Users/loic2/PycharmProjects/ssl_certs_script/CA_ROOT2/CA_CLIENT/PROF/certificate_signed.pem \
-certfile /Users/loic2/PycharmProjects/ssl_certs_script/CA_ROOT2/CA_CLIENT/certificate_signed.pem \
-password "pass:passphrase"