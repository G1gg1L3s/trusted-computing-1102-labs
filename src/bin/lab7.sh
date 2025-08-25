#!/bin/bash

set -eoux pipefail

sudo tpm2_getekcertificate -o /dev/null -o ecc-p256.cert.der
openssl x509 -in ecc-p256.cert.der -inform der -out ecc-p256.cert.pem

echo -n '\n\n'
openssl x509 -in ecc-p256.cert.pem -text -noout

sudo tpm2_createek -c primary.ctx -G ecc -Q
sudo tpm2_readpublic -c primary.ctx -o ek-p256.pem -f PEM -Q

openssl x509 -pubkey -in ecc-p256.cert.pem --noout -out ek-p256.cert.pub.pem
diff ek-p256.pem ek-p256.cert.pub.pem

if [ ! -f "stmtpmeccint02.crt" ]; then
    curl https://secure.globalsign.com/stmtpmeccint02.crt | \
        openssl x509 -inform der -outform pem > stmtpmeccint02.crt
fi

if [ ! -f "stmtpmeccroot01.crt" ]; then
    curl https://secure.globalsign.com/cacert/stmtpmeccroot01.crt | \
        openssl x509 -inform der -outform pem > stmtpmeccroot01.crt
fi

openssl verify -show_chain -partial_chain -trusted stmtpmeccroot01.crt -untrusted stmtpmeccint02.crt ecc-p256.cert.pem
