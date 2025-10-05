#!/bin/bash

set -eoux pipefail

HASH=$(sha256sum /etc/passwd | awk '{ print $1; }')

tpm2_pcrreset 23
tpm2_pcrextend 23:sha256=$HASH

tpm2_startauthsession -S policy.ctx
tpm2_policypcr -S policy.ctx -l sha256:23 -L policy.dat
tpm2_flushcontext policy.ctx

tpm2_createprimary -C o -g sha256 -G ecc -c primary.ctx
echo fuck_russia | tpm2_create -C primary.ctx -c key.ctx -L policy.dat -i- -u key.pub -r key.priv
tpm2_flushcontext -tls

tpm2_startauthsession --policy-session -S policy.ctx
tpm2_policypcr -S policy.ctx -l sha256:23
tpm2_unseal -c key.ctx -p session:policy.ctx
tpm2_flushcontext policy.ctx

tpm2_flushcontext -tls
