#!/bin/bash

set -eoux pipefail

tpm2_startauthsession -S session.ctx
# prints 0d84f55daf6e43ac97966e62c9bb989d3397777d25c5f749868055d65394f952
tpm2_policysecret -S session.ctx -L policy.dat -c o
tpm2_flushcontext session.ctx

tpm2_createprimary -C o \
    -g sha256 \
    -G ecc \
    -c primary.ctx \
    -L policy.dat \
    -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|adminwithpolicy'

tpm2_startauthsession --policy-session -S policy.ctx
tpm2_policysecret -S policy.ctx -L policy.dat -c o
tpm2_create -C primary.ctx -G ecc -c key.ctx -P session:policy.ctx

tpm2_flushcontext policy.ctx
tpm2_flushcontext -t
tpm2_flushcontext -s
