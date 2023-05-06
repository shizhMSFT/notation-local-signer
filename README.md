# Notation Local Signer plugin for Github Action

This plugin can be tested locally by

```bash
# install plugin
make install

# generate a key / cert bundle to sign and verify
make rotate-key

# add signing key
# note: SIGNING_KEY can be set as repository secret from Github
# ref: https://docs.github.com/en/actions/security-guides/encrypted-secrets
notation key add --plugin local-signer --id `pwd`/notation.crt --plugin-config env=SIGNING_KEY --default local
export SIGNING_KEY=`cat notation.key | base64 -w0`

# build, push, and sign
export NOTATION_EXPERIMENTAL=1
echo hello > hello.txt
oras push --oci-layout hello:v1 hello.txt
notation sign --oci-layout hello:v1
```

Since `notation` currently does not support signing a single file but artifacts, the experience of signing GitHub release is still incomplete.
