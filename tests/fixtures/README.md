# Credential fixtures

These are published test keys for tests only. Never deploy them.

`rfc9529.json`, `i.ccs` and `r.ccs` contain the published RFC 9529 method-3,
suite-2 test material. These keys are public test vectors.

`client-kid-01.ccs` and `node-empty-kid.ccs` use the same initiator and responder
keys in minimal CCS credentials without a subject. The client credential has
`kid=0x01` and both public-key coordinates; the node credential has an empty
`kid` and only the public x-coordinate. Their matching private keys are the
published RFC test keys. The credential bytes are consumed without re-encoding.

A deterministic test establishes sequential and combined sessions
through one proxy with these CCS bytes. `tools/interop-aiocoap.py --profile
minimal-ccs` also checks this credential profile against aiocoap in both roles,
with sequential and combined EDHOC and proxy routing. These checks do not
establish interoperability with any particular deployed application.
