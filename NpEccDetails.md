## Current implementation of NP feature in ZRTP ###

Some explanations regarding the current implementation of NPxx 
extensions for ZRTP.

### Initialize key exchange ###

The current implementation performs the following steps to 
initialize the key exchanged:

- each ZRTP peer generates NTRU prime keys (PQ_sk, PQ_pk)
- generate ECC keys (ECC_sk, ECC_pk). After determining the ZRTP 
  roles they become 
  - Initiator: ECC_ski, ECC_pki
  - Responder: ECC_skr, ECC_pkr
- pki = PQ_pk || ECC_pki

The implementation concatenates the data in the order shown above, no
padding between the two public keys.

Both ZRTP peers assume Initiator role first, generate _pki_ and 
prepare their ZRTP Commit message with this data. Add padding to 
_pki_ to full ZRTP word (multiple of 4 bytes). According to ZRTP2022 
the Commit message is now a variable length message which contains 
this set of public keys. The ECC public key data uses compressed format.

After the _Hello_, _HelloAck_, and _Commit_ exchange ZRTP determines 
which peer is Initiator or Responder. 

### Responder flow ###

The Responder takes the public key data of the Initiator's _commit_ 
message and performs the next steps:

- discard its NTRU prime
- extract _PQ_pk_ from Commit message, call NTRU prime encapsulation 
  which returns the shared secret _PQ_ss_ and the encrypted shared 
  secret _PQ_ct_ 
- extract _ECC_pki_ and compute the ECC secret _ECC_z_ using the 
  _ECC_pki_ and its _ECC_skr_ 
- compute the ECC KEM: `ECC_ss = KDF_ecc(ECC_z, ECC_pki || ECC_z)`
- create _pkr_ data: `pkr = PQ_ct || ECC_pkr`
- send ZRTP DHPart1 message which contains _pkr_ 

The implementation concatenates the data in the order shown above, no
padding between the two public keys.

### Initiator flow ###

The Initiator performs the steps after it received DHPart1 message:

- extract _PQ_ct_ and call NTRU prime decapsulation to get _PQ_ss_
- extract_ECC_pkr_ and compute the ECC secret _ECC_z_ using the 
  _ECC_pkr_ and its _ECC_ski_
- compute the ECC KEM: `ECC_ss = KDF_ecc(ECC_z, ECC_pki || ECC_z)` 

### Common flow ###

Both peers now concatenate the shared secrets:
    combined_ss = PQ_ss || ECC_ss
and use this as input to ZRTP KDF.

The implementation concatenates the data in the order shown above, no
padding between the two public keys.

### Implementation of KDF_ecc ###

The current implementation uses a _HKDF_ according to RFC5869. The 
implementation uses the _extract_ and _expand_ step.

The input to the HDKF:

- input keying material (IKM): _ECC_z_
- salt: _PQ_ss_
- info: name of the ZRTP public key algorithm. Thus, either: "NP06",
  "NP09", or "NP12"

To get the salt it is necessary to compute the NTRU prime secret 
before computing the ECC KEM. Using _PQ_ss_ as salt is in accordance 
with the proposal in RFC5869, chapter _3.1. To Salt or not to Salt_, 
last paragraph.


