## ZRTP supports Post-Quantum Public Key Algorithm ##

Back in 2017 Phil and I started to discus about quantum-safe public key 
algorithm. Quantum safe public key algorithms at that time tend to have
quite large keys and/or do not support Diffie-Hellman key exchange. This them
for usage in ZRTP. Phil got some information about the new SIDH algorithm
and asked if this could be a fit for ZRTP. 

After some research it became clear that SIDH would fit into the existing ZRTP
implementation

### Why SIDH ###
This is what the inventors/authors of SIDH say about it:
> SIDH Library is a fast and portable software library that implements
> state-of-the-art supersingular isogeny cryptographic schemes. The chosen
> parameters aim to provide security against attackers running a large-scale
> quantum computer, and security against classical algorithms.

SIDH stands out in several aspects when comparing to the traditional quantum
safe algorithms

- SIDH has small public key sizes: less than 600 bytes for a 751-bit size SIDH.
  This was important because ZRTP uses UDP/IP to exchange its protocol data. A
  UDP packet should not exceed the Maximum Transfer Unit (MTU) with is about
  1500 byte in normal Ethernet based networks.

- It's nearly a drop-in replacement for normal DH algorithms, only some small 
  adaptations were necessary (SIDH is not fully symmetrical, requires different
  key generations and shared secret computation for Alice and Bob). This 
  matches ZRTP's initiator/responder roles and no changes in ZRTP's protocol
  state engine are required.

- One drawback is that SIDH is slower than other algorithms. This is not an 
  issue for ZRTP. ZRTP is a point-to-pint protocol to set up an encrypted phone
  call and for this reason it's not relevant if the computation takes 3-4ms of
  30-40ms. The network usually takes longer to send and receive data.

The SIDH reference implementation is available on [Github][github-1] 

SIDH, actually it's sister algorithm SIKE (Supersingular Isogengy Key 
Encapsulation), is a participant of _NIST Post-Quantum Cryptography 
Standardization_ process and is already an alternative candidate of round 3.
More details are available in the [NIST document][nist-1]. Both, SIDH and SIKE,
are based on the same public-key algorithm.

The NIST quote regarding SIKE:
> NIST sees SIKE as a strong candidate for future standardization with
> continued improvements and accordingly selected SIKE to move into the
> third round as an alternate candidate. There are applications which would
> benefit from SIKE’s small key and ciphertext sizes and which may be
> able to accept the performance impact. Further research in isogeny-based
> cryptography is encouraged.

[nist-1]: https://nvlpubs.nist.gov/nistpubs/ir/2020/NIST.IR.8309.pdf
[github-1]: https://github.com/Microsoft/PQCrypto-SIDH


### Implementation ###
To be able to integrate SIDH into ZRTP and to be able to use different SIDH
sizes some additional code was necessary. This additional code does not change
the SIDH core reference implementation. The additional code implements wrappers
to enable access via C++ code and a new cmake-based build process to create 
shared and static object libraries. The new build process supports Android, 
iOS, OSX, Linux and, to some extent, also Windows ;-) .

Unit tests for the new code is available and run the SIDH unit tests under the
hood. The repository includes a small Android application which tests and
benchmarks the implementation on Android devices.

With this infrastructure it was fairly easy to enhance ZRTP to include the SIDH
public key exchange.

The additional code, new build process together with SIDH core is available in
[this][github-2] Github repository.

[github-2]: https://github.com/wernerd/PQCrypto-SIDH


### How does ZRTP use SIDH ###
Because SIDH as such is a fairly new algorithm we decided to use a hybrid
approach and combine SIDH with a well known, classic Elliptic curve algorithm.
In the (hopefully) unlikely event that SIDH is not even secure against classic
attacks we then have at least the proven security of the classic Elliptic curve
algorithm. If this happens, then of course ZRTP would not be _quantum-safe_ .

ZRTP uses SIDH-751 and combines it with the _Curve41417_ by Dan Bernstein and
Tanja Lange. For details and some more links regarding this curve refer to
Silent Circle's [blog][sc-1].

According to the SIDH authors SIDH-751 matches the post-quantum security of 
AES256 (level 5). SIDH-610 would also be OK for ZRTP, however, we decided to
use the most secure level, just to be on the safe side. We will check this
decision once researchers got more confidence in SIDH. 

During key negotiation ZRTP generates two public key pairs:
- one pair for SIDH-751
- the second pair for Curve41417

ZRTP the creates a composed key which consists of the two public keys of 
the key pairs:

    |________ SIDH public key ________|___ curve414 key ___| 

ZRTP exchanges these keys inside the DHPart1 and DHPart2 packets. The receiver
unpacks the composed key and generates to shared secrets as usual. ZRTP 
concatenates both shared secrets to create a composed shared secret:

    |________ SIDH shared secret ________|___ curve414 shared secret ___|

The composed shared secret is input of the normal ZRTP KDF.

SIDH processing and key generation needs some checks to use and create the
correct keys. Either SIDH key type A (ZRTP Initiator, inside DHPart2) or SIDH
key type B (ZRTP Responder, inside DHPart1).

[sc-1]: https://www.silentcircle.com/blog/this-one-goes-to-414/
