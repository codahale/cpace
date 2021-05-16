# cpace

A CPACE-inspired PAKE using ristretto255 and STROBE.

Because ristretto255 is a prime order group with non-malleable encode/decode/map standards, this ditches the EC hygiene
checks. Because STROBE strongly binds all aspects of the protocol, this ditches the protocol transcript and identity
point checking busywork.