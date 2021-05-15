//! An implementation of a CPACE-inspired PAKE using ristretto255 and STROBE.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, trivial_casts, unused_lifetimes, unused_qualifications)]

pub use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use strobe_rs::{SecParam, Strobe};

/// An asynchronous PAKE exchange.
pub struct Exchanger {
    cpace: Strobe,
    d: Scalar,
    y: RistrettoPoint,
}

impl Exchanger {
    /// Create a new [Exchanger] with the given identities and shared password.
    pub fn new(id_a: &[u8], id_b: &[u8], password: &[u8]) -> Exchanger {
        // Initialize the protocol with all available associated data.
        let mut cpace = Strobe::new(b"cpace-r255-strobe", SecParam::B256);

        // Add the ids in lexical order.
        cpace.ad(if id_a < id_b { id_a } else { id_b }, false);
        cpace.ad(if id_a < id_b { id_b } else { id_a }, false);

        // Key with the password.
        cpace.key(password, false);

        // Generate a random scalar.
        let mut r = [0u8; 64];
        getrandom::getrandom(&mut r).expect("rng failure");
        let d = Scalar::from_bytes_mod_order_wide(&r);

        // Extract a generator point from the protocol PRF output.
        cpace.prf(&mut r, false);
        let g = RistrettoPoint::from_uniform_bytes(&r);

        Exchanger { cpace, d, y: g * d }
    }

    /// The public point to be sent to the remote party.
    pub fn send(&self) -> RistrettoPoint {
        self.y
    }

    /// Given the public point from the remote party, unwrap the exchange into a synchronized Strobe
    /// protocol.
    pub fn receive(self, y: RistrettoPoint) -> Strobe {
        // Move the STROBE protocol from the receiver.
        let mut cpace = self.cpace;

        // Compress both points so we can order them lexically.
        let y_local = self.y.compress().to_bytes();
        let y_remote = y.compress().to_bytes();

        // Order send/receive operations lexically. If the local point's compressed form is
        // lexically before the remote one, mark the send as happening first. Otherwise, mark the
        // receive as happening first.
        if y_local < y_remote {
            cpace.send_clr(&y_local, false);
            cpace.recv_clr(&y_remote, false);
        } else {
            cpace.recv_clr(&y_remote, false);
            cpace.send_clr(&y_local, false);
        }

        // Key the protocol with the shared secret point G*d*d.
        cpace.key((y * self.d).compress().as_bytes(), false);

        cpace
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_exchange() {
        let alice = Exchanger::new(b"Alice", b"Bea", b"secret");
        let a_p = alice.send();

        let bea = Exchanger::new(b"Bea", b"Alice", b"secret");
        let b_p = alice.send();

        let mut alice = alice.receive(b_p);
        let mut bea = bea.receive(a_p);

        let mut prf_a = [0u8; 16];
        alice.prf(&mut prf_a, false);

        let mut prf_b = [0u8; 16];
        bea.prf(&mut prf_b, false);

        assert_ne!(prf_b, prf_a);
    }
}
