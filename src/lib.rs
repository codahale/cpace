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
    /// Create a new [Exchanger] with the given identities, shared password, and optional session
    /// ID.
    pub fn new(
        local_id: &[u8],
        remote_id: &[u8],
        password: &[u8],
        session_id: Option<&[u8]>,
    ) -> Exchanger {
        // Initialize the protocol with all available associated data.
        let mut cpace = Strobe::new(b"cpace-r255-strobe", SecParam::B256);

        // Add the identities in lexical order.
        cpace.ad(if local_id < remote_id { local_id } else { remote_id }, false);
        cpace.ad(if local_id < remote_id { remote_id } else { local_id }, false);

        // Add the session ID, if any.
        if let Some(id) = session_id {
            cpace.ad(id, false);
        }

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
        let alice = Exchanger::new(b"Alice", b"Bea", b"secret", None);
        let y_alice = alice.send();

        let bea = Exchanger::new(b"Bea", b"Alice", b"secret", None);
        let y_bea = bea.send();

        let mut alice = alice.receive(y_bea);
        let mut bea = bea.receive(y_alice);

        let mut prf_a = [0u8; 16];
        alice.prf(&mut prf_a, false);

        let mut prf_b = [0u8; 16];
        bea.prf(&mut prf_b, false);

        assert_eq!(prf_b, prf_a);
    }

    #[test]
    fn bad_local_id() {
        let alice = Exchanger::new(b"Alice", b"Bea", b"secret", None);
        let y_alice = alice.send();

        let bea = Exchanger::new(b"Hank", b"Alice", b"secret", None);
        let y_bea = bea.send();

        let mut alice = alice.receive(y_bea);
        let mut bea = bea.receive(y_alice);

        let mut prf_a = [0u8; 16];
        alice.prf(&mut prf_a, false);

        let mut prf_b = [0u8; 16];
        bea.prf(&mut prf_b, false);

        assert_ne!(prf_b, prf_a);
    }

    #[test]
    fn bad_remote_id() {
        let alice = Exchanger::new(b"Alice", b"Hank", b"secret", None);
        let y_alice = alice.send();

        let bea = Exchanger::new(b"Bea", b"Alice", b"secret", None);
        let y_bea = bea.send();

        let mut alice = alice.receive(y_bea);
        let mut bea = bea.receive(y_alice);

        let mut prf_a = [0u8; 16];
        alice.prf(&mut prf_a, false);

        let mut prf_b = [0u8; 16];
        bea.prf(&mut prf_b, false);

        assert_ne!(prf_b, prf_a);
    }

    #[test]
    fn bad_password() {
        let alice = Exchanger::new(b"Alice", b"Bea", b"secret", None);
        let y_alice = alice.send();

        let bea = Exchanger::new(b"Bea", b"Alice", b"dingus", None);
        let y_bea = bea.send();

        let mut alice = alice.receive(y_bea);
        let mut bea = bea.receive(y_alice);

        let mut prf_a = [0u8; 16];
        alice.prf(&mut prf_a, false);

        let mut prf_b = [0u8; 16];
        bea.prf(&mut prf_b, false);

        assert_ne!(prf_b, prf_a);
    }

    #[test]
    fn missing_session_id() {
        let alice = Exchanger::new(b"Alice", b"Bea", b"secret", Some(b"ok then"));
        let y_alice = alice.send();

        let bea = Exchanger::new(b"Bea", b"Alice", b"secret", None);
        let y_bea = bea.send();

        let mut alice = alice.receive(y_bea);
        let mut bea = bea.receive(y_alice);

        let mut prf_a = [0u8; 16];
        alice.prf(&mut prf_a, false);

        let mut prf_b = [0u8; 16];
        bea.prf(&mut prf_b, false);

        assert_ne!(prf_b, prf_a);
    }

    #[test]
    fn bad_session_id() {
        let alice = Exchanger::new(b"Alice", b"Bea", b"secret", Some(b"ok then"));
        let y_alice = alice.send();

        let bea = Exchanger::new(b"Bea", b"Alice", b"secret", Some(b"well then"));
        let y_bea = bea.send();

        let mut alice = alice.receive(y_bea);
        let mut bea = bea.receive(y_alice);

        let mut prf_a = [0u8; 16];
        alice.prf(&mut prf_a, false);

        let mut prf_b = [0u8; 16];
        bea.prf(&mut prf_b, false);

        assert_ne!(prf_b, prf_a);
    }

    #[test]
    fn bad_point() {
        let alice = Exchanger::new(b"Alice", b"Bea", b"secret", None);
        let y_alice = RistrettoPoint::from_uniform_bytes(&[69u8; 64]);

        let bea = Exchanger::new(b"Bea", b"Alice", b"secret", None);
        let y_bea = bea.send();

        let mut alice = alice.receive(y_bea);
        let mut bea = bea.receive(y_alice);

        let mut prf_a = [0u8; 16];
        alice.prf(&mut prf_a, false);

        let mut prf_b = [0u8; 16];
        bea.prf(&mut prf_b, false);

        assert_ne!(prf_b, prf_a);
    }
}
