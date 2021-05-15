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

/// The state object of the protocol initiator.
pub struct Initiator {
    cpace: Strobe,
    salt: [u8; 16],
    d: Scalar,
}

impl Initiator {
    /// Create a new [Initiator] with the given identities and shared password.
    pub fn new(initiator_id: &[u8], responder_id: &[u8], password: &[u8]) -> Initiator {
        // Initialize the protocol with all available associated data.
        let mut cpace = Strobe::new(b"cpace-r255-strobe", SecParam::B256);
        cpace.ad(initiator_id, false);
        cpace.ad(responder_id, false);

        // Key with the password.
        cpace.key(password, false);

        // Generate a random scalar.
        let mut r = [0u8; 64];
        getrandom::getrandom(&mut r).expect("rng failure");
        let d = Scalar::from_bytes_mod_order_wide(&r);

        // Generate a random salt.
        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt).expect("rng failure");

        Initiator { cpace, salt, d }
    }

    /// Start a key exchange.
    ///
    /// Returns a salt and a [RistrettoPoint] which must be sent to the responder.
    pub fn start(&mut self) -> ([u8; 16], RistrettoPoint) {
        // Send the salt to the responder.
        self.cpace.send_clr(&self.salt, false);

        // Extract a generator point from the protocol's PRF output.
        let mut r = [0u8; 64];
        self.cpace.prf(&mut r, false);
        let g = RistrettoPoint::from_uniform_bytes(&r);

        // Calculate the public point by multiplying the generator point by the secret scalar.
        let a = g * self.d;

        // Send the public point to the responder.
        self.cpace.send_clr(a.compress().as_bytes(), false);

        (self.salt, a)
    }

    /// Finish a key exchange.
    ///
    /// Returns a [Strobe] protocol with the same initial state as the responder.
    pub fn finish(self, salt: [u8; 16], b: RistrettoPoint) -> Strobe {
        // Move the protocol to a local variable.
        let mut cpace = self.cpace;

        // Receive the responder's salt and public point.
        cpace.recv_clr(&salt, false);
        cpace.recv_clr(b.compress().as_bytes(), false);

        // Key the protocol with the shared secret point.
        cpace.key((b * self.d).compress().as_bytes(), false);

        // Return the keyed protocol.
        cpace
    }
}

/// The state object of the protocol responder.
pub struct Responder {
    cpace: Strobe,
    salt: [u8; 16],
    d: Scalar,
}

impl Responder {
    /// Create a new [Responder] with the given identities and shared password.
    pub fn new(responder_id: &[u8], initiator_id: &[u8], password: &[u8]) -> Responder {
        // Initialize the protocol with all available associated data.
        let mut cpace = Strobe::new(b"cpace-r255-strobe", SecParam::B256);
        cpace.ad(initiator_id, false);
        cpace.ad(responder_id, false);

        // Key with the password.
        cpace.key(password, false);

        // Generate a random scalar.
        let mut r = [0u8; 64];
        getrandom::getrandom(&mut r).expect("rng failure");
        let d = Scalar::from_bytes_mod_order_wide(&r);

        // Generate a random salt.
        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt).expect("rng failure");

        Responder { cpace, salt, d }
    }

    /// Start a key exchange.
    ///
    /// Returns a [RistrettoPoint] which must be sent to the initiator.
    pub fn start(&mut self, salt: [u8; 16], a: RistrettoPoint) -> ([u8; 16], RistrettoPoint) {
        // Receive the salt from the initiator.
        self.cpace.recv_clr(&salt, false);

        // Extract a generator point from the protocol's PRF output.
        let mut r = [0u8; 64];
        self.cpace.prf(&mut r, false);
        let g = RistrettoPoint::from_uniform_bytes(&r);

        // Calculate the public point by multiplying the generator point by the secret scalar.
        let b = g * self.d;

        // Receive the initiator's public point.
        self.cpace.recv_clr(a.compress().as_bytes(), false);

        // Send the initiator the second salt and public point.
        self.cpace.send_clr(&self.salt, false);
        self.cpace.send_clr(b.compress().as_bytes(), false);

        // Key the protocol with the shared secret point.
        self.cpace.key((a * self.d).compress().as_bytes(), false);

        // Return the second salt and public point to the initiator.
        (self.salt, b)
    }

    /// Finish a key exchange.
    ///
    /// Returns a [Strobe] protocol with the same initial state as the initiator.
    pub fn finish(self) -> Strobe {
        self.cpace
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_exchange() {
        let mut initiator = Initiator::new(b"Alice", b"Bea", b"our shared secret");
        let (salt_a, a) = initiator.start();

        let mut responder = Responder::new(b"Bea", b"Alice", b"our shared secret");
        let (salt_b, b) = responder.start(salt_a, a);

        let mut strobe_i = initiator.finish(salt_b, b);
        let mut prf_i = [0u8; 16];
        strobe_i.prf(&mut prf_i, false);

        let mut strobe_r = responder.finish();
        let mut prf_r = [0u8; 16];
        strobe_r.prf(&mut prf_r, false);

        assert_eq!(prf_r, prf_i);
    }

    #[test]
    fn bad_initiator_id() {
        let mut initiator = Initiator::new(b"Hank", b"Bea", b"our shared secret");
        let (salt_a, a) = initiator.start();

        let mut responder = Responder::new(b"Bea", b"Alice", b"our shared secret");
        let (salt_b, b) = responder.start(salt_a, a);

        let mut strobe_i = initiator.finish(salt_b, b);
        let mut prf_i = [0u8; 16];
        strobe_i.prf(&mut prf_i, false);

        let mut strobe_r = responder.finish();
        let mut prf_r = [0u8; 16];
        strobe_r.prf(&mut prf_r, false);

        assert_ne!(prf_r, prf_i);
    }

    #[test]
    fn bad_responder_id() {
        let mut initiator = Initiator::new(b"Alice", b"Bea", b"our shared secret");
        let (salt_a, a) = initiator.start();

        let mut responder = Responder::new(b"Frank", b"Alice", b"our shared secret");
        let (salt_b, b) = responder.start(salt_a, a);

        let mut strobe_i = initiator.finish(salt_b, b);
        let mut prf_i = [0u8; 16];
        strobe_i.prf(&mut prf_i, false);

        let mut strobe_r = responder.finish();
        let mut prf_r = [0u8; 16];
        strobe_r.prf(&mut prf_r, false);

        assert_ne!(prf_r, prf_i);
    }

    #[test]
    fn bad_password() {
        let mut initiator = Initiator::new(b"Alice", b"Bea", b"our shared secret");
        let (salt_a, a) = initiator.start();

        let mut responder = Responder::new(b"Bea", b"Alice", b"my best guess");
        let (salt_b, b) = responder.start(salt_a, a);

        let mut strobe_i = initiator.finish(salt_b, b);
        let mut prf_i = [0u8; 16];
        strobe_i.prf(&mut prf_i, false);

        let mut strobe_r = responder.finish();
        let mut prf_r = [0u8; 16];
        strobe_r.prf(&mut prf_r, false);

        assert_ne!(prf_r, prf_i);
    }

    #[test]
    fn bad_initiator_salt() {
        let mut initiator = Initiator::new(b"Alice", b"Bea", b"our shared secret");
        let (mut salt_a, a) = initiator.start();
        salt_a[2] ^= 1;

        let mut responder = Responder::new(b"Bea", b"Alice", b"our shared secret");
        let (salt_b, b) = responder.start(salt_a, a);

        let mut strobe_i = initiator.finish(salt_b, b);
        let mut prf_i = [0u8; 16];
        strobe_i.prf(&mut prf_i, false);

        let mut strobe_r = responder.finish();
        let mut prf_r = [0u8; 16];
        strobe_r.prf(&mut prf_r, false);

        assert_ne!(prf_r, prf_i);
    }

    #[test]
    fn bad_initiator_point() {
        let mut initiator = Initiator::new(b"Alice", b"Bea", b"our shared secret");
        let (salt_a, _) = initiator.start();
        let a = RistrettoPoint::from_uniform_bytes(&[69u8; 64]);

        let mut responder = Responder::new(b"Bea", b"Alice", b"our shared secret");
        let (salt_b, b) = responder.start(salt_a, a);

        let mut strobe_i = initiator.finish(salt_b, b);
        let mut prf_i = [0u8; 16];
        strobe_i.prf(&mut prf_i, false);

        let mut strobe_r = responder.finish();
        let mut prf_r = [0u8; 16];
        strobe_r.prf(&mut prf_r, false);

        assert_ne!(prf_r, prf_i);
    }

    #[test]
    fn bad_responder_salt() {
        let mut initiator = Initiator::new(b"Alice", b"Bea", b"our shared secret");
        let (salt_a, a) = initiator.start();

        let mut responder = Responder::new(b"Bea", b"Alice", b"our shared secret");
        let (mut salt_b, b) = responder.start(salt_a, a);
        salt_b[2] ^= 1;

        let mut strobe_i = initiator.finish(salt_b, b);
        let mut prf_i = [0u8; 16];
        strobe_i.prf(&mut prf_i, false);

        let mut strobe_r = responder.finish();
        let mut prf_r = [0u8; 16];
        strobe_r.prf(&mut prf_r, false);

        assert_ne!(prf_r, prf_i);
    }

    #[test]
    fn bad_responder_point() {
        let mut initiator = Initiator::new(b"Alice", b"Bea", b"our shared secret");
        let (salt_b, a) = initiator.start();

        let mut responder = Responder::new(b"Bea", b"Alice", b"our shared secret");
        let (salt_b, _) = responder.start(salt_b, a);
        let b = RistrettoPoint::from_uniform_bytes(&[42u8; 64]);

        let mut strobe_i = initiator.finish(salt_b, b);
        let mut prf_i = [0u8; 16];
        strobe_i.prf(&mut prf_i, false);

        let mut strobe_r = responder.finish();
        let mut prf_r = [0u8; 16];
        strobe_r.prf(&mut prf_r, false);

        assert_ne!(prf_r, prf_i);
    }

    #[test]
    fn async_exchange() {
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
