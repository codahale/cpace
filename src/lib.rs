//! An implementation of a CPACE-inspired PAKE using ristretto255 and STROBE.

#![no_std]
#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    trivial_casts,
    unused_lifetimes,
    unused_qualifications,
    clippy::cognitive_complexity,
    clippy::missing_const_for_fn,
    clippy::needless_borrow
)]

pub use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use strobe_rs::{SecParam, Strobe};

/// Possible errors for the key agreement protocol.
#[derive(Debug)]
pub enum Error {
    /// The peer's key is invalid (e.g. a zero point).
    InvalidPeerKey,
}

/// The role of a given exchanger.
pub enum Role {
    /// Initiators are exchangers that have initiated the session.
    INITIATOR,
    /// Responders are exchangers that are responding to an initiator.
    RESPONDER,
}

impl Role {
    /// Record local and remote data according to role. As an initiator, mark the local data as
    /// being sent first; as a responder, mark the remote data as being received first. This fixes
    /// potential concurrent replay attacks in a peer-to-peer setting, with an attacker sending us
    /// our own points and replaying our own messages as if they came from the recipient.
    fn record(&self, cpace: &mut Strobe, local: &[u8], remote: &[u8]) {
        match self {
            Role::INITIATOR => {
                cpace.send_clr(local, false);
                cpace.recv_clr(remote, false);
            }
            Role::RESPONDER => {
                cpace.recv_clr(remote, false);
                cpace.send_clr(local, false);
            }
        }
    }
}

/// An asynchronous PAKE exchange.
pub struct Exchanger {
    role: Role,
    cpace: Strobe,
    d: Scalar,
    y: RistrettoPoint,
}

impl Exchanger {
    /// Create a new [Exchanger] with the given identities, shared password, and optional session
    /// ID.
    pub fn new(
        role: Role,
        local_id: &[u8],
        remote_id: &[u8],
        password: &[u8],
        session_id: &[u8],
    ) -> Exchanger {
        // Initialize the protocol with all available associated data.
        let mut cpace = Strobe::new(b"cpace-r255-strobe", SecParam::B256);

        // Record the local and remote IDs according to role.
        role.record(&mut cpace, local_id, remote_id);

        // Add the session ID.
        cpace.ad(session_id, false);

        // Key with the password.
        cpace.key(password, false);

        // Generate a random scalar.
        let mut r = [0u8; 64];
        getrandom::getrandom(&mut r).expect("rng failure");
        let d = Scalar::from_bytes_mod_order_wide(&r);

        // Extract a generator point from the protocol PRF output.
        cpace.prf(&mut r, false);
        let g = RistrettoPoint::from_uniform_bytes(&r);

        Exchanger { role, cpace, d, y: g * d }
    }

    /// The public point to be sent to the remote party.
    pub const fn send(&self) -> RistrettoPoint {
        self.y
    }

    /// Given the public point from the remote party, unwrap the exchange into a synchronized Strobe
    /// protocol.
    pub fn receive(self, y: RistrettoPoint) -> Result<Strobe, Error> {
        // Move the STROBE protocol from the receiver.
        let mut cpace = self.cpace;

        // Record local and remote points according to role.
        self.role.record(&mut cpace, &self.y.compress().to_bytes(), &y.compress().to_bytes());

        // Calculate the shared secret point (G*d')*d and check for contributory behavior.
        let k = y * self.d;
        if k.is_identity() {
            return Err(Error::InvalidPeerKey);
        }

        // Key the protocol with the shared secret point.
        cpace.key(k.compress().as_bytes(), false);

        Ok(cpace)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_exchange() -> Result<(), Error> {
        let alice = Exchanger::new(Role::INITIATOR, b"Alice", b"Bea", b"secret", b"");
        let y_alice = alice.send();

        let bea = Exchanger::new(Role::RESPONDER, b"Bea", b"Alice", b"secret", b"");
        let y_bea = bea.send();

        let mut alice = alice.receive(y_bea)?;
        let mut bea = bea.receive(y_alice)?;

        let mut prf_a = [0u8; 16];
        alice.prf(&mut prf_a, false);

        let mut prf_b = [0u8; 16];
        bea.prf(&mut prf_b, false);

        assert_eq!(prf_b, prf_a);

        Ok(())
    }

    #[test]
    fn bad_local_id() -> Result<(), Error> {
        let alice = Exchanger::new(Role::INITIATOR, b"Alice", b"Bea", b"secret", b"");
        let y_alice = alice.send();

        let bea = Exchanger::new(Role::RESPONDER, b"Hank", b"Alice", b"secret", b"");
        let y_bea = bea.send();

        let mut alice = alice.receive(y_bea)?;
        let mut bea = bea.receive(y_alice)?;

        let mut prf_a = [0u8; 16];
        alice.prf(&mut prf_a, false);

        let mut prf_b = [0u8; 16];
        bea.prf(&mut prf_b, false);

        assert_ne!(prf_b, prf_a);

        Ok(())
    }

    #[test]
    fn bad_remote_id() -> Result<(), Error> {
        let alice = Exchanger::new(Role::INITIATOR, b"Alice", b"Hank", b"secret", b"");
        let y_alice = alice.send();

        let bea = Exchanger::new(Role::RESPONDER, b"Bea", b"Alice", b"secret", b"");
        let y_bea = bea.send();

        let mut alice = alice.receive(y_bea)?;
        let mut bea = bea.receive(y_alice)?;

        let mut prf_a = [0u8; 16];
        alice.prf(&mut prf_a, false);

        let mut prf_b = [0u8; 16];
        bea.prf(&mut prf_b, false);

        assert_ne!(prf_b, prf_a);

        Ok(())
    }

    #[test]
    fn bad_password() -> Result<(), Error> {
        let alice = Exchanger::new(Role::INITIATOR, b"Alice", b"Bea", b"secret", b"");
        let y_alice = alice.send();

        let bea = Exchanger::new(Role::RESPONDER, b"Bea", b"Alice", b"dingus", b"");
        let y_bea = bea.send();

        let mut alice = alice.receive(y_bea)?;
        let mut bea = bea.receive(y_alice)?;

        let mut prf_a = [0u8; 16];
        alice.prf(&mut prf_a, false);

        let mut prf_b = [0u8; 16];
        bea.prf(&mut prf_b, false);

        assert_ne!(prf_b, prf_a);

        Ok(())
    }

    #[test]
    fn bad_session_id() -> Result<(), Error> {
        let alice = Exchanger::new(Role::INITIATOR, b"Alice", b"Bea", b"secret", b"one");
        let y_alice = alice.send();

        let bea = Exchanger::new(Role::RESPONDER, b"Bea", b"Alice", b"secret", b"two");
        let y_bea = bea.send();

        let mut alice = alice.receive(y_bea)?;
        let mut bea = bea.receive(y_alice)?;

        let mut prf_a = [0u8; 16];
        alice.prf(&mut prf_a, false);

        let mut prf_b = [0u8; 16];
        bea.prf(&mut prf_b, false);

        assert_ne!(prf_b, prf_a);

        Ok(())
    }

    #[test]
    fn bad_point() -> Result<(), Error> {
        let alice = Exchanger::new(Role::INITIATOR, b"Alice", b"Bea", b"secret", b"");
        let y_alice = RistrettoPoint::from_uniform_bytes(&[69u8; 64]);

        let bea = Exchanger::new(Role::RESPONDER, b"Bea", b"Alice", b"secret", b"");
        let y_bea = bea.send();

        let mut alice = alice.receive(y_bea)?;
        let mut bea = bea.receive(y_alice)?;

        let mut prf_a = [0u8; 16];
        alice.prf(&mut prf_a, false);

        let mut prf_b = [0u8; 16];
        bea.prf(&mut prf_b, false);

        assert_ne!(prf_b, prf_a);

        Ok(())
    }

    #[test]
    fn replay_attack() -> Result<(), Error> {
        // Alice initiates a session with Bea, but Mallory intercepts the request.
        let alice_send = Exchanger::new(Role::INITIATOR, b"Alice", b"Bea", b"secret", b"");
        let y_alice_send = alice_send.send();

        // Alice receives a session request from Mallory pretending to be Bea.
        let alice_recv = Exchanger::new(Role::RESPONDER, b"Alice", b"Bea", b"secret", b"");
        let y_alice_recv = alice_recv.send();

        // In the Alice-initiated session, Mallory replies to Alice with her own point from the
        // Mallory-initiated session.
        let mut alice_send = alice_send.receive(y_alice_recv)?;

        // In the Mallory-initiated session, Mallory replies to Alice with her own point from the
        // Alice-initiated session.
        let mut alice_recv = alice_recv.receive(y_alice_send)?;

        // Now when Alice sends a message to who she thinks is Bea, Mallory can record it.
        let mut prf_a = [0u8; 16];
        alice_send.prf(&mut prf_a, false);

        // And Mallory can send that same message to Alice, who will believe it's from Bea.
        let mut prf_b = [0u8; 16];
        alice_recv.prf(&mut prf_b, false);

        // But the y_alice_send point was constructed with a different generator.
        assert_ne!(prf_b, prf_a);

        Ok(())
    }
}
