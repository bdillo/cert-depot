use std::{
    collections::HashMap,
    error::Error,
    time::{Duration, SystemTime},
};

use rand_core::RngCore;
use ssh_key::{
    certificate::CertType, public::KeyData, rand_core::OsRng, Certificate, PrivateKey, PublicKey,
};

use subtle::ConstantTimeEq;

const CERT_VALIDITY_WINDOW: Duration = Duration::new(60 * 60 * 24 * 3, 0); // 3 days
const PROVISIONING_VALIDITY_WINDOW: Duration = Duration::new(60 * 3, 0); // 3 minutes

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SshPrincipal {
    Username(String),
    Hostname(String),
}

#[derive(Debug, PartialEq, Eq)]
pub struct ProvisioningSecret {
    secret: [u8; 32],
    valid_until: SystemTime,
}

impl ProvisioningSecret {
    fn new() -> Self {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);

        let valid_until = SystemTime::now() + PROVISIONING_VALIDITY_WINDOW;

        Self {
            secret,
            valid_until,
        }
    }

    fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    fn valid_until(&self) -> &SystemTime {
        &self.valid_until
    }

    fn is_valid(&self) -> bool {
        self.valid_until > SystemTime::now()
    }
}

#[derive(Debug)]
pub struct SshCertificateAuthority {
    ca_signing_key: PrivateKey,
    ca_public_key: PublicKey,
    principal_provisioning_secrets: HashMap<SshPrincipal, ProvisioningSecret>,
}

impl SshCertificateAuthority {
    pub fn new(ca_signing_key: PrivateKey) -> Self {
        let ca_public_key = ca_signing_key.public_key().to_owned();

        Self {
            ca_signing_key,
            ca_public_key,
            principal_provisioning_secrets: HashMap::new(),
        }
    }

    fn new_secret_for_principal(&mut self, principal: &SshPrincipal) {
        let secret = ProvisioningSecret::new();

        self.principal_provisioning_secrets
            .insert(principal.clone(), secret);
    }

    fn validate_challenge(&mut self, principal: &SshPrincipal, offered_secret: &[u8; 32]) -> bool {
        let secret = self.principal_provisioning_secrets.get(principal);
        let dummy = [0u8; 32]; // in case we don't have any secret in our hashmap for the given principal so we can
                               // still do a constant time comparison

        // TODO: clean this up a bit. Maybe store stuff differently
        let secret_is_correct: bool = match secret {
            Some(s) => s.secret().ct_eq(offered_secret).into(),
            None => dummy.ct_eq(offered_secret).into(),
        };

        // validate provisioning secret expiration

        todo!()
    }

    fn sign(
        &self,
        subject_public_key: impl Into<KeyData>,
        cert_type: CertType, // TODO: can this just be based on the principal enum variant?
        principal: SshPrincipal,
    ) -> Result<Certificate, Box<dyn Error>> {
        todo!()
    }
}
