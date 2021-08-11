use std::io;
use std::io::Read;
use std::io::Write;
use std::fmt;
use std::fs::File;
use std::time::Duration;
use std::time::SystemTime;
use std::path::Path;
use std::path::PathBuf;
use std::borrow::Borrow;
use std::hash::Hash;
use std::hash::Hasher;
use std::collections::HashMap;
use std::collections::HashSet;
use std::rc::Rc;
use std::rc::Weak;

use anyhow::anyhow;
use anyhow::Result as GeneralResult;
use chrono::DateTime;
use chrono::Local;
use sequoia_openpgp::armor::Writer;
use sequoia_openpgp::armor::Kind;
use sequoia_openpgp::cert::CipherSuite;
use sequoia_openpgp::cert::CertBuilder;
use sequoia_openpgp::Packet;
use sequoia_openpgp::Cert;
use sequoia_openpgp::KeyHandle;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::parse::PacketParser;
use sequoia_openpgp::parse::stream::VerificationHelper;
use sequoia_openpgp::parse::stream::MessageStructure;
use sequoia_openpgp::parse::stream::MessageLayer;
use sequoia_openpgp::parse::stream::Verifier;
use sequoia_openpgp::parse::stream::VerifierBuilder;
use sequoia_openpgp::cert::CertParser;
use sequoia_openpgp::serialize::Serialize;
use sequoia_openpgp::serialize::stream::Message;
use sequoia_openpgp::serialize::stream::Signer;
use sequoia_openpgp::types::SignatureType;
use sequoia_openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp::crypto::KeyPair;
use sequoia_openpgp::Fingerprint;
use sequoia_openpgp::packet::key::SecretKeyMaterial;
use sequoia_openpgp::packet::signature::SignatureBuilder;
use sequoia_openpgp::policy::Policy;
use sequoia_openpgp::KeyID;



pub struct GenerateConfig<'a> {
    user_id: &'a str,
    cipher_suite: CipherSuite,
    expires: Option<Duration>,
    with_password: bool,
    output: (Box<dyn Write + Sync + Send>, Box<dyn Write + Sync + Send>) // cert output, rev output
}

impl <'a> GenerateConfig<'a> {

    pub fn new(user_id: &'a str) -> Self {
        GenerateConfig {
            user_id,
            cipher_suite: CipherSuite::RSA2k,
            expires: None,
            with_password: false,
            output: (Box::new(io::stdout()), Box::new(io::stdout()))
        }
    }

    pub fn set_cipher_suite(&mut self, cipher_suite: &str) -> GeneralResult<()> {
        match cipher_suite {
            "rsa2048" => {
                self.cipher_suite = CipherSuite::RSA2k;
            }
            "rsa3072" => {
                self.cipher_suite = CipherSuite::RSA3k;
            }
            "rsa4096" => {
                self.cipher_suite = CipherSuite::RSA4k;
            }
            "cv25519" => {
                self.cipher_suite = CipherSuite::Cv25519;
            }
            _ => {
                return Err(anyhow!("unrecognize type: {}", cipher_suite))
            }
        }
        Ok(())
    }

    pub fn set_with_password(&mut self, with_password: bool) -> GeneralResult<()> {
        self.with_password = with_password;
        Ok(())
    }

    pub fn set_expires(&mut self, expires: &str) -> GeneralResult<()> {
        self.expires = Some(Duration::from_secs(60 * 60 * 24 * 365));
        Ok(())
    }

    pub fn set_output(&mut self, output: &str) -> Result<(), String> {
        if output.is_empty() || output == "-" {
            self.output = (Box::new(io::stdout()), Box::new(io::stdout()));
        } else {
            let cert = output;
            let cert = File::create(cert).map_err(|e| format!("{}", e))?;
            let rev = output.to_string() + ".rev";
            let rev = File::create(rev.as_str()).map_err(|e| format!("{}", e))?;
            self.output = (Box::new(cert), Box::new(rev));
        }
        Ok(())
    }

}

pub fn generate(cfg: GenerateConfig<'_>) -> GeneralResult<()> {

    let mut builder = CertBuilder::new()
        .add_userid(cfg.user_id)
        .set_cipher_suite(cfg.cipher_suite);
    if let Some(t) = cfg.expires {
        builder = builder
            .set_creation_time(SystemTime::now())
            .set_validity_period(t);
    }
    builder = builder.add_signing_subkey();
    if cfg.with_password {
        let p0 = rpassword::read_password_from_tty(Some("Enter password to protect the key: "))?.into();
        let p1 = rpassword::read_password_from_tty(Some("Repeat the password once more: "))?.into();

        if p0 == p1 {
            builder = builder.set_password(Some(p0));
        } else {
            return Err(anyhow::anyhow!("Passwords do not match."));
        }
    }

    let (cert, rev) = builder.generate()?;

    let headers = cert.armor_headers();
    {
        let headers: Vec<_> = headers.iter()
                .map(|value| ("Comment", value.as_str()))
                .collect();
        let mut w = Writer::with_headers(cfg.output.0, Kind::SecretKey, headers)?;
        cert.as_tsk().serialize(&mut w)?;
        w.finalize()?;
    }

    {
        let mut headers: Vec<_> = headers.iter()
            .map(|value| ("Comment", value.as_str()))
            .collect();
        headers.insert(0, ("Comment", "Revocation certificate for"));

        let mut w = Writer::with_headers(cfg.output.1, Kind::PublicKey, headers)?;
        Packet::Signature(rev).serialize(&mut w)?;
        w.finalize()?;
    }


    Ok(())
}


/**
 * basic
 */

pub fn load_cert<P: AsRef<Path>>(path: P) -> GeneralResult<Cert> {
    Cert::from_file(path)
}

pub fn load_keyring<P: AsRef<Path>>(path: P) -> GeneralResult<Vec<Cert>> {
    let mut certs = vec![];

    for maybe_cert in CertParser::from_file(path)? {
        certs.push(maybe_cert?);
    }
    
    Ok(certs)
}

pub fn load_cert_from_keyring<P: AsRef<Path>>(path: P, keyhandle: Option<&KeyHandle>) -> GeneralResult<Option<Cert>> {
    
    let mut parser = CertParser::from_file(path)?;
    match keyhandle {
        Some(KeyHandle::KeyID(key_id)) => {
            for maybe_cert in parser {
                let cert = maybe_cert?;
                for key in cert.keys() {
                    if key.keyid() == *key_id {
                        return Ok(Some(cert))
                    }
                }
            }
        },
        Some(KeyHandle::Fingerprint(fingerprint)) => {
            for maybe_cert in parser {
                let cert = maybe_cert?;
                for key in cert.keys() {
                    if key.fingerprint() == *fingerprint {
                        return Ok(Some(cert))
                    }
                }
            }
        },
        None => {
            if let Some(maybe_cert) = parser.next() {
                let cert = maybe_cert?;
                if let Some(maybe_cert) = parser.next() {
                    let _ = maybe_cert?;
                    return Ok(None)
                }
                return Ok(Some(cert))
            }
        }
    }
    
    Ok(None)
}

fn get_signing_keys<'a, I: IntoIterator<Item = &'a Cert>>(certs: I, p: &dyn Policy, timestamp: Option<SystemTime>, key_id: Option<KeyID>) -> GeneralResult<Vec<KeyPair>> {
    
    let mut keys = Vec::new();
    
    'next_cert: 
    for tsk in certs {
        for key in tsk.keys()
            .with_policy(p, timestamp)
            .alive()
            .revoked(false)
            .for_signing()
            .supported()
            .map(|ka| ka.key())
        {
            // TODO: change logic process
            if let Some(secret) = key.optional_secret() {
                if let Some(ref key_id) = key_id {
                    if *key_id != key.keyid() {
                        continue;
                    }
                }
                
                let unencrypted = match secret {
                    SecretKeyMaterial::Encrypted(ref e) => {

                        if e.algo() == SymmetricAlgorithm::Unencrypted {
                            continue;
                        }
                        let password = rpassword::read_password_from_tty(Some(&format!("Please enter password to decrypt {}/{}: ", tsk, key))).unwrap();
                        
                        e.decrypt(key.pk_algo(), &password.into())?
                    },
                    SecretKeyMaterial::Unencrypted(ref u) => u.clone(),
                };

                keys.push(KeyPair::new(key.clone(), unencrypted).unwrap());
                break 'next_cert;
            }
        }

        return Err(anyhow::anyhow!("Found no suitable signing key on {}", tsk));
    }

    Ok(keys)
}



pub fn check_key(cert: &Cert, p: &dyn Policy, timestamp: Option<SystemTime>, key_id: &KeyID) -> GeneralResult<bool> {
    for key in cert.keys()
            .with_policy(p, timestamp)
            .alive()
            .revoked(false)
            .for_signing()
            .supported()
            .map(|ka| ka.key())
            .filter(|key| key.keyid() == *key_id)
    {
        return Ok(true);
    }

    Ok(false)
}



pub trait PasswordProvider {
    fn provide(&self, cert: Fingerprint, key: Fingerprint) -> io::Result<String>;
}

pub fn get_signing_key(cert: &Cert, p: &dyn Policy, timestamp: Option<SystemTime>, key_id: &KeyID, password: &dyn PasswordProvider) -> GeneralResult<KeyPair> {
    for key in cert.keys()
            .with_policy(p, timestamp)
            .alive()
            .revoked(false)
            .for_signing()
            .supported()
            .map(|ka| ka.key())
            .filter(|key| key.keyid() == *key_id)
    {
        // TODO: change logic process
        if let Some(secret) = key.optional_secret() {
            let unencrypted = match secret {
                SecretKeyMaterial::Encrypted(ref e) => {

                    if e.algo() == SymmetricAlgorithm::Unencrypted {
                        continue;
                    }
                    let password = password.provide(cert.fingerprint(), key.fingerprint())?;
                    
                    e.decrypt(key.pk_algo(), &password.into())?
                },
                SecretKeyMaterial::Unencrypted(ref u) => u.clone(),
            };

            return Ok(KeyPair::new(key.clone(), unencrypted).unwrap());
        }
    }

    Err(anyhow::anyhow!("Found no suitable signing key on {}", cert))
}

pub fn build_signer<'a, W: 'a + Write + Sync + Send>(w: W, mut keypairs: Vec<KeyPair>) -> GeneralResult<Message<'a>> {
    if keypairs.is_empty() {
        return Err(anyhow::anyhow!("No signing keys found"));
    }

    let mut builder = SignatureBuilder::new(SignatureType::Text);
    // for (critical, n) in notations.iter() {
    //     builder = builder.add_notation(
    //         n.name(),
    //         n.value(),
    //         Some(n.flags().clone()),
    //         *critical
    //     )?;
    // }

    let message = Message::new(w);
    let mut signer = Signer::with_template(message, keypairs.pop().unwrap(), builder).cleartext();

    for s in keypairs {
        signer = signer.add_signer(s);
    }
    let message = signer.build()?;

    Ok(message)
}


pub fn export_publickey<W: Write + Sync + Send>(cert: &Cert, w: &mut W) -> GeneralResult<()> {
    let mut w = Writer::new(w, Kind::PublicKey)?;
    cert.serialize(&mut w)?;
    w.finalize()?;
    Ok(())
}

pub fn export_publickey_raw<W: Write + Sync + Send>(cert: &Cert, w: &mut W) -> GeneralResult<()> {
    cert.serialize(w)
}



pub fn verify<'a, R, F, T>(cmgr: &'a CertificationManager, signed: R, f: F) -> GeneralResult<T> 
where
    R: 'a + Read + Sync + Send,
    F: FnOnce(&mut dyn Read) -> GeneralResult<T>,
{
    let h = VerifyHelper {
        cmgr,
    };
    let mut v = VerifierBuilder::from_reader(signed)?.with_policy(cmgr.policy, SystemTime::now(), h)?;
    let value = f(&mut v)?;
    Ok(value)
} 

struct VerifyHelper<'a> {
    cmgr: &'a CertificationManager<'a>,
}

impl<'a> VerificationHelper for VerifyHelper<'a> {

    fn inspect(&mut self, pp: &PacketParser) -> GeneralResult<()> {
        // Do nothing.
        let _ = pp;
        Ok(())
    }

    fn get_certs(&mut self, ids: &[KeyHandle]) -> GeneralResult<Vec<Cert>> {
        let mut certs = Vec::new();
        for id in ids {
            match id {
                KeyHandle::KeyID(key_id) => {
                    certs.push(self.cmgr.get(key_id).ok_or_else(|| anyhow!("cert not find: {}", key_id))?.as_ref().clone())
                }
                KeyHandle::Fingerprint(fingerprint) => {
                    let mut find = false;
                    'loop2:
                    for cert in self.cmgr.iter() {
                        for key in cert.keys()
                            .with_policy(self.cmgr.policy, self.cmgr.timestamp)
                            .alive()
                            .revoked(false)
                            .for_signing()
                            .supported()
                            .map(|ka| ka.key())
                            .filter(|key| key.fingerprint() == *fingerprint) {
                            certs.push(cert.as_ref().clone());
                            find = true;
                            break 'loop2;
                        }
                    }

                    if !find {
                        return Err(anyhow!("cert not find: {}", fingerprint))
                    }
                }
            }
        }
        Ok(certs)
    }

    fn check(&mut self, structure: MessageStructure) -> GeneralResult<()> {

        // In this function, we implement our signature verification
        // policy.
 
        let mut good = false;
        for (i, layer) in structure.into_iter().enumerate() {
            match (i, layer) {
                // First, we are interested in signatures over the
                // data, i.e. level 0 signatures.
                (0, MessageLayer::SignatureGroup { results }) => {
                    // Finally, given a VerificationResult, which only says
                    // whether the signature checks out mathematically, we apply
                    // our policy.
                    match results.into_iter().next() {
                        Some(Ok(_)) =>
                            good = true,
                        Some(Err(e)) =>
                            return Err(sequoia_openpgp::Error::from(e).into()),
                        None =>
                            return Err(anyhow!("No signature")),
                    }
                },
                _ => return Err(anyhow!("Unexpected message structure")),
            }
        }
 
        if good {
            Ok(()) // Good signature.
        } else {
            Err(anyhow!("Signature verification failed"))
        }
    }
}



pub fn read_cert_from_console() -> GeneralResult<Cert> {
    let mut buf = Vec::new();
    let len = io::stdin().read_to_end(&mut buf)?;
    Cert::from_reader(buf.as_slice())
}

/**
 * 
 */

pub struct CertsInfo<'a> {
    certs: &'a [Cert],
    key_id: Option<&'a KeyID>,
    p: &'a dyn Policy
}

impl<'a> CertsInfo<'a> {

    pub fn new(certs: &'a [Cert], key_id: Option<&'a KeyID>, p: &'a dyn Policy) -> Self {
        CertsInfo {
            certs,
            key_id,
            p
        }
    }
}

impl<'a> fmt::Display for CertsInfo<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use sequoia_openpgp::cert::prelude::*;

        enum SystemTimeDisplay {
            Some(SystemTime),
            None(&'static str)
        }

        impl fmt::Display for SystemTimeDisplay {

            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    Self::Some(time) => {
                        let time: DateTime<Local> = time.clone().into();
                        time.format("%Y-%m-%d").fmt(f)
                    },
                    Self::None(msg) => {
                        f.write_str(msg)
                    }
                }
            }
        }

        impl From<Option<SystemTime>> for SystemTimeDisplay {

            fn from(t: Option<SystemTime>) -> Self {
                match t {
                    Some(t) => Self::Some(t),
                    None => Self::None("never")
                }
            }
        }


        for cert in self.certs {

            if cert.is_tsk() {
                f.write_fmt(format_args!("* {} [Transferable Secret Key]\n", cert.fingerprint()))?;
            } else {
                f.write_fmt(format_args!("* {} [OpenPGP Certificate]\n", cert.fingerprint()))?;
            }
        
            
            for ka in cert.keys().with_policy(self.p, None).supported() {
                let ka: ValidErasedKeyAmalgamation<_> = ka;
                let key = ka.key();
                if let Some(key_id) = self.key_id {
                    if *key_id == key.keyid() {
                        f.write_str("->")?;
                    }
                }
                f.write_fmt(format_args!(
                    "\t{}/{} {}\n\t create: {}, expires: {}\n", 
                    key.pk_algo(),
                    key.keyid(),
                    key.fingerprint(),
                    SystemTimeDisplay::Some(key.creation_time()),
                    SystemTimeDisplay::from(ka.key_expiration_time())
                ))?;
                if ka.primary() {
                    f.write_str("\t  ")?;
                    let mut first = true;
                    for ua in cert.userids() {
                        if first {
                            first = false;
                        } else {
                            f.write_str(", ")?;
                        }
                        f.write_str(String::from_utf8_lossy(ua.value()).borrow())?;
                    }
                    f.write_str("\n")?;
                }
            }
        }
        Ok(())
    }
}


/**
 * 
 */

struct CertWrap(Rc<Cert>);

impl std::cmp::PartialEq for CertWrap {
    
    fn eq(&self, other: &Self) -> bool {
        self.0.fingerprint().eq(&other.0.fingerprint())
    }

    fn ne(&self, other: &Self) -> bool {
        self.0.fingerprint().ne(&other.0.fingerprint())
    }
}

impl Eq for CertWrap {

}

impl Hash for CertWrap {

    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.fingerprint().hash(state);
    }
}

pub struct CertificationManager<'a> {
    policy: &'a dyn Policy,
    path: PathBuf,
    certs: HashSet<CertWrap>,
    indexs: HashMap<KeyID, Weak<Cert>>,
    changed: bool,
    timestamp: SystemTime,
}

impl<'a> CertificationManager<'a> {

    pub fn new(path: PathBuf, p: &'a dyn Policy) -> GeneralResult<Self> {
        let timestamp = SystemTime::now();

        let mut changed = false;
        let mut certs = HashSet::new();
        let mut indexs = HashMap::new();
        
        match File::open(path.as_path()) {
            Ok(ifile) => {
                for maybe_cert in CertParser::from_reader(ifile)? {
                    let cert = Rc::new(maybe_cert?);
                    let insert = certs.insert(CertWrap(cert.clone()));
                    if insert {
                        for ka in cert.keys()
                            .with_policy(p, timestamp)
                            .alive()
                            .revoked(false)
                            .for_signing()
                            .supported() {
                            
                            let key_id = ka.keyid();
                            indexs.insert(key_id, Rc::downgrade(&cert));
                        }
                    }
                    changed = !insert;
                }
            },
            Err(e) => {
                if e.kind() == io::ErrorKind::NotFound {
                    
                } else {
                    return Err(e.into());
                }
            }
        }
        
        

        Ok(CertificationManager {
            policy: p,
            path,
            certs,
            indexs,
            changed,
            timestamp
        })
    }

    pub fn save(&mut self) -> GeneralResult<()> {
        let mut ofile = File::create(self.path.as_path())?;
        for CertWrap(cert) in self.certs.iter() {
            cert.serialize(&mut ofile)?;
        }
        Ok(())
    }

    pub fn add(&mut self, cert: Rc<Cert>) -> bool {
        let timestamp = SystemTime::now();

        let insert = self.certs.insert(CertWrap(cert.clone()));
        if insert {
            for ka in cert.keys()
                .with_policy(self.policy, timestamp)
                .alive()
                .revoked(false)
                .for_signing()
                .supported() {
                
                let key_id = ka.keyid();
                self.indexs.insert(key_id, Rc::downgrade(&cert));
            }
            self.changed = true;
        }

        insert
    }

    pub fn remove(&mut self, cert: &Rc<Cert>) -> bool {

        let remove = self.certs.remove(&CertWrap(cert.clone()));
        if remove {
            for ka in cert.keys()
                .with_policy(self.policy, self.timestamp)
                .alive()
                .revoked(false)
                .for_signing()
                .supported() {
                
                let key_id = ka.keyid();
                self.indexs.remove(&key_id);
            }
            self.changed = true;
        }

        remove
    }

    pub fn get(&self, key_id: &KeyID) -> Option<Rc<Cert>> {
        if let Some(cert) = self.indexs.get(key_id) {
            return Weak::upgrade(cert);
        }
        None
    }

    pub fn iter<'b>(&'b self) -> impl Iterator<Item = &'b Rc<Cert>> {
        self.certs.iter().map(|v| &v.0)
    }
}

impl<'a> Drop for CertificationManager<'a> {

    fn drop(&mut self) {
        if self.changed {
            if let Err(e) = self.save() {
                eprintln!("{}", e);
            }
            self.changed = false;
        }
    }
}


/**
 * 
 */

pub struct TTYPasswordProvider;

impl PasswordProvider for TTYPasswordProvider {

    fn provide(&self, cert: Fingerprint, key: Fingerprint) -> io::Result<String> {
        rpassword::read_password_from_tty(Some(&format!("Please enter password to decrypt {}/{}: ", cert, key)))
    }
}


// Joins certificates and keyrings into a keyring, applying a filter.
// fn filter<F>(inputs: Option<clap::Values>, output: &mut dyn io::Write, mut filter: F, to_certificate: bool) -> Result<()>
// where F: FnMut(Cert) -> Option<Cert>,
// {
//     if let Some(inputs) = inputs {
//         for name in inputs {
//             for cert in CertParser::from_file(name)? {
//                 let cert = cert.context(format!("Malformed certificate in keyring {:?}", name))?;
//                 if let Some(cert) = filter(cert) {
//                     if to_certificate {
//                         cert.serialize(output)?;
//                     } else {
//                         cert.as_tsk().serialize(output)?;
//                     }
//                 }
//             }
//         }
//     } else {
//         for cert in CertParser::from_reader(io::stdin())? {
//             let cert = cert.context("Malformed certificate in keyring")?;
//             if let Some(cert) = filter(cert) {
//                 if to_certificate {
//                     cert.serialize(output)?;
//                 } else {
//                     cert.as_tsk().serialize(output)?;
//                 }
//             }
//         }
//     }
//     Ok(())
// }
