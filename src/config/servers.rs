use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt;
use std::str::FromStr;
use std::io;
use std::path::PathBuf;
use std::rc::Rc;
use std::fs::File;
use std::fs::OpenOptions;

use anyhow::Result as GeneralResult;
use serde::Serialize;
use serde::Deserialize;
use serde::Serializer;
use serde::Deserializer;
use serde::de;
use serde::de::Visitor;
use sequoia_openpgp::KeyID;
use sequoia_openpgp::Cert;
use sequoia_openpgp::policy::Policy;
use uuid::Uuid;
use crate::pgp;

#[derive(Serialize, Deserialize)]
pub struct ServerData {

    pub name: String,

    #[serde(deserialize_with = "deserialize_fromstr")]
    #[serde(serialize_with = "serialize_key_id")]
    pub key_id: KeyID,

    pub trust: u32,

    #[serde(skip)]
    cert: Option<Rc<Cert>>,
}

impl ServerData {

    pub fn new(name: String, key_id: KeyID, trust: u32) -> Self {
        ServerData {
            name,
            key_id,
            trust,
            cert: None
        }
    }

    pub fn cert(&self) -> Option<Rc<Cert>> {
        self.cert.clone()
    }

    pub fn get_cert(&self) -> &Cert {
        self.cert.as_ref().unwrap()
    }
}


pub struct ServersConfig<'a> {
    cfg: super::FileConfig<HashMap<Uuid, ServerData>>,
    cert_file: PathBuf,
    policy: &'a dyn Policy,
}

impl<'a> ServersConfig<'a> {

    pub fn new(path: PathBuf, cert_file: PathBuf, policy: &'a dyn Policy) -> GeneralResult<Self> {
        let mut cfg: super::FileConfig<HashMap<Uuid, ServerData>> = super::FileConfig::new(path, Default::default)?;
        
        let p = policy;
        let cert_file_path = cert_file.as_path();
        cfg.modify(move |data: &mut HashMap<Uuid, ServerData>| -> GeneralResult<bool> {
            let mut changed = false;
            let old_len = data.len();
            {
                let mut indexs: HashMap<KeyID, &mut ServerData> = HashMap::new();
                for s in data.values_mut() {
                    indexs.insert(s.key_id.clone(), s);
                }
                let certs = match File::open(cert_file_path) {
                    Ok(ifile) => {
                        pgp::read_keyring(ifile)?
                    },
                    Err(e) => {
                        if e.kind() == io::ErrorKind::NotFound {
                            let ofile = OpenOptions::new().write(true).create_new(true).open(cert_file_path)?;
                            Vec::new()
                        } else {
                            return Err(e.into())
                        }
                    }
                };
                for cert in certs {
                    let cert = Rc::new(cert);
                    for key_id in pgp::iter_cert(cert.as_ref(), p, None) {
                        if let Some(s) = indexs.get_mut(&key_id) {
                            (*s).cert = Some(cert.clone());
                            break;
                        }
                    }
                }
            }
            data.retain(|k, v| v.cert.is_some());
            let new_len = data.len();
            if new_len != old_len {
                changed = true;
            }
            Ok(changed)
        })?;

        Ok(
            ServersConfig {
                cfg,
                cert_file,
                policy
            }
        )
    }

    pub fn save(&mut self) -> GeneralResult<bool> {
        if self.cfg.save()? {
            let data = self.cfg.get_data();
            let mut ofile = File::create(self.cert_file.as_path())?;
            for e in data.values() {
                pgp::export_publickey_raw(e.cert.as_ref().unwrap().as_ref(), &mut ofile)?;
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn get_data(&self) -> &HashMap<Uuid, ServerData> {
        self.cfg.get_data()
    }

    pub fn add<F>(&mut self, server_uuid: Uuid, mut server_data: ServerData, cert: F) -> GeneralResult<bool>
    where
        F: FnOnce(&Uuid, &ServerData) -> GeneralResult<Rc<Cert>>
    {
        let mut success = false;
        let p_success = &mut success;
        let p = self.policy;
        self.cfg.modify(move |data: &mut HashMap<Uuid, ServerData>| -> GeneralResult<bool> {
            match data.entry(server_uuid) {
                Entry::Vacant(v) => {
                    let cert = cert(&server_uuid, &server_data)?;
                    if pgp::check_key(cert.as_ref(), p, None, &server_data.key_id) {
                        server_data.cert = Some(cert);
                        v.insert(server_data);
                        *p_success = true;
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                },
                Entry::Occupied(o) => {
                    Ok(false)
                }
            }
        })?;
        Ok(success)
    }

    pub fn remove(&mut self, server_uuid: &Uuid) -> bool {
        let mut success = false;
        let p_success = &mut success;
        self.cfg.modify(move |data: &mut HashMap<Uuid, ServerData>| -> Result<bool, ()> {
            if let Some(v) = data.remove(server_uuid) {
                *p_success = true;
            }
            Ok(*p_success)
        })
        .unwrap();
        success
    }

    pub fn get(&self, server_uuid: &Uuid) -> Option<(Rc<Cert>, KeyID)> {
        self.cfg.get_data().get(server_uuid).map(|s| (s.cert.as_ref().unwrap().clone(), s.key_id.clone()))
    }

    pub fn get_ref(&self, server_uuid: &Uuid) -> Option<(&Cert, &KeyID)> {
        self.cfg.get_data().get(server_uuid).map(|s| (s.cert.as_ref().unwrap().as_ref(), &s.key_id))
    }

    pub fn policy(&self) -> &dyn Policy {
        self.policy
    }
}


impl<'a> Drop for ServersConfig<'a> {

    fn drop(&mut self) {
        if let Err(e) = self.save() {
            eprintln!("{}", e)
        }
    }
}


fn serialize_key_id<S: Serializer>(v: &KeyID, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(v.to_hex().as_str())
}

pub fn deserialize_fromstr<'de, D, T, TE>(d: D) -> Result<T, D::Error> 
where
    D: Deserializer<'de>,
    T: FromStr<Err = TE>,
    TE: fmt::Display,
{
    use std::marker::PhantomData;

    struct InnerVisitor<T, TE>(PhantomData<(T, TE)>);

    impl<'de, T, TE> Visitor<'de> for InnerVisitor<T, TE> 
    where
        T: FromStr<Err = TE>,
        TE: fmt::Display,
    {
        type Value = T;
        
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("string liked")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            match FromStr::from_str(v) {
                Ok(v) => Ok(v),
                Err(e) =>Err(de::Error::custom(e))
            }
        }
    }

    d.deserialize_str(InnerVisitor(PhantomData))
}