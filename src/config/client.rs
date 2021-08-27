use std::fmt;
use std::fs;
use std::str::FromStr;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;

use anyhow::Result as GeneralResult;
use serde::Serialize;
use serde::Deserialize;
use serde::Serializer;
use serde::Deserializer;
use serde::de;
use serde::de::Visitor;
use sequoia_openpgp::KeyID;
use sequoia_openpgp::Cert;
use sequoia_openpgp::crypto::KeyPair;
use sequoia_openpgp::policy::Policy;
use uuid::Uuid;
use url::Url;
use crate::pgp;

#[derive(Serialize, Deserialize, Default)]
pub struct ClientData {

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub cert_file: Option<PathBuf>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(serialize_with = "serialize_optional_key_id")]
    #[serde(deserialize_with = "deserialize_optional_fromstr")]
    pub key_id: Option<KeyID>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub server_uuid: Option<Uuid>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(serialize_with = "serialize_optional_api_url")]
    #[serde(deserialize_with = "deserialize_optional_fromstr")]
    pub api_url: Option<Url>,

    #[serde(skip)]
    cert: Option<Rc<Cert>>,
}



impl ClientData {

    pub fn cert(&self) -> Option<Rc<Cert>> {
        self.cert.clone()
    }

    pub fn get_cert(&self) -> Option<&Cert> {
        self.cert.as_ref().map(AsRef::as_ref)
    }

    fn update(&mut self, policy: &dyn Policy) -> GeneralResult<bool> {
        let mut changed = false;
        if let Some(ref cert_file) = self.cert_file {
            match pgp::load_cert(cert_file.as_path()) {
                Ok(cert) => {
                    let cert = Rc::new(cert);
                    self.cert = Some(cert.clone());
                    if let Some(ref key_id) = self.key_id {
                        if pgp::check_secret_key(cert.as_ref(), policy, None, key_id) {
                            
                        } else {
                            let e = anyhow::anyhow!("invalid key-id of cert: {}", key_id);
                            self.key_id = None;
                            changed = true;
                            return Err(e)
                        }
                    }
                }
                Err(e) => {
                    self.cert_file = None;
                    changed = true;
                    return Err(e)
                }
            }
        }
        Ok(changed)
    }

    fn try_update_cert_file(&mut self, cert_file: PathBuf, policy: &dyn Policy) -> bool {
        match pgp::load_cert(cert_file.as_path()) {
            Ok(cert) => {
                self.cert_file = Some(cert_file);
                let cert = Rc::new(cert);
                self.cert = Some(cert.clone());
                if let Some(ref key_id) = self.key_id {
                    if pgp::check_secret_key(cert.as_ref(), policy, None, key_id) {
                            
                    } else {
                        self.key_id = None;
                        return false;
                    }
                }
                true
            }
            Err(e) => {
                false
            }
        } 
    }

    fn try_update_key_id(&mut self, key_id: KeyID, policy: &dyn Policy) -> bool {
        if let Some(ref cert) = self.cert {
            if pgp::check_secret_key(cert.as_ref(), policy, None, &key_id) {
                self.key_id = Some(key_id);
                true
            } else {
                false
            }
        } else {
            self.key_id = Some(key_id);
            true
        }
    }
}


pub struct ClientConfig<'a> {
    cfg: super::FileConfig<ClientData>,
    policy: &'a dyn Policy,
}

impl<'a> ClientConfig<'a> {

    pub fn new(path: PathBuf, policy: &'a dyn Policy) -> GeneralResult<Self> {

        let rectify = |data: &mut ClientData| -> GeneralResult<bool> {
            let mut changed = false;
            if let Some(ref mut cert_file) = data.cert_file {
                if !cert_file.is_absolute() {
                    *cert_file = fs::canonicalize(cert_file.as_path())?;
                    changed |= true;
                }           
            }
            if let Some(ref mut api_url) = data.api_url {
                let path = api_url.path();
                if !path.ends_with('/') {
                    let path = path.to_owned() + "/";
                    api_url.set_path(path.as_str());
                    changed |= true;
                }
            }

            changed |= data.update(policy)?;

            Ok(changed)
        };

        let mut cfg = super::FileConfig::new(path, Default::default)?;
        cfg.modify(rectify)?;

        Ok(
            ClientConfig {
                cfg,
                policy,
            }
        )
    }

    pub fn get_data(&self) -> &ClientData {
        self.cfg.get_data()
    }

    pub fn get_data_mut(&mut self) -> &mut ClientData {
        self.cfg.get_data_mut()
    }

    pub fn policy(&self) -> &dyn Policy {
        self.policy
    }

    pub fn set_cert_file(&mut self, v: &str) -> bool {
        let path = Path::new(v);
        if path.is_file() {
            let path = if path.is_absolute() {
                path.to_owned()
            } else {
                fs::canonicalize(path).unwrap()
            };
            
            let policy = self.policy;
            let mut success = false;
            let p_success = &mut success;
            self.cfg.modify(move |data: &mut ClientData| -> GeneralResult<bool> {
                *p_success = data.try_update_cert_file(path, policy);
                Ok(*p_success)
            })
            .unwrap();
            success
        } else {
            false
        }
    }

    pub fn set_key_id(&mut self, v: &str) -> bool {
        if let Ok(key_id) = KeyID::from_str(v) {
            let policy = self.policy;
            let mut success = false;
            let p_success = &mut success;
            self.cfg.modify(move |data: &mut ClientData| -> GeneralResult<bool> {
                *p_success = data.try_update_key_id(key_id, policy);
                Ok(*p_success)
            })
            .unwrap();
            success
        } else {
            false
        }
    }

    pub fn set_server_uuid(&mut self, v: &str) -> bool {
        if let Ok(uuid) = Uuid::from_str(v) {
            self.cfg.get_data_mut().server_uuid = Some(uuid);
            true
        } else {
            false
        }
    }

    pub fn set_api_url(&mut self, v: &str) -> bool {
        if let Ok(mut url) = Url::from_str(v) {
            let path = url.path();
            if !path.ends_with('/') {
                let path = path.to_owned() + "/";
                url.set_path(path.as_str());
            }
            self.cfg.get_data_mut().api_url = Some(url);
            true
        } else {
            false
        }
    }
}

fn serialize_optional_key_id<S: Serializer>(v: &Option<KeyID>, s: S) -> Result<S::Ok, S::Error> {
    if let Some(v) = v {
        s.serialize_str(v.to_hex().as_str())
    } else {
        s.serialize_none()
    }
}

fn serialize_optional_api_url<S: Serializer>(v: &Option<Url>, s: S) -> Result<S::Ok, S::Error> {
    if let Some(v) = v {
        s.serialize_str(v.as_str())
    } else {
        s.serialize_none()
    }
}

fn deserialize_optional_fromstr<'de, D, T, TE>(d: D) -> Result<Option<T>, D::Error> 
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
        type Value = Option<T>;
        
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("string liked")
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
            deserializer.deserialize_str(InnerVisitor(PhantomData))
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            match FromStr::from_str(v) {
                Ok(v) => Ok(Some(v)),
                Err(e) =>Err(de::Error::custom(e))
            }
        }
    }

    d.deserialize_option(InnerVisitor(PhantomData))
}

