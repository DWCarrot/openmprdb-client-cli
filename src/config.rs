
use std::path::Path;
use std::path::PathBuf;
use std::fmt;
use std::io;
use std::io::Read as _;
use std::io::Write as _;
use std::env;
use std::str::FromStr;
use std::fs;
use std::fs::File;
use std::collections::HashMap;

use anyhow::Result as GeneralResult;
use uuid::Uuid;
use url::Url;
use serde::Serialize;
use serde::Serializer;
use serde::Deserialize;
use serde::Deserializer;
use serde::de;
use serde::de::Visitor;
use serde_json::ser as json_ser;
use sequoia_openpgp::KeyID;
use sequoia_openpgp::Fingerprint;


pub fn current_exe_path() -> io::Result<PathBuf> {
    let exe = env::current_exe()?;
    exe.parent().map(PathBuf::from).ok_or_else(|| io::Error::from(io::ErrorKind::Other))
}

#[derive(Serialize, Deserialize, Default)]
pub struct ConfigData {

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub cert_file: Option<PathBuf>,     // TODO: change to keyring file

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(serialize_with = "serialize_optional_key_id")]
    #[serde(deserialize_with = "deserialize_optional_fromstr")]
    pub key_id: Option<KeyID>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(serialize_with = "serialize_optional_fingerprint")]
    #[serde(deserialize_with = "deserialize_optional_fromstr")]
    pub fingerprint: Option<Fingerprint>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub server_uuid: Option<Uuid>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(serialize_with = "serialize_optional_api_url")]
    #[serde(deserialize_with = "deserialize_optional_fromstr")]
    pub api_url: Option<Url>,

    #[serde(skip_serializing_if = "HashMap::is_empty")]
    #[serde(default)]
    pub servers: HashMap<Uuid, ServerData>,
}

#[derive(Serialize, Deserialize)]
pub struct ServerData {

    pub name: String,

    #[serde(deserialize_with = "deserialize_fromstr")]
    #[serde(serialize_with = "serialize_key_id")]
    pub key_id: KeyID,

    #[serde(deserialize_with = "deserialize_fromstr")]
    #[serde(serialize_with = "serialize_fingerprint")]
    pub fingerprint: Fingerprint,

    pub trust: u32,
}


fn serialize_key_id<S: Serializer>(v: &KeyID, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(v.to_hex().as_str())
}

fn serialize_fingerprint<S: Serializer>(v: &Fingerprint, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(v.to_hex().as_str())
}

fn serialize_optional_key_id<S: Serializer>(v: &Option<KeyID>, s: S) -> Result<S::Ok, S::Error> {
    if let Some(v) = v {
        s.serialize_str(v.to_hex().as_str())
    } else {
        s.serialize_none()
    }
}

fn serialize_optional_fingerprint<S: Serializer>(v: &Option<Fingerprint>, s: S) -> Result<S::Ok, S::Error> {
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

fn deserialize_optional_fromstr<'de, D: Deserializer<'de>, T: FromStr>(d: D) -> Result<Option<T>, D::Error> {
    use std::marker::PhantomData;

    struct InnerVisitor<T>(PhantomData<T>);

    impl<'de, T: FromStr> Visitor<'de> for InnerVisitor<T> {
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
                Err(e) =>Err(de::Error::invalid_value(de::Unexpected::Str(v), &self))
            }
        }
    }

    d.deserialize_option(InnerVisitor(PhantomData))
}

fn deserialize_fromstr<'de, D: Deserializer<'de>, T: FromStr>(d: D) -> Result<T, D::Error> {
    use std::marker::PhantomData;

    struct InnerVisitor<T>(PhantomData<T>);

    impl<'de, T: FromStr> Visitor<'de> for InnerVisitor<T> {
        type Value = T;
        
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("string liked")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            match FromStr::from_str(v) {
                Ok(v) => Ok(v),
                Err(e) =>Err(de::Error::invalid_value(de::Unexpected::Str(v), &self))
            }
        }
    }

    d.deserialize_str(InnerVisitor(PhantomData))
}



pub struct Config {
    path: PathBuf,
    cfg: ConfigData,
    changed: bool
}

impl Config {

    pub fn new() -> GeneralResult<Self> {
        let mut changed = false;
        let path = current_exe_path()?.join("config");
        let cfg = match File::open(path.as_path()) {
            Ok(ifile) => {
                let mut cfg: ConfigData = serde_json::from_reader(ifile)?;
                if let Some(api_url) = &mut cfg.api_url {
                    let path = api_url.path();
                    if !path.ends_with('/') {
                        let path = path.to_owned() + "/";
                        api_url.set_path(path.as_str());
                        changed = true;
                    }
                }
                if let Some(path) = &mut cfg.cert_file {
                    if !path.is_absolute() {
                        cfg.cert_file = Some(fs::canonicalize(path)?);
                        changed = true;
                    }
                }
                cfg
            },
            Err(e) => {
                if e.kind() == io::ErrorKind::NotFound {
                    Default::default()
                } else {
                    return Err(e.into())
                }
            }
        };
        Ok(Config {
            path,
            cfg,
            changed
        })
    }

    pub fn save(&mut self) -> GeneralResult<()> {
        if self.changed {
            let ofile = File::create(self.path.as_path())?;
            let formatter = json_ser::PrettyFormatter::with_indent(b"    ");
            let mut ser = json_ser::Serializer::with_formatter(ofile, formatter);
            self.cfg.serialize(&mut ser)?;
            self.changed = false;
        }
        Ok(())
    }

    pub fn get_data(&self) -> &ConfigData {
        &self.cfg
    }

    pub fn get_data_mut(&mut self) -> &mut ConfigData {
        self.changed = true;
        &mut self.cfg
    }

    pub fn set_cert_file(&mut self, v: &str) -> bool {
        let path = Path::new(v);
        if path.is_file() {
            let path = if path.is_absolute() {
                path.to_owned()
            } else {
                fs::canonicalize(path).unwrap()
            };
            self.cfg.cert_file = Some(path);
            self.changed = true;
            true
        } else {
            false
        }
    }

    pub fn set_key_id(&mut self, v: &str) -> bool {
        if let Ok(key_id) = KeyID::from_str(v) {
            self.cfg.key_id = Some(key_id);
            self.changed = true;
            true
        } else {
            false
        }
    }

    pub fn set_fingerprint(&mut self, v: &str) -> bool {
        if let Ok(fingerprint) = Fingerprint::from_str(v) {
            self.cfg.fingerprint = Some(fingerprint);
            self.changed = true;
            true
        } else {
            false
        }
    }

    pub fn set_server_uuid(&mut self, v: &str) -> bool {
        if let Ok(uuid) = Uuid::from_str(v) {
            self.cfg.server_uuid = Some(uuid);
            self.changed = true;
            true
        } else {
            false
        }
    }

    pub fn set_api_url(&mut self, v: &str) -> bool {
        if let Ok(url) = Url::from_str(v) {
            self.cfg.api_url = Some(url);
            self.changed = true;
            true
        } else {
            false
        }
    }

    // pub fn get_cert_file<'a>(&'a mut self) -> Cow<'a, str> {
    //     if let Some(ref path) = self.cfg.cert_file {
    //         path.to_string_lossy()
    //     } else {
    //         Cow::Borrowed("")
    //     }
    // }

    // pub fn get_key_id<'a>(&'a mut self) -> Cow<'a, str> {
    //     if let Some(ref key_id) = self.cfg.key_id {
    //         Cow::Owned(key_id.to_hex())
    //     } else {
    //         Cow::Borrowed("")
    //     }
    // }

    // pub fn get_server_uuid<'a>(&'a mut self) -> Cow<'a, str> {
    //     if let Some(ref uuid) = self.cfg.server_uuid {
    //         Cow::Owned(uuid.to_hyphenated().to_string())
    //     } else {
    //         Cow::Borrowed("")
    //     }
    // }

    // pub fn get_api_url<'a>(&'a mut self) -> Cow<'a, str> {
    //     if let Some(ref url) = self.cfg.api_url {
    //         Cow::Borrowed(url.as_str())
    //     } else {
    //         Cow::Borrowed("")
    //     }
    // }
}

impl Drop for Config {

    fn drop(&mut self) {
        if let Err(e) = self.save() {
            eprintln!("{}", e);
        }
    }
}
