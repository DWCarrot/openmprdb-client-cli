use std::fmt;
use std::time::SystemTime;

use uuid::Uuid;
use chrono::NaiveDateTime;
use serde::Deserialize;
use serde::Deserializer;
use serde::de;
use serde::de::Visitor;

pub enum Expire {
    Forever,
    Some(NaiveDateTime)
}

impl<'de> Deserialize<'de> for Expire {

    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>
    {
        struct InnerVisitor;

        impl<'de> Visitor<'de> for InnerVisitor {
            type Value = Expire;
            
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("datetime{YYYY-mm-dd HH:MM:SS Z} or \"forever\"")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                let value = if v == "forever" {
                    Expire::Forever
                } else {
                    let datetime = NaiveDateTime::parse_from_str(v, "%Y-%m-%d %H:%M:%S %z").map_err(de::Error::custom)?;
                    Expire::Some(datetime)
                };
                Ok(value)
            }
        }

        deserializer.deserialize_str(InnerVisitor)
    }
}

fn deserialize_datetime<'de, D>(deserializer: D) -> Result<NaiveDateTime, D::Error>
where
    D: Deserializer<'de>
{
    struct InnerVisitor;

    impl<'de> Visitor<'de> for InnerVisitor {
        type Value = NaiveDateTime;
        
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("datetime{YYYY-mm-dd HH:MM:SS Z} or \"forever\"")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            let value = NaiveDateTime::parse_from_str(v, "%Y-%m-%d %H:%M:%S %z").map_err(de::Error::custom)?;
            Ok(value)
        }
    }

    deserializer.deserialize_str(InnerVisitor)
}

#[derive(Deserialize)]
pub struct BanListItem {
    
    pub uuid: Uuid,
    
    pub name: String,
    
    #[serde(deserialize_with = "deserialize_datetime")]
    pub created: NaiveDateTime,// "2021-08-23 16:29:12 +0800",
    
    pub source: String, // "§4RDCarrot§r",
    
    pub expires: Expire, //"forever",
    
    pub reason: String,//"cheating"

}

pub type BanList = Vec<BanListItem>;


pub trait GeneratePoints {

    fn generate(&self, data: &BanListItem) -> f32;
}


pub struct BasicGeneratePoints;

impl GeneratePoints for BasicGeneratePoints {

    fn generate(&self, data: &BanListItem) -> f32 {
        -1.0
    }
}