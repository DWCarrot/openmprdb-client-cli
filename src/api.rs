use std::io;
use std::borrow::Cow;
use std::fmt;
use std::fmt::Display;
use std::str::FromStr;

use serde::Serialize;
use serde::Deserialize;
use sequoia_openpgp::Cert;
use sequoia_openpgp::KeyID;
use sequoia_openpgp::crypto::KeyPair;
use url::Url;
use uuid::Uuid;

use crate::pgp;
use crate::config::deserialize_fromstr;


/**
 * 
 */


pub enum RequestMethod {
    POST, 
    GET, 
    PUT, 
    PATCH, 
    DELETE
}


pub trait RequestInfo {

    fn method(&self) -> RequestMethod;

    fn content_type(&self) -> &'static str;

    fn url<'a>(&self, base_url: &'a Url) -> Cow<'a, Url>;

}


pub trait WriteTo {
    type Error;

    fn write_to<W: io::Write + Sync + Send>(&self, w: W) -> Result<(), Self::Error>;
}

pub trait ReadFrom: Sized {
    type Error;

    fn read_from<R: io::Read>(r: R) -> Result<Self, Self::Error>;
}

/**
 * 
 */


#[derive(Serialize, Deserialize, Debug)]
pub enum Status {
    OK,
    NG,

    #[serde(skip)]
    Unexpected,
}


#[derive(Deserialize, Debug)]
pub struct ErrorResponse {

    pub status: Status,

    pub reason: String,

    #[serde(skip)]
    pub code: u16,
}

impl Display for ErrorResponse {
    
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("ErrorResponse [{}]: {}", self.code, self.reason.as_str()))
    }
}


/**
 * 
 */


pub struct RegisterContent {

    pub server_name: String
}

impl WriteTo for RegisterContent {
    type Error = io::Error;

    fn write_to<W: io::Write + Sync + Send>(&self, mut w: W) -> Result<(), Self::Error> {
        w.write_fmt(format_args!("server_name: {}\n", self.server_name))?;
        Ok(())
    }
}


pub struct RegisterRequest<'a> {
    content: RegisterContent,
    cert: &'a Cert,
    keypair: KeyPair,
}

impl<'a> RegisterRequest<'a> {

    pub fn new(content: RegisterContent, cert: &'a Cert, keypair: KeyPair) -> Self {
        RegisterRequest {
            content,
            cert,
            keypair
        }
    }
}

impl<'a> WriteTo for RegisterRequest<'a> {
    type Error = anyhow::Error;

    fn write_to<W: io::Write + Sync + Send>(&self, w: W) -> Result<(), Self::Error> {

        #[derive(Serialize)]
        struct RegisterRaw<'a> {
            message: Cow<'a, str>,
            public_key: Cow<'a, str>,
        }

        let public_key = {
            let mut buf: Vec<u8> = Vec::new();
            pgp::export_publickey(self.cert, &mut buf)?;
            buf
        };

        let message = {
            let mut buf: Vec<u8> = Vec::new();
            let mut w = pgp::build_signer(&mut buf, vec![self.keypair.clone()])?;
            self.content.write_to(&mut w)?;
            w.finalize()?;
            buf
        };

        let raw = RegisterRaw {
            message: String::from_utf8_lossy(&message),
            public_key: String::from_utf8_lossy(&public_key),
        };

        serde_json::to_writer(w, &raw)?;

        Ok(())
    }
}

impl<'a> RequestInfo for RegisterRequest<'a> {

    fn method(&self) -> RequestMethod {
        RequestMethod::PUT
    }

    fn content_type(&self) -> &'static str {
        "application/json"
    }

    fn url<'b>(&self, base_url: &'b Url) -> Cow<'b, Url> {
        Cow::Owned(base_url.join("server/register").unwrap())
    }
}


#[derive(Deserialize)]
pub struct RegisterResponse {

    pub status: Status,

    pub uuid: Uuid,
}



/**
 * 
 */


pub struct UnregisterContent {
    
    pub timestamp: u64,

    pub comment: String,
}

impl WriteTo for UnregisterContent {
    type Error = io::Error;

    fn write_to<W: io::Write + Sync + Send>(&self, mut w: W) -> Result<(), Self::Error> {
        w.write_fmt(format_args!("timestamp: {}\n", self.timestamp))?;
        w.write_fmt(format_args!("comment: {}\n", self.comment))?;
        Ok(())
    }
}


pub struct UnregisterRequest {
    content: UnregisterContent,
    keypair: KeyPair,
    server_uuid: Uuid,
}

impl UnregisterRequest {

    pub fn new(content: UnregisterContent, keypair: KeyPair,server_uuid: Uuid) -> Self {
        UnregisterRequest {
            content,
            keypair,
            server_uuid,
        }
    }
}

impl WriteTo for UnregisterRequest {
    type Error = anyhow::Error;

    fn write_to<W: io::Write + Sync + Send>(&self, w: W) -> Result<(), Self::Error> {
        let mut w = pgp::build_signer(w, vec![self.keypair.clone()])?;
        self.content.write_to(&mut w)?;
        w.finalize()?;
        Ok(())
    }
}

impl RequestInfo for UnregisterRequest {

    fn method(&self) -> RequestMethod {
        RequestMethod::DELETE
    }

    fn content_type(&self) -> &'static str {
        "text/plain"
    }

    fn url<'b>(&self, base_url: &'b Url) -> Cow<'b, Url> {
        Cow::Owned(base_url.join(&format!("server/uuid/{}", self.server_uuid.to_hyphenated_ref())).unwrap())
    }
}


#[derive(Deserialize)]
pub struct UnregisterResponse {
    
    pub status: Status,

    pub uuid: Uuid,
}

/**
 * 
 */


#[derive(Debug)]
pub struct SubmitContent {

    pub uuid: Uuid,

    pub timestamp: u64,

    pub player_uuid: Uuid,

    pub points: f32,

    pub comment: String,
}

impl WriteTo for SubmitContent {
    type Error = io::Error;

    fn write_to<W: io::Write + Sync + Send>(&self, mut w: W) -> Result<(), Self::Error> {
        w.write_fmt(format_args!("uuid: {}\n", self.uuid))?;
        w.write_fmt(format_args!("timestamp: {}\n", self.timestamp))?;
        w.write_fmt(format_args!("player_uuid: {}\n", self.player_uuid))?;
        w.write_fmt(format_args!("points: {}\n", self.points))?;
        w.write_fmt(format_args!("comment: {}\n", self.comment))?;
        Ok(())
    }
}

impl ReadFrom for SubmitContent {
    type Error = anyhow::Error;

    fn read_from<R: io::Read>(mut r: R) -> Result<Self, Self::Error> {
        let mut buf = String::new();
        r.read_to_string(&mut buf)?;
        let mut tmp_uuid = None;
        let mut tmp_timestamp = None;
        let mut tmp_player_uuid = None;
        let mut tmp_points = None;
        let mut comment = String::new();
        for s in buf.lines() {
            if let Some((key, value)) = s.split_once(':') {
                let key = key.trim();
                let value = value.trim();
                match key {
                    "uuid" => tmp_uuid = Some(Uuid::from_str(value)?),
                    "timestamp" => tmp_timestamp = Some(u64::from_str(value)?),
                    "player_uuid" => tmp_player_uuid = Some(Uuid::from_str(value)?),
                    "points" => tmp_points = Some(f32::from_str(value)?),
                    "comment" => comment = String::from(value),
                    _ => { }
                }
            }
        }

        let data = SubmitContent {
            uuid: tmp_uuid.ok_or_else(|| anyhow::anyhow!("missing field: uuid"))?,
            timestamp: tmp_timestamp.ok_or_else(|| anyhow::anyhow!("missing field: timestamp"))?,
            player_uuid: tmp_player_uuid.ok_or_else(|| anyhow::anyhow!("missing field: player_uuid"))?,
            points: tmp_points.ok_or_else(|| anyhow::anyhow!("missing field: points"))?,
            comment
        };
        Ok(data)
    }
}


pub struct SubmitRequest {
    content: SubmitContent,
    keypair: KeyPair
}

impl SubmitRequest {

    pub fn new(content: SubmitContent, keypair: KeyPair) -> Self {
        SubmitRequest {
            content,
            keypair
        }
    }
}

impl WriteTo for SubmitRequest {
    type Error = anyhow::Error;

    fn write_to<W: io::Write + Sync + Send>(&self, w: W) -> Result<(), Self::Error> {
        let mut w = pgp::build_signer(w, vec![self.keypair.clone()])?;
        self.content.write_to(&mut w)?;
        w.finalize()?;
        Ok(())
    }
}

impl RequestInfo for SubmitRequest {

    fn method(&self) -> RequestMethod {
        RequestMethod::PUT
    }

    fn content_type(&self) -> &'static str {
        "text/plain"
    }

    fn url<'b>(&self, base_url: &'b Url) -> Cow<'b, Url> {
        Cow::Owned(base_url.join("submit/new").unwrap())
    }
}


#[derive(Deserialize)]
pub struct SubmitResponse {

    pub status: Status,
    
    pub uuid: Uuid,
}



/**
 * 
 */


pub struct RecallContent {

    pub timestamp: u64,

    pub comment: String
}

impl WriteTo for RecallContent {
    type Error = io::Error;

    fn write_to<W: io::Write + Sync + Send>(&self, mut w: W) -> Result<(), Self::Error> {
        w.write_fmt(format_args!("timestamp: {}\n", self.timestamp))?;
        w.write_fmt(format_args!("comment: {}\n", self.comment))?;
        Ok(())
    }
}


pub struct RecallRequest {
    submit_uuid: Uuid,
    content: RecallContent,
    keypair: KeyPair
}

impl RecallRequest {

    pub fn new(submit_uuid: Uuid, content: RecallContent, keypair: KeyPair) -> Self {
        RecallRequest {
            submit_uuid,
            content,
            keypair
        }
    }
}

impl WriteTo for RecallRequest {
    type Error = anyhow::Error;

    fn write_to<W: io::Write + Sync + Send>(&self, w: W) -> Result<(), Self::Error> {
        let mut w = pgp::build_signer(w, vec![self.keypair.clone()])?;
        self.content.write_to(&mut w)?;
        w.finalize()?;
        Ok(())
    }
}

impl RequestInfo for RecallRequest {

    fn method(&self) -> RequestMethod {
        RequestMethod::DELETE
    }

    fn content_type(&self) -> &'static str {
        "text/plain"
    }

    fn url<'b>(&self, base_url: &'b Url) -> Cow<'b, Url> {
        Cow::Owned(base_url.join(&format!("submit/uuid/{}", self.submit_uuid.to_hyphenated_ref())).unwrap())
    }
}


#[derive(Deserialize)]
pub struct RecallResponse {
    
    pub status: Status,

    pub uuid: Uuid,
}



/**
 * 
 */


pub struct ServerListRequest {
    limit: Option<usize>,
}

impl ServerListRequest {

    pub fn new(limit: Option<usize>) -> Self {
        ServerListRequest {
            limit
        }
    }
}

impl WriteTo for ServerListRequest {
    type Error = anyhow::Error;

    fn write_to<W: io::Write + Sync + Send>(&self, w: W) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl RequestInfo for ServerListRequest {

    fn method(&self) -> RequestMethod {
        RequestMethod::GET
    }

    fn content_type(&self) -> &'static str {
        ""
    }

    fn url<'b>(&self, base_url: &'b Url) -> Cow<'b, Url> {
        let mut url = base_url.join("server/list").unwrap();
        if let Some(limit) = self.limit {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("limit", limit.to_string().as_str());
        }
        Cow::Owned(url)
    }
}

#[derive(Deserialize)]
pub struct ServerListResponse {

    pub status: Status,

    pub servers: Vec<ServerData>
}

#[derive(Deserialize)]
pub struct ServerData {

    pub id: usize,

    pub server_name: String,

    pub uuid: Uuid,

    #[serde(deserialize_with = "deserialize_fromstr")]
    pub key_id: KeyID,

    #[serde(deserialize_with = "deserialize_fromstr")]
    pub public_key: Cert,
}



/**
 * 
 */


pub struct GetSubmitRequest {
    submit_uuid: Uuid, 
}

impl GetSubmitRequest {

    pub fn new(submit_uuid: Uuid) -> Self {
        GetSubmitRequest {
            submit_uuid
        }
    }
}

impl WriteTo for GetSubmitRequest {
    type Error = anyhow::Error;

    fn write_to<W: io::Write + Sync + Send>(&self, w: W) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl RequestInfo for GetSubmitRequest {

    fn method(&self) -> RequestMethod {
        RequestMethod::GET
    }

    fn content_type(&self) -> &'static str {
        ""
    }

    fn url<'b>(&self, base_url: &'b Url) -> Cow<'b, Url> {
        Cow::Owned(base_url.join(&format!("submit/uuid/{}", self.submit_uuid.to_hyphenated_ref())).unwrap())
    }
}


#[derive(Deserialize)]
pub struct GetSubmitResponse {

    pub status: Status,

    pub uuid: Uuid,

    pub server_uuid: Uuid,

    pub content: String,
}



/**
 * 
 */


pub enum ServerHandle {
    ServerUUID(Uuid),
    KeyID(KeyID)
}

impl From<Uuid> for ServerHandle {

    fn from(v: Uuid) -> Self {
        Self::ServerUUID(v)
    }
}

impl From<KeyID> for ServerHandle {

    fn from(v: KeyID) -> Self {
        Self::KeyID(v)
    }
}

pub struct GetServerSubmitRequest {
    handle: ServerHandle,
    limit: Option<usize>,
    after: Option<u64>,
}

impl GetServerSubmitRequest {

    pub fn new(handle: ServerHandle, limit: Option<usize>, after: Option<u64>) -> Self {
        GetServerSubmitRequest {
            handle,
            limit,
            after
        }
    }
}

impl WriteTo for GetServerSubmitRequest {
    type Error = anyhow::Error;

    fn write_to<W: io::Write + Sync + Send>(&self, w: W) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl RequestInfo for GetServerSubmitRequest {

    fn method(&self) -> RequestMethod {
        RequestMethod::GET
    }

    fn content_type(&self) -> &'static str {
        ""
    }

    fn url<'b>(&self, base_url: &'b Url) -> Cow<'b, Url> {
        let path = match &self.handle {
            ServerHandle::ServerUUID(server_uuid) => {
                format!("submit/server/{}", server_uuid.to_hyphenated_ref())
            }
            ServerHandle::KeyID(key_id) => {
                format!("submit/key/{}", key_id)
            }
        };
        let mut url = base_url.join(&path).unwrap();
        {
            let mut pairs = url.query_pairs_mut();
            if let Some(limit) = self.limit {
                pairs.append_pair("limit", limit.to_string().as_str());
            }
            if let Some(after) = self.after {
                pairs.append_pair("after", after.to_string().as_str());
            }
        }
        Cow::Owned(url)
    }
}


#[derive(Deserialize)]
pub struct GetServerSubmitResponse {

    pub status: Status,

    pub submits: Vec<GetServerSubmitResponseSingle>,
}

#[derive(Deserialize)]
pub struct GetServerSubmitResponseSingle {

    pub id: usize,

    pub uuid: Uuid,

    pub server_uuid: Uuid,

    pub content: String,
}