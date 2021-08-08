use std::io;
use std::borrow::Cow;
use std::fmt::Display;

use serde::Serialize;
use serde::Deserialize;
use sequoia_openpgp::Cert;
use sequoia_openpgp::crypto::KeyPair;
use sequoia_openpgp::armor::Writer;
use sequoia_openpgp::armor::Kind;
use sequoia_openpgp::serialize::Serialize as _;
use url::Url;
use uuid::Uuid;

use crate::pgp;


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
            let mut w = Writer::new(&mut buf, Kind::PublicKey)?;
            self.cert.serialize(&mut w)?;
            w.finalize()?;
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

    timestamp: u64,

    comment: String
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