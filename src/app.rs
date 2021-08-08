use std::io;
use std::str::FromStr;
use std::time::Duration;
use std::time::SystemTime;
use std::env;
use std::borrow::Borrow;


use sequoia_openpgp::Cert;
use sequoia_openpgp::KeyID;
use sequoia_openpgp::policy::Policy;
use sequoia_openpgp::policy::StandardPolicy;
use anyhow::Result as GeneralResult;
use anyhow::anyhow;
use serde::de::DeserializeOwned;
use ureq::AgentBuilder;
use ureq::Agent;
use ureq::Proxy;
use uuid::Uuid;
use url::Url;


use crate::pgp;
use crate::api;
use crate::config;
use api::WriteTo;
use api::RequestInfo;
use api::RequestMethod;
use pgp::PasswordProvider;

//////////////////////////////////////////////////////

pub trait App {

    fn execute(self) -> GeneralResult<()>;
}

pub fn request<I, O>(api_url: &Url, req: I) -> GeneralResult<Result<O, api::ErrorResponse>> 
where 
    I: WriteTo<Error = anyhow::Error> + RequestInfo,
    O: DeserializeOwned
{
    let mut ab = AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10));
    if let Ok(s) = env::var("HTTP_PROXY") {
        let proxy = Proxy::new(s)?;
        ab = ab.proxy(proxy)
    } else {
        if let Ok(s) = env::var("SOCKS_PROXY") {
            let proxy = Proxy::new(s)?;
            ab = ab.proxy(proxy)
        }
    }
    let agent = ab.build();
    let mut buf = Vec::with_capacity(256 * 1024);
    req.write_to(&mut buf)?;

    let method = match req.method() {
        RequestMethod::GET => "GET",
        RequestMethod::PUT => "PUT",
        RequestMethod::POST => "POST",
        RequestMethod::DELETE => "DELETE",
        RequestMethod::PATCH => "PATCH",
    };
    let url = req.url(api_url);

    println!("{} {} ({})\n\n{}", &method, &url, req.content_type(), String::from_utf8_lossy(buf.as_slice()));

    let response = agent.request_url(method, url.borrow())
        .set("Content-Type", req.content_type())
        .send(buf.as_slice());
    match response {
        Ok(response) => {
            let rdr = response.into_reader();
            Ok(Ok(serde_json::from_reader(rdr)?))
        },
        Err(e) => {
            match e {
                ureq::Error::Status(code, response) => {
                    let s = response.into_string()?;
                    let deserialized: Result<api::ErrorResponse, _> = serde_json::from_str(s.as_str());
                    let resp = match deserialized {
                        Ok(mut resp) => { resp.code = code; resp },
                        Err(e) => api::ErrorResponse { status: api::Status::Unexpected, reason: s , code }
                    };
                    Ok(Err(resp))
                },
                ureq::Error::Transport(transport) => {
                    Err(transport.into())
                }
            }
        }
    }
}

//////////////////////////////////////////////////////

pub fn command_keys(cfg: &config::ConfigData) -> GeneralResult<()> {
    let policy = StandardPolicy::new();
    let cert = pgp::load(cfg.cert_file.as_ref().ok_or_else(|| anyhow!("cert_file have not been specific"))?)?;
    let key_id = cfg.key_id.as_ref();
    println!("\n{}", pgp::CertInfo::new(&cert, key_id, &policy));
    Ok(())
}

//////////////////////////////////////////////////////

pub fn command_register(cfg: &mut config::ConfigData, server_name: &str) -> GeneralResult<()> {
    let policy = StandardPolicy::new();
    let cert = pgp::load(cfg.cert_file.as_ref().ok_or_else(|| anyhow!("config.cert_file have not been specific"))?)?;
    let key_id = cfg.key_id.as_ref().ok_or_else(|| anyhow!("config.key_id have not been specific"))?.clone();
    let api_url = cfg.api_url.as_ref().ok_or_else(|| anyhow!("config.api_url have not been specific"))?;
    
    let keypair = pgp::get_signing_key(&cert, &policy, Some(SystemTime::now()), key_id, &pgp::TTYPasswordProvider)?;
    let req = api::RegisterRequest::new(
        api::RegisterContent{ server_name: server_name.to_string() }, 
        &cert, 
        keypair
    );

    match request::<api::RegisterRequest, api::RegisterResponse>(api_url, req)? {
        Ok(s) => {
            println!("succeed\n+ server_uuid: {}", s.uuid);
            cfg.server_uuid = Some(s.uuid);
        }
        Err(e) => {
            eprintln!("failed: {}", e.reason);
        }
    }
    Ok(())
}

pub fn command_unregister(cfg: &mut config::ConfigData, comment: &str) -> GeneralResult<()> {
    let policy = StandardPolicy::new();
    let cert = pgp::load(cfg.cert_file.as_ref().ok_or_else(|| anyhow!("config.cert_file have not been specific"))?)?;
    let key_id = cfg.key_id.as_ref().ok_or_else(|| anyhow!("config.key_id have not been specific"))?.clone();
    let api_url = cfg.api_url.as_ref().ok_or_else(|| anyhow!("config.api_url have not been specific"))?;
    let server_uuid = cfg.server_uuid.as_ref().ok_or_else(|| anyhow!("config.server_uuid have not been specific or server have not been registered"))?.clone();
    let comment = comment.to_string();

    let keypair = pgp::get_signing_key(&cert, &policy, Some(SystemTime::now()), key_id, &pgp::TTYPasswordProvider)?;
    let req = api::UnregisterRequest::new(
        api::UnregisterContent{ 
            timestamp: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs(),
            comment,
        },
        keypair,
        server_uuid
    );

    match request::<api::UnregisterRequest, api::UnregisterResponse>(api_url, req)? {
        Ok(s) => {
            println!("succeed\n- server_uuid: {}", s.uuid);
            cfg.server_uuid = None;
        }
        Err(e) => {
            eprintln!("failed: {}", e.reason);
        }
    }
    Ok(())
}


pub fn command_submit(cfg: &config::ConfigData, player_uuid: &str, points: f32, comment: &str) -> GeneralResult<()> {
    let policy = StandardPolicy::new();
    let cert = pgp::load(cfg.cert_file.as_ref().ok_or_else(|| anyhow!("config.cert_file have not been specific"))?)?;
    let key_id = cfg.key_id.as_ref().ok_or_else(|| anyhow!("config.key_id have not been specific"))?.clone();
    let api_url = cfg.api_url.as_ref().ok_or_else(|| anyhow!("config.api_url have not been specific"))?;
    let server_uuid = cfg.server_uuid.as_ref().ok_or_else(|| anyhow!("config.server_uuid have not been specific or server have not been registered"))?.clone();
    let player_uuid = Uuid::from_str(player_uuid)?;
    let comment = comment.to_string();

    let keypair = pgp::get_signing_key(&cert, &policy, Some(SystemTime::now()), key_id, &pgp::TTYPasswordProvider)?;
    let req = api::SubmitRequest::new(
        api::SubmitContent{ 
            uuid: server_uuid,
            timestamp: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs(),
            player_uuid,
            points,
            comment,
        },
        keypair
    );

    match request::<api::SubmitRequest, api::SubmitResponse>(api_url, req)? {
        Ok(s) => {
            println!("succeed\n+ record_uuid: {}", s.uuid);
        }
        Err(e) => {
            eprintln!("failed: {:?}", e);
        }
    }
    Ok(())
}