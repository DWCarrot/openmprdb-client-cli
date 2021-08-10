use std::io;
use std::error;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;
use std::time::SystemTime;
use std::env;
use std::borrow::Borrow;
use std::path::Path;
use std::fs::File;


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

#[derive(Debug)]
pub enum AppError<'a, E> {

    MissingParameter { name: &'static str },

    InvalidParameter { name: &'static str, value: &'a str },

    Execute(E),

    Unexpected(E)
}

impl<'a, E: error::Error> fmt::Display for AppError<'a, E> {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingParameter { name } => {
                f.write_fmt(format_args!("missing parameter: {}", name))?;
            }
            Self::InvalidParameter { name, value } => {
                f.write_fmt(format_args!("invalid parameter: {} = {}", name, value))?;
            }
            Self::Execute(e)=> {
                f.write_fmt(format_args!("{}", e))?;
            }
            Self::Unexpected(e) => {
                f.write_fmt(format_args!("[unexpected] {}", e))?;
            }
        }
        Ok(())
    }
}

impl<'a, E: error::Error + 'static> error::Error for AppError<'a, E> {

    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::MissingParameter { name } => {
                None
            }
            Self::InvalidParameter { name, value } => {
                None
            }
            Self::Execute(e)=> {
                Some(e)
            }
            Self::Unexpected(e) => {
                Some(e)
            }
        }
    }
}

impl<'a> AppError<'a, anyhow::Error> {

    pub fn unwrap_option<'b, T>(value: &'b Option<T>, name: &'static str) -> Result<&'b T, Self> {
        if let Some(v) = value {
            Ok(v)
        } else {
            Err(Self::MissingParameter { name })
        }
    }

    pub fn parse<T: FromStr>(s: &'a str, name: &'static str) -> Result<T, Self> {
        match s.parse() {
            Ok(v) => Ok(v),
            Err(e) => Err(Self::InvalidParameter { name, value: s })
        }
    }
}

fn timestamp<'a>(now: SystemTime) -> Result<u64, AppError<'a, anyhow::Error>> {
    match now.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => Ok(d.as_secs()),
        Err(e) => Err(AppError::Unexpected(e.into()))
    }
}

//////////////////////////////////////////////////////

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

pub fn command_keyring(cfg: &mut config::Config) -> Result<(), AppError<'_, anyhow::Error>> {
    let (policy, certs, key_id, fingerprint) = {
        let cfg_data = cfg.get_data();
        let policy = StandardPolicy::new();
        let certs = pgp::load_keyring(AppError::unwrap_option(&cfg_data.cert_file, "config.cert_file")?)
            .map_err(|e| AppError::Execute(e.into()))?;
        let fingerprint = cfg_data.fingerprint.as_ref();
        let key_id = cfg_data.key_id.as_ref();
        (policy, certs, key_id, fingerprint)
    };
    println!("\n{}", pgp::CertsInfo::new(certs.as_slice(), key_id, fingerprint, &policy));

    if certs.len() == 1 {
        if cfg.get_data().fingerprint.is_none() {
            let fingerprint = certs[0].fingerprint();
            println!("update config.fingerprint = {}", &fingerprint);
            cfg.get_data_mut().fingerprint = Some(fingerprint);
        }
    }

    Ok(())
}

//////////////////////////////////////////////////////

pub fn command_register<'a>(cfg: &mut config::Config, server_name: &'a str) -> Result<(), AppError<'a, anyhow::Error>> {
    let (policy, cert, key_id, api_url) = {
        let cfg_data = cfg.get_data();
        let policy = StandardPolicy::new();
        let cert = pgp::load_cert_from_keyring(
            AppError::unwrap_option(&cfg_data.cert_file, "config.cert_file")?,
            &cfg_data.fingerprint
        )
        .map_err(|e| AppError::Execute(e.into()))?
        .ok_or_else(|| AppError::MissingParameter { name: "config.fingerprint" })?;
        let key_id = AppError::unwrap_option(&cfg_data.key_id, "config.key_id")?;
        let api_url = AppError::unwrap_option(&cfg_data.api_url, "config.api_url" )?;
        (policy, cert, key_id, api_url)
    };
    let keypair = pgp::get_signing_key(&cert, &policy, Some(SystemTime::now()), key_id, &pgp::TTYPasswordProvider)
        .map_err(|e| AppError::Execute(e))?;

    let req = api::RegisterRequest::new(
        api::RegisterContent{ server_name: server_name.to_string() }, 
        &cert, 
        keypair
    );

    match request::<api::RegisterRequest, api::RegisterResponse>(api_url, req)
            .map_err(|e| AppError::Execute(e))? {
        Ok(s) => {
            println!("succeed\n+ server_uuid: {}", s.uuid);
            cfg.get_data_mut().server_uuid = Some(s.uuid);
        }
        Err(e) => {
            eprintln!("failed: {}", e.reason);
        }
    }

    Ok(())
}

pub fn command_unregister<'a>(cfg: &mut config::Config, comment: &'a str) -> Result<(), AppError<'a, anyhow::Error>> {
    
    let (policy, cert, key_id, api_url, server_uuid, comment) = {
        let cfg_data = cfg.get_data();
        let policy = StandardPolicy::new();
        let cert = pgp::load_cert_from_keyring(
            AppError::unwrap_option(&cfg_data.cert_file, "config.cert_file")?,
            &cfg_data.fingerprint
        )
        .map_err(|e| AppError::Execute(e.into()))?
        .ok_or_else(|| AppError::MissingParameter { name: "config.fingerprint" })?;
        let key_id = AppError::unwrap_option(&cfg_data.key_id, "config.key_id")?;
        let api_url = AppError::unwrap_option(&cfg_data.api_url, "config.api_url" )?;
        let server_uuid = AppError::unwrap_option(&cfg_data.server_uuid, "config.server_uuid" )?.clone();
        let comment = comment.to_string();

        (policy, cert, key_id, api_url, server_uuid, comment)
    };

    let keypair = pgp::get_signing_key(&cert, &policy, Some(SystemTime::now()), key_id, &pgp::TTYPasswordProvider)
        .map_err(|e| AppError::Execute(e))?;
    let req = api::UnregisterRequest::new(
        api::UnregisterContent{ 
            timestamp: timestamp(SystemTime::now())?,
            comment,
        },
        keypair,
        server_uuid
    );

    match request::<api::UnregisterRequest, api::UnregisterResponse>(api_url, req)
        .map_err(|e| AppError::Execute(e))? {
        Ok(s) => {
            println!("succeed\n- server_uuid: {}", s.uuid);
            cfg.get_data_mut().server_uuid = None;
        }
        Err(e) => {
            eprintln!("failed: {}", e.reason);
        }
    }
    Ok(())
}


pub fn command_submit<'a>(cfg: &mut config::Config, player_uuid: &'a str, points: &'a str, comment: &'a str) -> Result<(), AppError<'a, anyhow::Error>> {
    
    let cfg_data = cfg.get_data();
    let policy = StandardPolicy::new();
    let cert = pgp::load_cert_from_keyring(
        AppError::unwrap_option(&cfg_data.cert_file, "config.cert_file")?,
        &cfg_data.fingerprint
    )
    .map_err(|e| AppError::Execute(e.into()))?
    .ok_or_else(|| AppError::MissingParameter { name: "config.fingerprint" })?;
    let key_id = AppError::unwrap_option(&cfg_data.key_id, "config.key_id")?;
    let api_url = AppError::unwrap_option(&cfg_data.api_url, "config.api_url" )?;
    let server_uuid = AppError::unwrap_option(&cfg_data.server_uuid, "config.server_uuid" )?.clone();
    let player_uuid = AppError::parse(player_uuid, "player_uuid")?;
    let points: f32 = AppError::parse(points, "points")?;
    let comment = comment.to_string();

    let keypair = pgp::get_signing_key(&cert, &policy, Some(SystemTime::now()), key_id, &pgp::TTYPasswordProvider)
        .map_err(|e| AppError::Execute(e))?;
    let req = api::SubmitRequest::new(
        api::SubmitContent{ 
            uuid: server_uuid,
            timestamp: timestamp(SystemTime::now())?,
            player_uuid,
            points,
            comment,
        },
        keypair
    );

    match request::<api::SubmitRequest, api::SubmitResponse>(api_url, req)
        .map_err(|e| AppError::Execute(e))? {
        Ok(s) => {
            println!("succeed\n+ record_uuid: {}", s.uuid);
        }
        Err(e) => {
            eprintln!("failed: {:?}", e);
        }
    }
    Ok(())
}

pub fn command_recall<'a>(cfg: &mut config::Config, record_uuid: &'a str, comment: &'a str) -> Result<(), AppError<'a, anyhow::Error>> {
    
    let cfg_data = cfg.get_data();
    let policy = StandardPolicy::new();
    let cert = pgp::load_cert_from_keyring(
        AppError::unwrap_option(&cfg_data.cert_file, "config.cert_file")?,
        &cfg_data.fingerprint
    )
    .map_err(|e| AppError::Execute(e.into()))?
    .ok_or_else(|| AppError::MissingParameter { name: "config.fingerprint" })?;
    let key_id = AppError::unwrap_option(&cfg_data.key_id, "config.key_id")?;
    let api_url = AppError::unwrap_option(&cfg_data.api_url, "config.api_url" )?;
    let server_uuid = AppError::unwrap_option(&cfg_data.server_uuid, "config.server_uuid")?.clone();
    let record_uuid = AppError::parse(record_uuid, "record_uuid")?;
    let comment = comment.to_string();

    let keypair = pgp::get_signing_key(&cert, &policy, Some(SystemTime::now()), key_id, &pgp::TTYPasswordProvider)
        .map_err(|e| AppError::Execute(e))?;
    let req = api::RecallRequest::new(
        record_uuid,
        api::RecallContent{
            timestamp: timestamp(SystemTime::now())?,
            comment,
        },
        keypair
    );

    match request::<api::RecallRequest, api::RecallResponse>(api_url, req)
            .map_err(|e| AppError::Execute(e))? {
        Ok(s) => {
            println!("succeed\n- record_uuid: {}", s.uuid);
        }
        Err(e) => {
            eprintln!("failed: {:?}", e);
        }
    }
    Ok(())
}


pub fn command_certs_add<'a>(cfg: &mut config::Config, server_uuid: &'a str, name: &'a str, key_id: &'a str, trust: &'a str) -> Result<(), AppError<'a, anyhow::Error>> {

    let policy = StandardPolicy::new();

    let dir = {
        let mut dir = config::current_exe_path().map_err(|e| AppError::Unexpected(e.into()))?;
        dir.push("servers");
        if !dir.is_dir() {
            std::fs::create_dir_all(dir.as_path()).map_err(|e| AppError::Unexpected(e.into()))?;
        }
        dir
    };
    let insert = certs_add(
        cfg, 
        AppError::parse(server_uuid, "server_uuid")?, 
        name.to_owned(), 
        AppError::parse(key_id, "key_id")?, 
        AppError::parse(trust, "trust")?, 
        pgp::read_cert_from_console,
        &policy,
        dir
    )
    .map_err(|e| AppError::Execute(e.into()))?;

    if !insert {
        Err(AppError::Execute(anyhow!("server exsit already")))
    } else {
        Ok(())
    }
}

pub fn certs_add<'a, P, C>(cfg: &mut config::Config, server_uuid: Uuid, name: String, key_id: KeyID, trust: u32, cert: C, p: &dyn Policy, folder: P) -> GeneralResult<bool> 
where
    P: AsRef<Path>,
    C: FnOnce() -> GeneralResult<Cert>
{
    use std::collections::hash_map::Entry;

    let servers = &mut cfg.get_data_mut().servers;

    let insert = match servers.entry(server_uuid) {
        Entry::Occupied(o) => {
            false
        }
        Entry::Vacant(v) => {
            let cert = cert()?;
            if !pgp::check_key(&cert, p, Some(SystemTime::now()), &key_id)? {
                return Err(anyhow!("key_id {} doesn't exist in {}", &key_id, &cert))
            }

            let folder = folder.as_ref();
    
            {
                let path = folder.join(server_uuid.to_simple_ref().encode_upper(&mut Uuid::encode_buffer()));
                let mut ofile = File::create(path)?;
                pgp::export_publickey_raw(&cert, &mut ofile)?;
            }
            
            let server_data = config::ServerData {
                name,
                key_id,
                fingerprint: cert.fingerprint(),
                trust
            };

            v.insert(server_data);

            true
        }
    };

    Ok(insert)
}


pub fn command_certs_remove<'a>(cfg: &mut config::Config, server_uuid: &'a str) -> Result<(), AppError<'a, anyhow::Error>> {

    let dir = {
        let mut dir = config::current_exe_path().map_err(|e| AppError::Unexpected(e.into()))?;
        dir.push("servers");
        if !dir.is_dir() {
            return Err(AppError::Unexpected(anyhow!("servers folder disappear")))
        }
        dir
    };
    let remove = certs_remove(
        cfg, 
        &AppError::parse(server_uuid, "server_uuid")?, 
        dir
    )
    .map_err(|e| AppError::Execute(e.into()))?;

    if !remove {
        Err(AppError::Execute(anyhow!("server exsit already")))
    } else {
        Ok(())
    }
}

pub fn certs_remove<'a, P: AsRef<Path>>(cfg: &mut config::Config, server_uuid: &Uuid, folder: P) -> GeneralResult<bool> {

    let remove = match cfg.get_data_mut().servers.remove(server_uuid) {
        Some(data) => {
            let folder = folder.as_ref();
            let path = folder.join(server_uuid.to_simple_ref().encode_upper(&mut Uuid::encode_buffer()));
            if path.is_file() {
                std::fs::remove_file(path)?;
            }
            true
        }
        None => {
            false
        }
    };

    Ok(remove)
}