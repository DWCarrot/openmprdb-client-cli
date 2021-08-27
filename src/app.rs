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
use std::collections::HashMap;
use std::ops::Range;


use sequoia_openpgp::Cert;
use sequoia_openpgp::KeyID;
use sequoia_openpgp::KeyHandle;
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
use chrono::NaiveDateTime;


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

    ErrorResponse(api::ErrorResponse),

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
            Self::ErrorResponse(e) => {
                f.write_fmt(format_args!("{}", e))?;
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
            Self::ErrorResponse(e) => {
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

impl<'a> From<anyhow::Error> for AppError<'a, anyhow::Error> {

    fn from(e: anyhow::Error) -> Self {
        Self::Execute(e)
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

    pub fn execute_with_message(msg: &'static str) -> Self {
        Self::Execute(anyhow!(msg))
    }
}

fn timestamp<'a>(now: SystemTime) -> Result<u64, AppError<'a, anyhow::Error>> {
    match now.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => Ok(d.as_secs()),
        Err(e) => Err(AppError::Unexpected(e.into()))
    }
}

//////////////////////////////////////////////////////

pub fn request<'a, I, O>(api_url: &Url, req: I) -> Result<O, AppError<'a, anyhow::Error>> 
where 
    I: WriteTo<Error = anyhow::Error> + RequestInfo,
    O: DeserializeOwned
{
    let mut ab = AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10));
    if let Ok(s) = env::var("HTTP_PROXY") {
        let proxy = Proxy::new(s).map_err(|e| AppError::Execute(e.into()))?;
        ab = ab.proxy(proxy)
    } else {
        if let Ok(s) = env::var("SOCKS_PROXY") {
            let proxy = Proxy::new(s).map_err(|e| AppError::Execute(e.into()))?;
            ab = ab.proxy(proxy)
        }
    }
    let agent = ab.build();

    let method = match req.method() {
        RequestMethod::GET => "GET",
        RequestMethod::PUT => "PUT",
        RequestMethod::POST => "POST",
        RequestMethod::DELETE => "DELETE",
        RequestMethod::PATCH => "PATCH",
    };
    let url = req.url(api_url);

    let request = agent.request_url(method, url.borrow());

    let response = if !req.content_type().is_empty() {

        let mut buf = Vec::with_capacity(256 * 1024);
        req.write_to(&mut buf)?;

        #[cfg(debug_assertions)]
        {
            println!("{} {} ({})\n\n{}", &method, &url, req.content_type(), String::from_utf8_lossy(buf.as_slice()));
        }

        request.set("Content-Type", req.content_type())
                .send(buf.as_slice())
    } else {

        #[cfg(debug_assertions)]
        {
            println!("{} {} ({})\n\n", &method, &url, req.content_type());
        }

        request.call()
    }; 
        
    match response {
        Ok(response) => {
            let rdr = response.into_reader();
            Ok(serde_json::from_reader(rdr).map_err(|e| AppError::Unexpected(e.into()))?)
        },
        Err(e) => {
            match e {
                ureq::Error::Status(code, response) => {
                    let s = response.into_string().map_err(|e| AppError::Unexpected(e.into()))?;
                    let deserialized: Result<api::ErrorResponse, _> = serde_json::from_str(s.as_str());
                    let resp = match deserialized {
                        Ok(mut resp) => { resp.code = code; resp },
                        Err(e) => api::ErrorResponse { status: api::Status::Unexpected, reason: s , code }
                    };
                    Err(AppError::ErrorResponse(resp))
                },
                ureq::Error::Transport(transport) => {
                    Err(AppError::Unexpected(transport.into()))
                }
            }
        }
    }
}

//////////////////////////////////////////////////////

pub fn command_keyring(cfg: &mut config::client::ClientConfig) -> Result<(), AppError<'_, anyhow::Error>> {
    let cfg_data = cfg.get_data();
    let policy = StandardPolicy::new();
    let certs = pgp::load_keyring(AppError::unwrap_option(&cfg_data.cert_file, "config.cert_file")?)?;
    let key_id = cfg_data.key_id.as_ref();

    println!("\n{}", pgp::CertsInfo::new(certs.as_slice(), key_id, &policy));

    Ok(())
}

pub fn command_register<'a>(cfg: &mut config::client::ClientConfig, server_name: &'a str) -> Result<(), AppError<'a, anyhow::Error>> {
    let cfg_data = cfg.get_data();
    let policy = StandardPolicy::new();
    let key_id = AppError::unwrap_option(&cfg_data.key_id, "config.key_id")?;
    let cert = cfg_data.get_cert()
        .ok_or_else(|| AppError::MissingParameter { name: "config.cert_file" })?;
    let api_url = AppError::unwrap_option(&cfg_data.api_url, "config.api_url" )?;

    let keypair = pgp::get_signing_key(&cert, &policy, Some(SystemTime::now()), key_id, &pgp::TTYPasswordProvider)?;

    let req = api::RegisterRequest::new(
        api::RegisterContent{ server_name: server_name.to_string() }, 
        &cert, 
        keypair
    );

    let s = request::<api::RegisterRequest, api::RegisterResponse>(api_url, req)?;
    println!("succeed\n+ server_uuid: {}", s.uuid);
    cfg.get_data_mut().server_uuid = Some(s.uuid);

    Ok(())
}

pub fn command_unregister<'a>(cfg: &mut config::client::ClientConfig, comment: &'a str) -> Result<(), AppError<'a, anyhow::Error>> {
    let cfg_data = cfg.get_data();
    let policy = StandardPolicy::new();
    let key_id = AppError::unwrap_option(&cfg_data.key_id, "config.key_id")?;
    let cert = cfg_data.get_cert()
        .ok_or_else(|| AppError::MissingParameter { name: "config.cert_file" })?;   
    let api_url = AppError::unwrap_option(&cfg_data.api_url, "config.api_url" )?;
    let server_uuid = AppError::unwrap_option(&cfg_data.server_uuid, "config.server_uuid" )?.clone();
    let comment = comment.to_string();

    let keypair = pgp::get_signing_key(&cert, &policy, Some(SystemTime::now()), key_id, &pgp::TTYPasswordProvider)?;
    let req = api::UnregisterRequest::new(
        api::UnregisterContent{ 
            timestamp: timestamp(SystemTime::now())?,
            comment,
        },
        keypair,
        server_uuid
    );

    let s = request::<api::UnregisterRequest, api::UnregisterResponse>(api_url, req)?;
    println!("succeed\n- server_uuid: {}", s.uuid);
    cfg.get_data_mut().server_uuid = None;
       
    Ok(())
}


pub fn command_submit<'a>(cfg: &mut config::client::ClientConfig, rcfg: &mut config::records::RecordConfig, player_uuid: &'a str, points: &'a str, comment: &'a str) -> Result<(), AppError<'a, anyhow::Error>> {
    let cfg_data = cfg.get_data();
    let policy = StandardPolicy::new();
    let key_id = AppError::unwrap_option(&cfg_data.key_id, "config.key_id")?;
    let cert = cfg_data.get_cert()
        .ok_or_else(|| AppError::MissingParameter { name: "config.cert_file" })?;
    let api_url = AppError::unwrap_option(&cfg_data.api_url, "config.api_url" )?;
    let server_uuid = AppError::unwrap_option(&cfg_data.server_uuid, "config.server_uuid" )?.clone();
    let player_uuid = AppError::parse(player_uuid, "player_uuid")?;
    let points: f32 = AppError::parse(points, "points")?;
    let comment = comment.to_string();

    let keypair = pgp::get_signing_key(&cert, &policy, Some(SystemTime::now()), key_id, &pgp::TTYPasswordProvider)?;
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

    let s = request::<api::SubmitRequest, api::SubmitResponse>(api_url, req)?;
    println!("succeed\n+ record_uuid: {}", s.uuid);
        
    Ok(())
}

pub fn command_recall<'a>(cfg: &mut config::client::ClientConfig, record_uuid: &'a str, comment: &'a str) -> Result<(), AppError<'a, anyhow::Error>> {
    let cfg_data = cfg.get_data();
    let policy = StandardPolicy::new();
    let key_id = AppError::unwrap_option(&cfg_data.key_id, "config.key_id")?;
    let cert = cfg_data.get_cert()
        .ok_or_else(|| AppError::MissingParameter { name: "config.cert_file" })?;
    let api_url = AppError::unwrap_option(&cfg_data.api_url, "config.api_url" )?;
    let record_uuid = AppError::parse(record_uuid, "record_uuid")?;
    let comment = comment.to_string();

    let keypair = pgp::get_signing_key(&cert, &policy, Some(SystemTime::now()), key_id, &pgp::TTYPasswordProvider)?;
    let req = api::RecallRequest::new(
        record_uuid,
        api::RecallContent{
            timestamp: timestamp(SystemTime::now())?,
            comment,
        },
        keypair
    );

    let s = request::<api::RecallRequest, api::RecallResponse>(api_url, req)?;
    println!("succeed\n- record_uuid: {}", s.uuid);
        
    Ok(())
}


pub fn command_cert_add<'a>(cfg: &mut config::client::ClientConfig, server_uuid: &'a str, name: &'a str, key_id: &'a str, trust: &'a str) -> Result<(), AppError<'a, anyhow::Error>> {

    let server_uuid: Uuid = AppError::parse(server_uuid, "server_uuid")?;
    let key_id: KeyID = AppError::parse(key_id, "key_id")?;
    let name = name.to_owned();
    let trust: u32 = AppError::parse(trust, "trust")?;

    let policy = StandardPolicy::new();
    let mut cmgr = pgp::CertificationManager::new(
        config::current_exe_path("servers.pgp").map_err(|e| AppError::Unexpected(e.into()))?
        , &policy
    )?;

    if cmgr.get(&key_id).is_none() {
        let cert = pgp::read_cert_from_console()?;
        if !pgp::check_key(&cert, &policy, Some(SystemTime::now()), &key_id)? {
            return Err(AppError::execute_with_message("key_id not correspond to cert"));
        }


        if cmgr.add(cert.into()) {
            let server_data = config::ServerData {
                name,
                key_id,
                trust
            };
            cfg.get_data_mut().servers.insert(server_uuid, server_data);
            
            println!("added.");
        } else {
            return Err(AppError::execute_with_message("existed"));
        }
    } else {
        return Err(AppError::execute_with_message("existed"));
    }

    Ok(())
}

// pub fn cert_add<'a, P, C>(cfg: &mut config::client::ClientConfig, server_uuid: Uuid, name: String, key_id: KeyID, trust: u32, cert: C, p: &dyn Policy, folder: P) -> GeneralResult<bool> 
// where
//     P: AsRef<Path>,
//     C: FnOnce() -> GeneralResult<Cert>
// {
//     use std::collections::hash_map::Entry;

//     let servers = &mut cfg.get_data_mut().servers;

//     let insert = match servers.entry(server_uuid) {
//         Entry::Occupied(o) => {
//             false
//         }
//         Entry::Vacant(v) => {
//             let cert = cert()?;
//             if !pgp::check_key(&cert, p, Some(SystemTime::now()), &key_id)? {
//                 return Err(anyhow!("key_id {} doesn't exist in {}", &key_id, &cert))
//             }

//             let folder = folder.as_ref();
    
//             {
//                 let path = folder.join(server_uuid.to_simple_ref().encode_upper(&mut Uuid::encode_buffer()));
//                 let mut ofile = File::create(path)?;
//                 pgp::export_publickey_raw(&cert, &mut ofile)?;
//             }
            
//             let server_data = config::ServerData {
//                 name,
//                 key_id,
//                 fingerprint: cert.fingerprint(),
//                 trust
//             };

//             v.insert(server_data);

//             true
//         }
//     };

//     Ok(insert)
// }


pub fn command_cert_remove<'a>(cfg: &mut config::client::ClientConfig, server_uuid: &'a str) -> Result<(), AppError<'a, anyhow::Error>> {
    let server_uuid: Uuid = AppError::parse(server_uuid, "server_uuid")?;
    let policy = StandardPolicy::new();
    let mut cmgr = pgp::CertificationManager::new(
        config::current_exe_path("servers.pgp").map_err(|e| AppError::Unexpected(e.into()))?
        , &policy
    )?;

    if let Some(d) = cfg.get_data().servers.get(&server_uuid) {
        if let Some(cert) = cmgr.get(&d.key_id) {
            cmgr.remove(&cert);
            cfg.get_data_mut().servers.remove(&server_uuid);
            println!("removed.")
        } else {
            return Err(AppError::execute_with_message("certification not exsit"));
        }
    } else {
        return Err(AppError::execute_with_message("server not exsit"));
    }

    Ok(())
}

// pub fn cert_remove<'a, P: AsRef<Path>>(cfg: &mut config::client::ClientConfig, server_uuid: &Uuid, folder: P) -> GeneralResult<bool> {

//     let remove = match cfg.get_data_mut().servers.remove(server_uuid) {
//         Some(data) => {
//             let folder = folder.as_ref();
//             let path = folder.join(server_uuid.to_simple_ref().encode_upper(&mut Uuid::encode_buffer()));
//             if path.is_file() {
//                 std::fs::remove_file(path)?;
//             }
//             true
//         }
//         None => {
//             false
//         }
//     };

//     Ok(remove)
// }


pub fn command_server_list<'a>(cfg: &config::client::ClientConfig, limit: Option<&'a str>) -> Result<(), AppError<'a, anyhow::Error>> {
    let cfg_data = cfg.get_data();
    let api_url = AppError::unwrap_option(&cfg_data.api_url, "config.api_url" )?;
    
    let limit = if let Some(s) = limit {
        Some(AppError::parse(s, "limit")?)
    } else {
        None
    };
    
    let req = api::ServerListRequest::new(limit);
    let s = request::<api::ServerListRequest, api::ServerListResponse>(api_url, req)?;
    
    struct ServerDataDisplay<'a>(&'a api::ServerData);

    impl<'a> fmt::Display for ServerDataDisplay<'a> {
        
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let data = self.0;  
            let mut buf = Vec::new();
            if let Ok(_) = pgp::export_publickey(&data.public_key, &mut buf) {
                f.write_fmt(format_args!("server_name:{}\nserver_uuid: {}\nkey_id:{}\n\n", data.server_name.as_str(), data.uuid.to_hyphenated_ref(), data.key_id))?;
                f.write_str(String::from_utf8_lossy(buf.as_slice()).borrow())?;
            }
            Ok(())
        }
    }

    for d in &s.servers {
        println!("====================\n{}\n\n", ServerDataDisplay(d));
    }

    Ok(())
}


pub fn command_get_submit<'a>(cfg: &config::client::ClientConfig, record_uuid: &'a str) -> Result<(), AppError<'a, anyhow::Error>> {

    let cfg_data = cfg.get_data();
    let policy = StandardPolicy::new();
    let api_url = AppError::unwrap_option(&cfg_data.api_url, "config.api_url" )?;
    let record_uuid: Uuid = AppError::parse(record_uuid, "record_uuid")?;
    
    let mut cmgr = pgp::CertificationManager::new(
        config::current_exe_path("servers.pgp").map_err(|e| AppError::Unexpected(e.into()))?
        , &policy
    )?;

    let req = api::GetSubmitRequest::new(record_uuid);
    let s = request::<api::GetSubmitRequest, api::GetSubmitResponse>(api_url, req)?;

    fn transfer(r: &mut dyn io::Read) -> GeneralResult<api::SubmitContent> {
        api::ReadFrom::read_from(r)
    }

    match pgp::verify(&cmgr, s.content.as_bytes(), transfer) {
        Ok(d) => {
            let server_uuid = &d.uuid;
            let server_data = cfg_data.servers.get(server_uuid)
                .ok_or_else(|| AppError::Unexpected(anyhow!("missing congfig.servers[{}]", server_uuid.to_hyphenated_ref())))?;
            println!("+ Verified Message");
            println!("{}", ServerDataDisplay(server_data, server_uuid));
            println!("{:#?}", &d);
        }
        Err(e) => {
            println!("server_uuid: {}\n", s.server_uuid.to_hyphenated_ref());
            println!("{}\n", &s.content);
            return Err(e.into())
        }
    }

    Ok(())
}

struct ServerDataDisplay<'a>(&'a config::ServerData, &'a Uuid);

impl<'a> fmt::Display for ServerDataDisplay<'a> {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "server: {} [{}]\n   key: {}   trust: {}\n", 
            self.0.name.as_str(),
            self.1.to_hyphenated_ref(),
            self.0.key_id,
            self.0.trust
        ))
    }
}



pub enum ServerHandleWrap<'a> {
    UUID(&'a str),
    KeyID(&'a str),
}

pub fn command_get_server_submit<'a>(cfg: &config::client::ClientConfig, handle: ServerHandleWrap<'a>, limit: Option<&'a str>, after: Option<&'a str>) -> Result<(), AppError<'a, anyhow::Error>> {

    let cfg_data = cfg.get_data();
    let policy = StandardPolicy::new();
    let api_url = AppError::unwrap_option(&cfg_data.api_url, "config.api_url" )?;
    let handle: api::ServerHandle = match handle {
        ServerHandleWrap::UUID(s) => AppError::parse::<Uuid>(s, "server_uuid")?.into(),
        ServerHandleWrap::KeyID(s) => AppError::parse::<KeyID>(s, "key_id")?.into(),
    };
    let limit = if let Some(s) = limit {
        Some(AppError::parse(s, "limit")?)
    } else {
        None
    };
    let after = if let Some(s) = after {
        match NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
            Ok(datetime) => {
                let after = datetime.timestamp();
                if after > 0 {
                    Some(after as u64)
                } else {
                    None
                }
            }   
            Err(e) => {
                return Err(AppError::InvalidParameter{ name: "after", value: s });
            }
        }           
    } else {
        None
    };
    
    let mut cmgr = pgp::CertificationManager::new(
        config::current_exe_path("servers.pgp").map_err(|e| AppError::Unexpected(e.into()))?
        , &policy
    )?;

    let req = api::GetServerSubmitRequest::new(handle, limit, after);
    let sc = request::<api::GetServerSubmitRequest, api::GetServerSubmitResponse>(api_url, req)?;

    fn transfer(r: &mut dyn io::Read) -> GeneralResult<api::SubmitContent> {
        api::ReadFrom::read_from(r)
    }

    for s in &sc.submits {
        match pgp::verify(&cmgr, s.content.as_bytes(), transfer) {
            Ok(d) => {
                let server_uuid = &d.uuid;
                let server_data = cfg_data.servers.get(server_uuid)
                    .ok_or_else(|| AppError::Unexpected(anyhow!("missing congfig.servers[{}]", server_uuid.to_hyphenated_ref())))?;
                println!("+ Verified Message");
                println!("{}", ServerDataDisplay(server_data, server_uuid));
                println!("{:#?}", &d);
            }
            Err(e) => {
                println!("server_uuid: {}\n", s.server_uuid.to_hyphenated_ref());
                println!("{}\n", &s.content);
            }
        }
    }

    Ok(())
}


struct RecordTable<S, D> {
    sp: char,
    servers: Vec<S>,
    data: HashMap<Uuid, Vec<Option<D>>>,
}

impl<S: Clone, D: Clone> RecordTable<S, D> {

    pub fn new<I: IntoIterator<Item = S>>(servers: I, sp: char) -> Self {
        RecordTable {
            sp,
            servers: servers.into_iter().collect(),
            data: HashMap::new()
        }
    }

    pub fn col_range(&self) -> Range<usize> {
        0 .. self.servers.len()
    }

    pub fn get_server(&self, index: usize) -> S {
        self.servers[index].clone()
    }

    pub fn insert(&mut self, uuid: Uuid, index: usize, value: D) {
        let len = self.servers.len();
        if index < len {
            let mut line = self.data.entry(uuid).or_insert_with(|| vec![None; len]);
            unsafe { *(line.get_unchecked_mut(index)) = Some(value); };
        }
    } 
}

impl<D: fmt::Display> WriteTo for RecordTable<(&Uuid, &config::ServerData), D> {
    type Error = io::Error;

    fn write_to<W: io::Write + Sync + Send>(&self, mut w: W) -> Result<(), Self::Error> {
        let sp = self.sp;

        write!(w, "")?;
        for (_, server_data) in &self.servers {
            let server_data = *server_data;
            write!(w, "{}{}", sp, server_data.name.as_str())?;
        }
        writeln!(w, "")?;

        write!(w, "")?;
        for (uuid, _) in &self.servers {
            let uuid = *uuid;
            write!(w, "{}{}", sp, uuid.to_hyphenated_ref())?;
        }
        writeln!(w, "")?;

        write!(w, "")?;
        for (_, server_data) in &self.servers {
            let server_data = *server_data;
            write!(w, "{}{}", sp, server_data.trust)?;
        }
        writeln!(w, "")?;

        for (k, v) in self.data.iter() {
            write!(w, "{}", k.to_hyphenated_ref())?;
            for p in v.iter() {
                if let Some(p) = p {
                    write!(w, "{}{}", sp, p)?;
                } else {
                    write!(w, "{}", sp)?;
                }
            }
            writeln!(w, "")?;
        }

        w.flush()?;
        Ok(())
    }
} 

pub fn command_get_server_submit_auto<'a>(cfg: &config::client::ClientConfig, limit: Option<&'a str>, after: Option<&'a str>, output: &'a str) -> Result<(), AppError<'a, anyhow::Error>> {

    let cfg_data = cfg.get_data();
    let policy = StandardPolicy::new();
    let api_url = AppError::unwrap_option(&cfg_data.api_url, "config.api_url" )?;
    let limit = if let Some(s) = limit {
        Some(AppError::parse(s, "limit")?)
    } else {
        None
    };
    let after = if let Some(s) = after {
        match NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
            Ok(datetime) => {
                let after = datetime.timestamp();
                if after > 0 {
                    Some(after as u64)
                } else {
                    None
                }
            }   
            Err(e) => {
                return Err(AppError::InvalidParameter{ name: "after", value: s });
            }
        }           
    } else {
        None
    };
    
    let mut cmgr = pgp::CertificationManager::new(
        config::current_exe_path("servers.pgp").map_err(|e| AppError::Unexpected(e.into()))?
        , &policy
    )?;

    fn transfer(r: &mut dyn io::Read) -> GeneralResult<api::SubmitContent> {
        api::ReadFrom::read_from(r)
    }

    let mut table: RecordTable<_, f32> = RecordTable::new(cfg_data.servers.iter(), ',');

    for i in table.col_range() {

        let server_uuid = table.get_server(i).0;
        let handle = api::ServerHandle::ServerUUID(server_uuid.clone());
        let req = api::GetServerSubmitRequest::new(handle, limit, after);
        match request::<api::GetServerSubmitRequest, api::GetServerSubmitResponse>(api_url, req) {
            Ok(sc) => {
                for s in &sc.submits {
                    match pgp::verify(&cmgr, s.content.as_bytes(), transfer) {
                        Ok(d) => {
                            table.insert(d.player_uuid.clone(), i, d.points);
                        }
                        Err(e) => {
                            eprintln!("{}", e);
                        }
                    }
                }
            }
            Err(e) => {
                
            }
        }
    }

    let mut ofile = File::create(output).map_err(|e| AppError::InvalidParameter{ name: "output", value: output})?;   
    table.write_to(&mut ofile).map_err(|e| AppError::Unexpected(e.into()))?;

    Ok(())
}