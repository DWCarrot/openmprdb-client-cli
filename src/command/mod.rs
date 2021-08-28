pub mod error;
pub mod http;
pub mod banlist;

use std::fmt;
use std::fs::File;
use std::io;
use std::time::Duration;
use std::time::SystemTime;
use std::time::SystemTimeError;
use std::thread;
use std::rc::Rc;
use std::borrow::Borrow as _;

use anyhow::Result as GeneralResult;
use uuid::Uuid;
use sequoia_openpgp::KeyID;
use sequoia_openpgp::Cert;
use sequoia_openpgp::policy::Policy;
use sequoia_openpgp::crypto::KeyPair;

use crate::pgp;
use crate::api_v1 as api;
use crate::config::client::ClientConfig;
use crate::config::servers::ServersConfig;
use crate::config::servers::ServerData;
use crate::config::records::RecordConfig;


fn timestamp(now: SystemTime) -> Result<u64, SystemTimeError> {
    now.duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs())
}


pub struct SigningKeyPairGenerator<'a> {
    password: &'a dyn pgp::PasswordProvider,
    policy: &'a dyn Policy,
    cache: Option<(KeyID, KeyPair)>,
}

impl<'a> SigningKeyPairGenerator<'a> {

    pub fn new(password: &'a dyn pgp::PasswordProvider, policy: &'a dyn Policy) -> Self {
        SigningKeyPairGenerator {
            password,
            policy,
            cache: None
        }
    }

    pub fn generate(&mut self, cert: &Cert, key_id: &KeyID, timestamp: Option<SystemTime>) -> GeneralResult<&KeyPair> {
        
        if let Some((cached_key_id, cached_keypair)) = &self.cache {
            if cached_key_id == key_id {
                
            } else {
                let keypair = pgp::get_signing_key(cert, self.policy, timestamp, key_id, self.password)?;
                self.cache = Some((key_id.clone(), keypair));
            }
        } else {
            let keypair = pgp::get_signing_key(cert, self.policy, timestamp, key_id, self.password)?;
            self.cache = Some((key_id.clone(), keypair));
        }
        
        Ok(&self.cache.as_ref().unwrap().1)
    }
}



pub fn command_register<'a>(
    cfg: &mut ClientConfig, 
    httpc: &http::Client,
    kpg: &mut SigningKeyPairGenerator,
    server_name: &'a str,
) -> error::AppResult<'a> {
    let cfg_data = cfg.get_data();
    
    let cert = error::ConfigMissing::ok(cfg_data.get_cert(), "client.cert_file")?;
    let key_id = error::ConfigMissing::ok(cfg_data.key_id.as_ref(), "client.key_id")?;
    let keypair = kpg.generate(cert, key_id, None)?;
    let api_url = error::ConfigMissing::ok(cfg_data.api_url.as_ref(), "client.api_url")?;

    let req = api::RegisterRequest::new(
        api::RegisterContent{ server_name: server_name.to_string() }, 
        cert, 
        &keypair
    );

    let s = httpc.request::<api::RegisterRequest, api::RegisterResponse>(api_url, req)?;
    
    println!("succeed\n+ server_uuid: {}", s.uuid);

    cfg.get_data_mut().server_uuid = Some(s.uuid);

    Ok(())
}


pub fn command_unregister<'a>(
    cfg: &mut ClientConfig,
    httpc: &http::Client,
    kpg: &mut SigningKeyPairGenerator,
    comment: &'a str,
) -> error::AppResult<'a> {
    
    let comment = comment.to_owned();

    let cfg_data = cfg.get_data();
    let server_uuid = error::ConfigMissing::ok(cfg_data.server_uuid.as_ref(), "client.server_uuid")?.clone();
    let cert = error::ConfigMissing::ok(cfg_data.get_cert(), "client.cert_file")?;
    let key_id = error::ConfigMissing::ok(cfg_data.key_id.as_ref(), "client.key_id")?;
    let keypair = kpg.generate(cert, key_id, None)?;
    let api_url = error::ConfigMissing::ok(cfg_data.api_url.as_ref(), "client.api_url")?;

    let req = api::UnregisterRequest::new(
        api::UnregisterContent{ 
            timestamp: timestamp(SystemTime::now()).unwrap(),
            comment,
        },
        &keypair,
        server_uuid
    );

    let s = httpc.request::<api::UnregisterRequest, api::UnregisterResponse>(api_url, req)?;
    
    println!("succeed\n- server_uuid: {}", s.uuid);
    
    cfg.get_data_mut().server_uuid = None;
       
    Ok(())
}


pub fn command_submit<'a>(
    cfg: &mut ClientConfig,
    records: &mut RecordConfig,
    httpc: &http::Client,
    kpg: &mut SigningKeyPairGenerator,
    player_uuid: &'a str, 
    points: &'a str, 
    comment: &'a str,
    force: bool,
) -> error::AppResult<'a> {
    let player_uuid = error::ArgsError::parse(player_uuid, "player_uuid", "uuid")?;
    if let Some(record_uuid) = records.check_player_uuid(&player_uuid) {
        if force {

        } else {
            return Err(error::AppError::Other(anyhow::anyhow!("submit existed: {}", record_uuid)))
        }
    }
    let points = error::ArgsError::parse(points, "points", "float$[-1,1]")?;
    let comment = comment.to_owned();
    
    let cfg_data = cfg.get_data();
    let server_uuid = error::ConfigMissing::ok(cfg_data.server_uuid.as_ref(), "client.server_uuid")?.clone();
    let cert = error::ConfigMissing::ok(cfg_data.get_cert(), "client.cert_file")?;
    let key_id = error::ConfigMissing::ok(cfg_data.key_id.as_ref(), "client.key_id")?;
    let keypair = kpg.generate(cert, key_id, None)?;
    let api_url = error::ConfigMissing::ok(cfg_data.api_url.as_ref(), "client.api_url")?;

    let timestamp = timestamp(SystemTime::now()).unwrap();
    let req = api::SubmitRequest::new(
        api::SubmitContent{ 
            uuid: server_uuid,
            timestamp,
            player_uuid,
            points,
            comment,
        },
        &keypair
    );

    let s = httpc.request::<api::SubmitRequest, api::SubmitResponse>(api_url, req)?;
    println!("succeed\n+ record_uuid: {}", s.uuid);

    records.new_submit(s.uuid, timestamp, player_uuid);

    Ok(())
}


pub fn command_recall<'a>(
    cfg: &mut ClientConfig,
    records: &mut RecordConfig,
    httpc: &http::Client,
    kpg: &mut SigningKeyPairGenerator,
    record_uuid: &'a str, 
    comment: &'a str,
    force: bool,
) -> error::AppResult<'a> {
    let record_uuid = error::ArgsError::parse(record_uuid, "record_uuid", "uuid")?;
    if let Some(player_uuid) = records.check_record_uuid(&record_uuid) {
        
    } else {
        if force {

        } else {
            return Err(error::AppError::Other(anyhow::anyhow!("submit not existed: {}", &record_uuid)))
        }
    }
    let comment = comment.to_owned();
    
    let cfg_data = cfg.get_data();
    let server_uuid = error::ConfigMissing::ok(cfg_data.server_uuid.as_ref(), "client.server_uuid")?.clone();
    let cert = error::ConfigMissing::ok(cfg_data.get_cert(), "client.cert_file")?;
    let key_id = error::ConfigMissing::ok(cfg_data.key_id.as_ref(), "client.key_id")?;
    let keypair = kpg.generate(cert, key_id, None)?;
    let api_url = error::ConfigMissing::ok(cfg_data.api_url.as_ref(), "client.api_url")?;

    let timestamp = timestamp(SystemTime::now()).unwrap();    
    let req = api::RecallRequest::new(
        record_uuid,
        api::RecallContent{
            timestamp,
            comment,
        },
        &keypair
    );

    let s = httpc.request::<api::RecallRequest, api::RecallResponse>(api_url, req)?;
    println!("succeed\n- record_uuid: {} ", &s.uuid);
    
    records.new_recall(s.uuid, timestamp);

    Ok(())
}


pub fn command_cert_add<'a>(
    cfg: &mut ServersConfig, 
    server_uuid: &'a str, 
    name: &'a str, 
    key_id: &'a str, 
    trust: &'a str
) -> error::AppResult<'a> {

    let server_uuid: Uuid = error::ArgsError::parse(server_uuid, "server_uuid", "uuid")?;
    let key_id: KeyID = error::ArgsError::parse(key_id, "key_id", "hex")?;
    let name = name.to_owned();
    let trust: u32 = error::ArgsError::parse(trust, "trust", "integer$(1,2,3,4,5)")?;

    let success = cfg.add(server_uuid, ServerData::new(name, key_id, trust), |_, _| {
        println!("==== please input pgp text, end with ctrl-Z ===");
        pgp::read_cert_from_console().map(Rc::new)
    })?;

    if success {
        println!("success.")
    } else {
        println!("existed.")
    }

    Ok(())
}


pub fn command_cert_remove<'a>(
    cfg: &mut ServersConfig, 
    server_uuid: &'a str, 
) -> error::AppResult<'a> {
    
    let server_uuid: Uuid = error::ArgsError::parse(server_uuid, "server_uuid", "uuid")?;

    let success = cfg.remove(&server_uuid);

    if success {
        println!("success.")
    } else {
        println!("not existed.")
    }

    Ok(())
}


pub fn command_server_list<'a>(
    cfg: &ClientConfig,
    httpc: &http::Client,
    limit: Option<&'a str>
) -> error::AppResult<'a> {
      
    let limit = if let Some(s) = limit {
        Some(error::ArgsError::parse(s, "limit", "unsigned integer")?)
    } else {
        None
    };

    let cfg_data = cfg.get_data();
    let api_url = error::ConfigMissing::ok(cfg_data.api_url.as_ref(), "client.api_url" )?;

    let req = api::ServerListRequest::new(limit);
    let s = httpc.request::<api::ServerListRequest, api::ServerListResponse>(api_url, req)?;
    
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

fn transfer(r: &mut dyn io::Read) -> anyhow::Result<api::SubmitContent> {
    api::ReadFrom::read_from(r)
}

pub fn command_get_submit<'a> (
    cfg: &ClientConfig,
    servers: &ServersConfig,
    httpc: &http::Client,
    record_uuid: &'a str
) -> error::AppResult<'a> {

    let record_uuid: Uuid = error::ArgsError::parse(record_uuid, "record_uuid", "uuid")?;
    
    let cfg_data = cfg.get_data();
    let api_url = error::ConfigMissing::ok(cfg_data.api_url.as_ref(), "client.api_url")?;

    let req = api::GetSubmitRequest::new(record_uuid);
    let s = httpc.request::<api::GetSubmitRequest, api::GetSubmitResponse>(api_url, req)?;

    let v = if let Some((cert, key_id)) = servers.get_ref(&s.server_uuid) {
        pgp::verify(cert, key_id, servers.policy(), None, s.content.as_bytes(), transfer)
    } else {
        Err(anyhow::anyhow!("can not find cert for server:{}", &s.server_uuid))
    };

    match v {
        Ok(d) => {
            println!("+ Verified Message");
            println!("{}", ServerDataDisplay(servers.get_data().get(&s.server_uuid).unwrap(), &s.server_uuid));
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

struct ServerDataDisplay<'a>(&'a ServerData, &'a Uuid);

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

pub fn command_get_server_submit<'a>(
    cfg: &ClientConfig,
    servers: &ServersConfig,
    httpc: &http::Client,
    server_handle: ServerHandleWrap<'a>,
    limit: Option<&'a str>,
    after: Option<&'a str>
) -> error::AppResult<'a> {
    use chrono::NaiveDateTime;

    let (uuid, cert, key_id, handle) = match server_handle {
        ServerHandleWrap::UUID(s) => {
            let server_uuid: Uuid = error::ArgsError::parse(s, "server_uuid", "uuid")?;
            let (cert, key_id) = servers.get_ref(&server_uuid)
                    .ok_or_else(|| anyhow::anyhow!("can not find cert for server:{}", &server_uuid))?;
            (server_uuid, cert, key_id.clone(), api::ServerHandle::ServerUUID(server_uuid))
        },
        ServerHandleWrap::KeyID(s) => {
            let key_id: KeyID = error::ArgsError::parse(s, "key_id", "hex")?;
            let mut tuple = None;
            for (server_uuid, d) in servers.get_data().iter() {
                if d.key_id == key_id {
                    tuple = Some((server_uuid.clone(), d.get_cert(), key_id.clone(), api::ServerHandle::KeyID(key_id.clone())));
                    break;
                }
            }
            tuple
                .ok_or_else(|| anyhow::anyhow!("can not find cert for key_id:{}", &key_id))?
        },
    };
    let limit = if let Some(s) = limit {
        Some(error::ArgsError::parse(s, "limit", "unsigned integer")?)
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
                return Err(
                    error::ArgsError::new("after", "time{YYYY-mm-dd HH:MM:SS}", s).into()
                );
            }
        }           
    } else {
        None
    };

    let cfg_data = cfg.get_data();
    let api_url = error::ConfigMissing::ok(cfg_data.api_url.as_ref(), "client.api_url")?;

    let req = api::GetServerSubmitRequest::new(handle, limit, after);
    let sc = httpc.request::<api::GetServerSubmitRequest, api::GetServerSubmitResponse>(api_url, req)?;

    fn transfer(r: &mut dyn io::Read) -> GeneralResult<api::SubmitContent> {
        api::ReadFrom::read_from(r)
    }

    let submits: Vec<_> = 
        sc.submits
            .iter()
            .filter_map(
                |s| {
                    match pgp::verify(cert, &key_id, servers.policy(), None, s.content.as_bytes(), transfer) {
                        Ok(d) => Some(d),
                        Err(e) => {
                            println!("Un-Verified Message");
                            println!("{}\n", &s.content);
                            None
                        }
                    }
                }
            )
            .collect();

    println!("+ Verified Message");
    println!("{}\n", ServerDataDisplay(servers.get_data().get(&uuid).unwrap(), &uuid));
    for d in submits {
        println!("{:#?}", &d);
    }

    Ok(())
}


fn sleep_interval(interval: Duration, last: SystemTime) {
    let now = SystemTime::now();
    if let Ok(d) = now.duration_since(last) {
        if interval > d {
            let rest = interval - d;
            thread::sleep(rest)
        }
    }
}


pub fn command_import<'a>(
    cfg: &mut ClientConfig,
    records: &mut RecordConfig,
    httpc: &http::Client,
    kpg: &mut SigningKeyPairGenerator,
    banlist: &'a str,
    interval: Option<&'a str>,
    rules: &dyn banlist::GeneratePoints
) -> error::AppResult<'a> {
    
    let reader = File::open(banlist).map_err(error::AppError::new_other)?;
    let banlist: banlist::BanList = serde_json::from_reader(reader).map_err(error::AppError::new_other)?;
    let interval = match interval {
        Some(s) => Duration::from_millis(error::ArgsError::parse(s, "interval", "integer of milliseconds")?),
        None => Duration::ZERO
    };

    let cfg_data = cfg.get_data();
    let server_uuid = error::ConfigMissing::ok(cfg_data.server_uuid.as_ref(), "client.server_uuid")?.clone();
    let cert = error::ConfigMissing::ok(cfg_data.get_cert(), "client.cert_file")?;
    let key_id = error::ConfigMissing::ok(cfg_data.key_id.as_ref(), "client.key_id")?;
    let keypair = kpg.generate(cert, key_id, None)?;
    let api_url = error::ConfigMissing::ok(cfg_data.api_url.as_ref(), "client.api_url")?;

    let mut last = SystemTime::UNIX_EPOCH;

    for item in banlist.as_slice() {
        if let Some(record_uuid) = records.check_player_uuid(&item.uuid) {

            println!("player #{} existed: {}", &item.uuid, record_uuid);
            
        } else {

            sleep_interval(interval, last);

            let timestamp = item.created.timestamp() as u64;
            let player_uuid = item.uuid.clone();
            let points = rules.generate(item);
            let comment = item.reason.clone();

            let req = api::SubmitRequest::new(
                api::SubmitContent{ 
                    uuid: server_uuid.clone(),
                    timestamp,
                    player_uuid,
                    points,
                    comment,
                },
                &keypair
            );

            last = SystemTime::now();
        
            let s = httpc.request::<api::SubmitRequest, api::SubmitResponse>(api_url, req)?;

            println!("succeed\n+ record_uuid: {}", s.uuid);

            records.new_submit(s.uuid, timestamp, player_uuid);
        }
    }

    Ok(())
}