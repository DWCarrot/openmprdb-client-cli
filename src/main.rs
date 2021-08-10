mod pgp;
mod api;
mod app;
mod http;
mod config;

use std::fmt;
use std::path::Path;

use clap::App;
use clap::SubCommand;
use clap::Arg;
use uuid::Uuid;
use sequoia_openpgp::KeyID;
use sequoia_openpgp::Fingerprint;

fn main() {

    let app = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .subcommand(
            SubCommand::with_name("config")
                .help("config basic info; use [option]=<value> to set value & [option]=? to check value")
                .arg(
                    Arg::with_name("cert_file")
                        .long("cert-file")
                        .takes_value(true)
                        .help("set certification file of TPK and TSK data structures")
                )
                .arg(
                    Arg::with_name("key_id")
                        .long("key-id")
                        .takes_value(true)
                        .help("set specific key in the certification file to be used")
                )
                .arg(
                    Arg::with_name("server_uuid")
                        .long("server-uuid")
                        .takes_value(true)
                        .help("set server uuid registered; will be update automatically after a success register")   
                )
                .arg(
                    Arg::with_name("api_url")
                        .long("api-url")
                        .takes_value(true)
                        .help("set openmprdb api url")   
                )
        )
        .subcommand(
            SubCommand::with_name("keyring")
                .help("list keys in the specific certification file")
                .arg(
                    Arg::with_name("cert_file")
                        .long("cert-file")
                        .takes_value(true)
                        .help("set certification file of TPK and TSK data structures")
                )
                .arg(
                    Arg::with_name("key_id")
                        .long("key-id")
                        .takes_value(true)
                        .help("specific key in the certification file")
                )
        )
        .subcommand(
            SubCommand::with_name("register")
                .help("register server in OpenMPRDB with specific certification file")
                .arg(
                    Arg::with_name("cert_file")
                        .long("cert-file")
                        .takes_value(true)
                        .requires("key_id")
                        .help("set certification file of TPK and TSK data structures")
                )
                .arg(
                    Arg::with_name("key_id")
                        .long("key-id")
                        .takes_value(true)
                        .help("specific key in the certification file")
                )
                .arg(
                    Arg::with_name("fingerprint")
                        .long("fingerprint")
                        .takes_value(true)
                        .help("specific fingerprint the certification file")
                )
                .arg(
                    Arg::with_name("api_url")
                        .long("api-url")
                        .takes_value(true)
                        .help("openmprdb api url")
                )
                .arg(
                    Arg::with_name("server_name")
                        .long("server-name")
                        .short("s")
                        .takes_value(true)
                        .help("name of server to register")
                        .required(true)
                )
        )
        .subcommand(
            SubCommand::with_name("unregister")
                .help("unregister the server")
                .arg(
                    Arg::with_name("comment")
                        .long("comment")
                        .takes_value(true)
                )
        )
        .subcommand(
            SubCommand::with_name("submit")
                .help("submit a new record")
                .arg(
                    Arg::with_name("player_uuid")
                        .long("player-uuid")
                        .short("p")
                        .takes_value(true)
                        .required(true)
                )
                .arg(
                    Arg::with_name("points")
                        .long("points")
                        .short("s")
                        .takes_value(true)
                        .required(true)
                )
                .arg(
                    Arg::with_name("comment")
                        .long("comment")
                        .takes_value(true)
                )
        )
        .subcommand(
            SubCommand::with_name("recall")
                .help("recall the submitted record")
                .arg(
                    Arg::with_name("record_uuid")
                        .long("record-uuid")
                        .short("r")
                        .takes_value(true)
                        .required(true)   
                )
                .arg(
                    Arg::with_name("comment")
                        .long("comment")
                        .takes_value(true)
                )
        )
        .subcommand(
            SubCommand::with_name("cert")
                .help("add or remove public key certification of server registered in OpenMPRDB")
                .subcommand(
                    SubCommand::with_name("add")
                        .arg(
                            Arg::with_name("server_uuid")
                                .long("server-uuid")
                                .takes_value(true)
                                .required(true)
                                .help("uuid of the target server registered in OpenMPRDB to add")
                        )
                        .arg(
                            Arg::with_name("name")
                                .long("name")
                                .takes_value(true)
                                .required(true)
                                .help("name of the target server")
                        )
                        .arg(
                            Arg::with_name("key_id")
                                .long("key-id")
                                .takes_value(true)
                                .required(true)
                                .help("key-id of public key certification of the target server")
                        )
                        .arg(
                            Arg::with_name("trust")
                                .long("trust")
                                .takes_value(true)
                                .required(true)
                                .help("trust level")
                        ) 
                )
                .subcommand(
                    SubCommand::with_name("remove")
                        .arg(
                            Arg::with_name("server_uuid")
                                .long("server-uuid")
                                .takes_value(true)
                                .required(true)
                                .help("uuid of the target server registered in OpenMPRDB to remove")
                        )
                )
        );
    


    let matches = app.get_matches();

    match matches.subcommand() {
        ("config", Some(sub_matches)) => {
            let mut cfg = config::Config::new().unwrap();
            if let Some(s) = sub_matches.value_of("cert_file") {
                if s != "?" {
                    cfg.set_cert_file(s);
                }
                println!("cert_file = {}", OptionalPathDisplay(&cfg.get_data().cert_file))
            }
            if let Some(s) = sub_matches.value_of("key_id") {
                if s != "?" {
                    cfg.set_key_id(s);
                }
                println!("key_id = {}", OptionalKeyIDDisplay(&cfg.get_data().key_id))
            }
            if let Some(s) = sub_matches.value_of("fingerprint") {
                if s != "?" {
                    cfg.set_fingerprint(s);
                }
                println!("key_id = {}", OptionalFingerprintDisplay(&cfg.get_data().fingerprint))
            }
            if let Some(s) = sub_matches.value_of("api_url") {
                if s != "?" {
                    cfg.set_api_url(s);
                }
                println!("api_url = {}", OptionalStrDisplay(&cfg.get_data().api_url))
            }
            if let Some(s) = sub_matches.value_of("server_uuid") {
                if s != "?" {
                    cfg.set_server_uuid(s);
                }
                println!("server_uuid = {}", OptionalUUIDDisplay(&cfg.get_data().server_uuid))
            }
        },
        ("keyring", Some(sub_matches)) => {
            let mut cfg = config::Config::new().unwrap();
            if let Some(s) = sub_matches.value_of("cert_file") {
                cfg.set_cert_file(s);
                cfg.get_data_mut().key_id = None;
                println!("update config: cert_file = {}", OptionalPathDisplay(&cfg.get_data().cert_file))
            }
            if let Some(s) = sub_matches.value_of("key_id") {
                cfg.set_key_id(s);
                println!("update config: key_id = {}", OptionalKeyIDDisplay(&cfg.get_data().key_id))
            }
            app::command_keyring(&mut cfg).unwrap();
        },
        ("register", Some(sub_matches)) => {
            let mut cfg = config::Config::new().unwrap();
            if let Some(s) = sub_matches.value_of("cert_file") {
                cfg.set_cert_file(s);
                cfg.get_data_mut().key_id = None;
                println!("update config: cert_file = {}", OptionalPathDisplay(&cfg.get_data().cert_file))
            }
            if let Some(s) = sub_matches.value_of("key_id") {
                cfg.set_key_id(s);
                println!("update config: key_id = {}", OptionalKeyIDDisplay(&cfg.get_data().key_id))
            }
            if let Some(s) = sub_matches.value_of("api_url") {
                cfg.set_api_url(s);
                println!("update config: api_url = {}", OptionalStrDisplay(&cfg.get_data().api_url))
            }
            app::command_register(
                &mut cfg, 
                sub_matches.value_of("server_name").unwrap(),
            )
            .unwrap()
        },
        ("unregister", Some(sub_matches)) => {
            let mut cfg = config::Config::new().unwrap();
            app::command_unregister(
                &mut cfg, 
                sub_matches.value_of("comment").unwrap_or_default()
            )
            .unwrap();
        },
        ("submit", Some(sub_matches)) => {
            let mut cfg = config::Config::new().unwrap();
            app::command_submit(
                &mut cfg, 
                sub_matches.value_of("player_uuid").unwrap(),
                sub_matches.value_of("points").unwrap(),
                sub_matches.value_of("comment").unwrap_or_default()
            )
            .unwrap();
        },
        ("recall", Some(sub_matches)) => {
            let mut cfg = config::Config::new().unwrap();
            app::command_recall(
                &mut cfg, 
                sub_matches.value_of("record_uuid").unwrap(),
                sub_matches.value_of("comment").unwrap_or_default()
            )
            .unwrap();
        }
        ("cert", Some(sub_matches)) => {
            let mut cfg = config::Config::new().unwrap();
            match sub_matches.subcommand() {
                ("add", Some(sub_matches2)) => {
                    app::command_certs_add(
                        &mut cfg,
                        sub_matches2.value_of("server_uuid").unwrap(),
                        sub_matches2.value_of("name").unwrap(),
                        sub_matches2.value_of("key_id").unwrap(),
                        sub_matches2.value_of("trust").unwrap(),
                    )
                    .unwrap()
                }
                ("remove", Some(sub_matches2)) => {
                    app::command_certs_remove(
                        &mut cfg,
                        sub_matches2.value_of("server_uuid").unwrap(),
                    )
                    .unwrap()
                }
                _ => {

                }
            }
        }
        _ => {
            
        },
    }
}


struct OptionalKeyIDDisplay<'a>(&'a Option<KeyID>);

impl<'a> fmt::Display for OptionalKeyIDDisplay<'a> {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(key_id) = self.0 {
            f.write_str(key_id.to_hex().as_str())?;
        }
        Ok(())
    }
}


struct OptionalFingerprintDisplay<'a>(&'a Option<Fingerprint>);

impl<'a> fmt::Display for OptionalFingerprintDisplay<'a> {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(fingerprint) = self.0 {
            f.write_str(fingerprint.to_hex().as_str())?;
        }
        Ok(())
    }
}


struct OptionalPathDisplay<'a, P: AsRef<Path>>(&'a Option<P>);

impl<'a, P: AsRef<Path>> fmt::Display for OptionalPathDisplay<'a, P> {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use std::borrow::Borrow;

        if let Some(path) = self.0 {
            f.write_str(path.as_ref().to_string_lossy().borrow())?;
        }
        Ok(())
    }
}


struct OptionalUUIDDisplay<'a>(&'a Option<Uuid>);

impl<'a> fmt::Display for OptionalUUIDDisplay<'a> {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(uuid) = self.0 {
            uuid.to_hyphenated_ref().fmt(f)?;
        }
        Ok(())
    }
}


struct OptionalStrDisplay<'a, S: AsRef<str>>(&'a Option<S>);

impl<'a, S: AsRef<str>> fmt::Display for OptionalStrDisplay<'a, S> {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(url) = self.0 {
            f.write_str(url.as_ref())?;
        }
        Ok(())
    }
}