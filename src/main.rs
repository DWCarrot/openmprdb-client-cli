mod pgp;
mod api_v1;
mod config;
mod command;

use std::fmt;
use std::path::Path;

use clap::App;
use clap::SubCommand;
use clap::Arg;
use clap::ArgGroup;
use uuid::Uuid;
use sequoia_openpgp::KeyID;
use sequoia_openpgp::Fingerprint;

use config::client::ClientConfig;
use config::servers::ServersConfig;
use config::records::RecordConfig;

fn main() {

    let app = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .subcommand(
            SubCommand::with_name("config")
                .about("Config basic settings; use [option]=<value> to set value & [option]=? to check value")
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
        // .subcommand(
        //     SubCommand::with_name("keyring")
        //         .about("List keys info in the specific secret key file of the server (bind to this client)")
        //         .arg(
        //             Arg::with_name("cert_file")
        //                 .long("cert-file")
        //                 .takes_value(true)
        //                 .help("set certification file of TPK and TSK data structures")
        //         )
        //         .arg(
        //             Arg::with_name("key_id")
        //                 .long("key-id")
        //                 .takes_value(true)
        //                 .help("specific key in the certification file")
        //         )
        // )
        .subcommand(
            SubCommand::with_name("register")
                .about("Register the server with the secret key to remote OpenMPRDB ")
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
                // .arg(
                //     Arg::with_name("fingerprint")
                //         .long("fingerprint")
                //         .takes_value(true)
                //         .help("specific fingerprint the certification file")
                // )
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
                .about("Unregister the server with the secret key from remote OpenMPRDB")
                .arg(
                    Arg::with_name("comment")
                        .long("comment")
                        .takes_value(true)
                )
        )
        .subcommand(
            SubCommand::with_name("submit")
                .about("Submit one record to remote OpenMPRDB")
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
                .arg(
                    Arg::with_name("force")
                        .long("force")
                )
        )
        .subcommand(
            SubCommand::with_name("recall")
                .about("Recall the specific record from remote OpenMPRDB")
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
                .arg(
                    Arg::with_name("force")
                        .long("force")
                )
        )
        .subcommand(
            SubCommand::with_name("cert")
                .about("Management other server's public key registered in OpenMPRDB")
                .arg(
                    Arg::with_name("add")
                        .long("add")
                        .takes_value(false)
                        .help("to add other server's public key, input from console")
                )
                .arg(
                    Arg::with_name("remove")
                        .long("remove")
                        .takes_value(false)
                        .help("to remove other server's public key")
                )
                .group(
                    ArgGroup::with_name("add-remove")
                        .args(&["add", "remove"])
                        .required(true)
                )
                .arg(
                    Arg::with_name("server_uuid")
                        .long("server-uuid")
                        .takes_value(true)
                        .help("uuid of the target server registered in OpenMPRDB to add")
                        .required(true)
                )
                .arg(
                    Arg::with_name("name")
                        .long("name")
                        .takes_value(true)
                        .help("name of the target server")
                        .requires("add")
                )
                .arg(
                    Arg::with_name("key_id")
                        .long("key-id")
                        .takes_value(true)
                        .help("key-id of public key certification of the target server")
                        .requires("add")
                )
                .arg(
                    Arg::with_name("trust")
                        .long("trust")
                        .takes_value(true)
                        .help("trust level")
                        .requires("add")
                )
        )
        .subcommand(
            SubCommand::with_name("server")
                .about("Get & show servers registered in remote OpenMPRDB")
                .arg(
                    Arg::with_name("limit")
                        .long("limit")
                        .takes_value(true)
                )
        )
        .subcommand(
            SubCommand::with_name("record")
                .about("Acquire and verify record of records in remote OpenMPRDB with other server's public key")
                .arg(
                    Arg::with_name("submit_uuid")
                        .long("submit-uuid")
                        .takes_value(true)
                )
                .arg(
                    Arg::with_name("server_uuid")
                        .long("server-uuid")
                        .takes_value(true)
                )
                .arg(
                    Arg::with_name("key_id")
                        .long("key-id")
                        .takes_value(true)
                )
                // .arg(
                //     Arg::with_name("auto")
                //         .long("auto")
                //         .help("get record according to the servers in cert-config and merge them into a table")
                // )
                .group(
                    ArgGroup::with_name("according")
                        .args(&["submit_uuid", "server_uuid", "key_id", /* "auto" */])
                        .required(true)
                )
                .arg(
                    Arg::with_name("limit")
                        .long("limit")
                        .takes_value(true) 
                )
                .arg(
                    Arg::with_name("after")
                        .long("after")
                        .takes_value(true)
                        .help("ask to show submits after a specific time, in YYYY-MM-dd HH:mm:ss")
                )
                // .arg(
                //     Arg::with_name("output")
                //         .long("output")
                //         .short("o")
                //         .takes_value(true)
                //         .requires("auto")
                //         .help("output file")
                // )
        )
        .subcommand(
            SubCommand::with_name("import")
                .about("Submit mutiple records import from banlist (banned-players.json)")
                .arg(
                    Arg::with_name("banlist")
                        .takes_value(true)
                        .required(true)
                        .help("banlist file (banned-players.json)") 
                )
                .arg(
                    Arg::with_name("interval")
                        .long("interval")
                        .takes_value(true)
                        .help("requset interval in milliseconds")
                )
        );
    


    let matches = app.get_matches();
    
    let password = pgp::TTYPasswordProvider;

    match matches.subcommand() {
        ("config", Some(sub_matches)) => {

            let policy = config::build_policy();
            let mut cfg = ClientConfig::new(
                config::current_exe_path("config").unwrap(), 
                policy.as_ref(),
            )
            .unwrap();
            
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
        // ("keyring", Some(sub_matches)) => {

            // let policy = config::build_policy();
            // let mut cfg = ClientConfig::new(
            //     config::current_exe_path("config").unwrap(), 
            //     policy.as_ref(),
            //     &pgp::TTYPasswordProvider
            // )
            // .unwrap();

            // if let Some(s) = sub_matches.value_of("cert_file") {
            //     cfg.set_cert_file(s);
            //     cfg.get_data_mut().key_id = None;
            //     println!("update config: cert_file = {}", OptionalPathDisplay(&cfg.get_data().cert_file))
            // }
            // if let Some(s) = sub_matches.value_of("key_id") {
            //     cfg.set_key_id(s);
            //     println!("update config: key_id = {}", OptionalKeyIDDisplay(&cfg.get_data().key_id))
            // }
            
            // // TODO
        // },
        ("register", Some(sub_matches)) => {

            let policy = config::build_policy();
            let mut cfg = ClientConfig::new(
                config::current_exe_path("config").unwrap(), 
                policy.as_ref(),
            )
            .unwrap();
            let httpc = command::http::Client::new().unwrap();

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
            command::command_register(
                &mut cfg, 
                &httpc,
                &password,
                sub_matches.value_of("server_name").unwrap(),
            )
            .unwrap_or_else(handle_err);
        },
        ("unregister", Some(sub_matches)) => {

            let policy = config::build_policy();
            let mut cfg = ClientConfig::new(
                config::current_exe_path("config").unwrap(), 
                policy.as_ref(),
            )
            .unwrap();
            let httpc = command::http::Client::new().unwrap();

            command::command_unregister(
                &mut cfg,
                &httpc,
                &password,
                sub_matches.value_of("comment").unwrap_or_default()
            )
            .unwrap_or_else(handle_err);
        },
        ("submit", Some(sub_matches)) => {

            let policy = config::build_policy();
            let mut cfg = ClientConfig::new(
                config::current_exe_path("config").unwrap(), 
                policy.as_ref(),
            )
            .unwrap();
            let mut records = RecordConfig::new(
                config::current_exe_path(format!("record-{}", cfg.get_data().server_uuid.unwrap())).unwrap()
            )
            .unwrap();
            let httpc = command::http::Client::new().unwrap();


            command::command_submit(
                &mut cfg,
                &mut records,
                &httpc,
                &password,
                sub_matches.value_of("player_uuid").unwrap(),
                sub_matches.value_of("points").unwrap(),
                sub_matches.value_of("comment").unwrap_or_default(),
                sub_matches.is_present("force")
            )
            .unwrap_or_else(handle_err);
        },
        ("recall", Some(sub_matches)) => {

            let policy = config::build_policy();
            let mut cfg = ClientConfig::new(
                config::current_exe_path("config").unwrap(), 
                policy.as_ref(),
            )
            .unwrap();
            let mut records = RecordConfig::new(
                config::current_exe_path(format!("record-{}", cfg.get_data().server_uuid.unwrap())).unwrap()
            )
            .unwrap();
            let httpc = command::http::Client::new().unwrap();

            command::command_recall(
                &mut cfg,
                &mut records,
                &httpc,
                &password,
                sub_matches.value_of("record_uuid").unwrap(),
                sub_matches.value_of("comment").unwrap_or_default(),
                sub_matches.is_present("force")
            )
            .unwrap_or_else(handle_err);
        }
        ("cert", Some(sub_matches)) => {

            let policy = config::build_policy();
            let mut servers = ServersConfig::new(
                config::current_exe_path("servers").unwrap(), 
                config::current_exe_path("serverscert.pgp").unwrap(),
                policy.as_ref()
            )
            .unwrap();

            if sub_matches.is_present("add") {
                command::command_cert_add(
                    &mut servers,
                    sub_matches.value_of("server_uuid").unwrap(),
                    sub_matches.value_of("name").unwrap(),
                    sub_matches.value_of("key_id").unwrap(),
                    sub_matches.value_of("trust").unwrap(),
                )
                .unwrap_or_else(handle_err);
            } else if sub_matches.is_present("remove") {
                command::command_cert_remove(
                    &mut servers,
                    sub_matches.value_of("server_uuid").unwrap(),
                )
                .unwrap_or_else(handle_err);
            }
        }
        ("server", Some(sub_matches)) => {

            let policy = config::build_policy();
            let mut cfg = ClientConfig::new(
                config::current_exe_path("config").unwrap(), 
                policy.as_ref(),
            )
            .unwrap();
            let httpc = command::http::Client::new().unwrap();

            if sub_matches.is_present("#") {

            } else {
                command::command_server_list(
                    &cfg,
                    &httpc,
                    sub_matches.value_of("limit")
                )
                .unwrap_or_else(handle_err);
            }
        }
        ("record", Some(sub_matches)) => {

            let policy = config::build_policy();
            let mut cfg = ClientConfig::new(
                config::current_exe_path("config").unwrap(), 
                policy.as_ref(),
            )
            .unwrap();
            let mut servers = ServersConfig::new(
                config::current_exe_path("servers").unwrap(), 
                config::current_exe_path("serverscert.pgp").unwrap(),
                policy.as_ref()
            )
            .unwrap();
            let httpc = command::http::Client::new().unwrap();

            loop {
                if let Some(s) = sub_matches.value_of("submit_uuid") {
                    command::command_get_submit(
                        &cfg,
                        &servers,
                        &httpc,
                        s
                    )
                    .unwrap_or_else(handle_err);
                    break;
                }
                if let Some(s) = sub_matches.value_of("server_uuid") {
                    command::command_get_server_submit(
                        &cfg,
                        &servers,
                        &httpc,
                        command::ServerHandleWrap::UUID(s),
                        sub_matches.value_of("limit"),
                        sub_matches.value_of("after"),
                    )
                    .unwrap_or_else(handle_err);
                    break;
                }
                if let Some(s) = sub_matches.value_of("key_id") {
                    command::command_get_server_submit(
                        &cfg,
                        &servers,
                        &httpc,
                        command::ServerHandleWrap::KeyID(s),
                        sub_matches.value_of("limit"),
                        sub_matches.value_of("after"),
                    )
                    .unwrap_or_else(handle_err);
                    break;
                }
                // if sub_matches.is_present("auto") {
                //     app::command_get_server_submit_auto(
                //         &cfg,
                //         sub_matches.value_of("limit"),
                //         sub_matches.value_of("after"),
                //         sub_matches.value_of("output").unwrap()
                //     )
                //     .unwrap();
                //     break;
                // }
                // break;
            }
        },
        ("import", Some(sub_matches)) => {

            let policy = config::build_policy();
            let mut cfg = ClientConfig::new(
                config::current_exe_path("config").unwrap(), 
                policy.as_ref(),
            )
            .unwrap();
            let mut records = RecordConfig::new(
                config::current_exe_path(format!("record-{}", cfg.get_data().server_uuid.unwrap())).unwrap()
            )
            .unwrap();
            let httpc = command::http::Client::new().unwrap();

            let rules = command::banlist::BasicGeneratePoints;

            command::command_import(
                &mut cfg, 
                &mut records, 
                &httpc, 
                &password, 
                sub_matches.value_of("banlist").unwrap(),
                sub_matches.value_of("interval"),
                &rules
            )
            .unwrap_or_else(handle_err);
        },
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


fn handle_err(e: command::error::AppError) {
    match e {
        command::error::AppError::Args(a) => {
            eprintln!("{}", a);
        }
        command::error::AppError::Config(c) => {
            eprintln!("{}", c);
        }
        command::error::AppError::Response(r) => {
            eprintln!("{}", r);
        }
        command::error::AppError::Other(m) => {
            eprintln!("{}", m);
        }
    }
}