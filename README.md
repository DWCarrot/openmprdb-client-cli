# openmprdb-client-cli
A simple cli-client example for [OpenMPRDB](https://github.com/NyaaCat/OpenMPRDB) using Rust

### Build

after installed [Rust develop environment with _cargo_ ](https://www.rust-lang.org/learn/get-started)

in windows 10:

```bash
cargo build --release --features cng
```

in linux

```bash
cargo build --release --features nettle
```

### Usage

USAGE:
    openmprdbc-cli [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    help          Prints this message or the help of the given subcommand(s)
    config        Config basic settings; use [option]=<value> to set value & [option]=? to check value
    cert          Management other server's public key registered in OpenMPRDB
    keyring       List keys info in the specific secret key file of the server (bind to this client)
    register      Register the server with the secret key to remote OpenMPRDB
    unregister    Unregister the server with the secret key from remote OpenMPRDB
    submit        Submit one record to remote OpenMPRDB
    recall        Recall the specific record from remote OpenMPRDB
    server        Get & show servers registered in remote OpenMPRDB
    record        Acquire and verify record of records in remote OpenMPRDB with other server's public key


#### subcommand: config

Config basic settings; use [option]=<value> to set value & [option]=? to check value

USAGE:
    openmprdbc-cli config [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --api-url <api_url>            set openmprdb api url
        --cert-file <cert_file>        set certification file of TPK and TSK data structures
        --key-id <key_id>              set specific key in the certification file to be used
        --server-uuid <server_uuid>    set server uuid registered; will be update automatically after a success register


#### subcommand: keyring

List keys info in the specific secret key file of the server (bind to this client)

USAGE:
    openmprdbc-cli keyring [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --cert-file <cert_file>    set certification file of TPK and TSK data structures; default means use value in config
        --key-id <key_id>          specific key in the certification file; default means use value in config


#### subcommand: cert

Management other server's public key registered in OpenMPRDB

USAGE:
    openmprdbc-cli cert <--add|--remove> --server-uuid <server_uuid> [OPTIONS] 

FLAGS:
        --add        to add other server's public key
    -h, --help       Prints help information
        --remove     to remove other server's public key
    -V, --version    Prints version information

OPTIONS:
        --key-id <key_id>              key-id of public key certification of the target server
        --name <name>                  name of the target server
        --server-uuid <server_uuid>    uuid of the target server registered in OpenMPRDB to add
        --trust <trust>                trust level


#### subcommand: register

Register the server with the secret key to remote OpenMPRDB

USAGE:
    openmprdbc-cli register [OPTIONS] --server-name <server_name>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --api-url <api_url>            openmprdb api url
        --cert-file <cert_file>        set certification file of TPK and TSK data structures
        --fingerprint <fingerprint>    specific fingerprint the certification file
        --key-id <key_id>              specific key in the certification file
    -s, --server-name <server_name>    name of server to register

#### subcommand unregister

Unregister the server with the secret key from remote OpenMPRDB

USAGE:
    openmprdbc-cli unregister [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --comment <comment>    


#### subcommand: submit

Submit one record to remote OpenMPRDB

USAGE:
    openmprdbc-cli submit [OPTIONS] --player-uuid <player_uuid> --points <points>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --comment <comment>
    -p, --player-uuid <player_uuid>
    -s, --points <points>
#### subcommand: recall

Recall the specific record from remote OpenMPRDB

USAGE:
    openmprdbc-cli.exe recall [OPTIONS] --record-uuid <record_uuid>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --comment <comment>
    -r, --record-uuid <record_uuid>    
#### subcommand: server

Get & show servers registered in remote OpenMPRDB

USAGE:
    openmprdbc-cli server [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --limit <limit>    

#### subcommand: record

Acquire and verify record of records in remote OpenMPRDB with other server's public key

USAGE:
    openmprdbc-cli record <--submit-uuid <submit_uuid>|--server-uuid <server_uuid>|--key-id <key_id>> [OPTIONS] 

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --after <after>                ask to show submits after a specific time, in YYYY-MM-dd HH:mm:ss
        --key-id <key_id>
        --limit <limit>
        --server-uuid <server_uuid>
        --submit-uuid <submit_uuid>