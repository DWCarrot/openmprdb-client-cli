use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt;
use std::str;
use std::str::FromStr;
use std::io;
use std::io::Write as _;
use std::io::BufRead as _;
use std::path::PathBuf;
use std::fs::File;
use std::fs::OpenOptions;

use uuid::Uuid;

struct SubmitRecord {
    record_uuid: Uuid,
    timestamp: u64,
    player_uuid: Uuid
}

struct RecallRecord {
    record_uuid: Uuid,
    timestamp: u64,
}

enum Record {
    Submit(SubmitRecord),
    Recall(RecallRecord)
}

/**
 * format
 * + <record_uuid>:<timestamp> <player_uuid>
 * - <record_uuid>:<timestamp>
 */

impl fmt::Display for Record {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Submit( SubmitRecord { record_uuid, timestamp, player_uuid } ) => {
                f.write_fmt(format_args!("+ {}:{} {}", record_uuid, timestamp, player_uuid))
            }
            Self::Recall( RecallRecord { record_uuid, timestamp } ) => {
                f.write_fmt(format_args!("- {}:{}", record_uuid, timestamp))
            }
        }
        
    }
}

impl FromStr for Record {
    type Err = usize;

    fn from_str(s: &str) -> Result<Self, Self::Err> {

        let mut it = s.splitn(3, ' ');

        let parse2 = |it: &mut str::SplitN<char>| -> Result<(Uuid, u64), usize> {
            let p1 = it.next().ok_or_else(|| s.len())?;
            let mut it1 = p1.splitn(2, ':');
            let record_uuid = it1.next().ok_or_else(|| s.find(p1).unwrap() + p1.len())?;
            let timestamp = it1.next().ok_or_else(|| s.find(p1).unwrap() + p1.len())?;
            let record_uuid = Uuid::from_str(record_uuid).map_err(|e| s.find(record_uuid).unwrap() + 0)?;
            let timestamp = u64::from_str(timestamp).map_err(|e| s.find(timestamp).unwrap() + 0)?;

            Ok((record_uuid, timestamp))
        };

        
        let item = match it.next().ok_or_else(|| 0usize)? {
            "+" => {
                let (record_uuid, timestamp) = parse2(&mut it)?;

                let player_uuid = it.next().ok_or_else(|| s.len())?;
                let player_uuid = Uuid::from_str(player_uuid).map_err(|e| s.find(player_uuid).unwrap() + 0)?;

                Self::Submit( SubmitRecord { record_uuid, timestamp, player_uuid } )
            },
            "-" => {
                let (record_uuid, timestamp) = parse2(&mut it)?;
            
                Self::Recall( RecallRecord { record_uuid, timestamp } ) 
            },
            _ => {
                return Err(0);
            }
        };
        Ok(item)
    }
}


pub struct RecordConfig {
    path: PathBuf,
    cache: HashMap<Uuid, Uuid>, // submit_uuid +=> record
    index: HashMap<Uuid, Uuid>, // player_uuid +=> submit_uuid
    change: Vec<Record>,
}

impl RecordConfig {

    pub fn new(path: PathBuf) -> io::Result<Self> {
        
        let mut index = HashMap::new();
        let cache = match File::open(path.as_path()) {
            Ok(ifile) => {
                let mut cache = HashMap::new();
                let reader = io::BufReader::new(ifile);
                for maybe_line in reader.lines() {
                    let line = maybe_line?;
                    if line.is_empty() {
                        continue
                    }
                    let record = Record::from_str(line.as_str()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("`{}` @{}", line.as_str(), e)))?;
                    match record {
                        Record::Submit(s) => {
                            cache.insert(s.record_uuid.clone(), s.player_uuid.clone());
                        }
                        Record::Recall(r)=> {
                            cache.remove(&r.record_uuid);
                        }
                    }
                }
                for (record_uuid, player_uuid) in cache.iter() {
                    index.insert(player_uuid.clone(), record_uuid.clone());
                }
                cache
            },
            Err(e) => {
                if e.kind() == io::ErrorKind::NotFound {
                    let ofile = OpenOptions::new().write(true).create_new(true).open(path.as_path())?;
                    HashMap::new()
                } else {
                    return Err(e.into())
                }
            }
        };

        Ok(
            RecordConfig {
                path,
                cache,
                index,
                change: Vec::new(),
            }
        )
    }

    pub fn save(&mut self) -> io::Result<bool> {
        if self.change.len() > 0 {
            let mut ofile = OpenOptions::new().append(true).create(true).open(self.path.as_path())?;
            for r in self.change.as_slice() {
                ofile.write_fmt(format_args!("{}\n", r))?;
            }
            self.change.clear();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn new_submit(&mut self, record_uuid: Uuid, timestamp: u64, player_uuid: Uuid) -> bool {
        match self.cache.entry(record_uuid) {
            Entry::Occupied(o) => {
                false
            }
            Entry::Vacant(v) => {
                let r = SubmitRecord { record_uuid, timestamp, player_uuid };
                v.insert(r.player_uuid.clone());
                self.index.insert(r.player_uuid.clone(), r.record_uuid.clone());
                self.change.push(Record::Submit(r));
                true
            }
        }
    }

    pub fn new_recall(&mut self, record_uuid: Uuid, timestamp: u64) -> bool {
        if let Some(player_uuid) = self.cache.remove(&record_uuid) {
            let r = RecallRecord { record_uuid, timestamp };
            self.index.remove(&player_uuid);
            self.change.push(Record::Recall(r));
            true
        } else {
            false
        }
    }

    pub fn check_record_uuid(&self, record_uuid: &Uuid) -> Option<&Uuid> {
        self.cache.get(record_uuid)
    }

    pub fn check_player_uuid(&self, player_uuid: &Uuid) -> Option<&Uuid> {
        self.index.get(player_uuid)
    }
}

impl Drop for RecordConfig {

    fn drop(&mut self) {
        if let Err(e) = self.save() {
            eprintln!("{}", e)
        }
    }
}