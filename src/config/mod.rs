pub mod client;
pub mod servers;
pub mod records;
pub mod config;

use std::env;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::fs::File;
use std::fs::OpenOptions;

use serde::Serialize;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use sequoia_openpgp::policy::Policy;

pub fn current_exe_path<P: AsRef<Path>>(to_join: P) -> io::Result<PathBuf> {
    let exe = env::current_exe()?;
    if let Some(path) = exe.parent() {
        let mut path = PathBuf::from(path);
        path.push(to_join);
        Ok(path)
    } else {
        Err(io::Error::from(io::ErrorKind::Other))
    }
}


pub fn build_policy() -> Box<dyn Policy> {
    use sequoia_openpgp::policy::StandardPolicy;

    Box::new(StandardPolicy::new())
}



pub struct FileConfig<D: Serialize + DeserializeOwned> {
    data: D,
    changed: bool,
    path: PathBuf,
}

impl<D: Serialize + DeserializeOwned> FileConfig<D> {

    pub fn new<F: FnOnce() -> D>(path: PathBuf, default: F) -> io::Result<Self> {
        let mut changed = false;
        let data = match File::open(path.as_path()) {
            Ok(ifile) => {
                let mut data: D = serde_json::from_reader(ifile)?;
                data
            },
            Err(e) => {
                if e.kind() == io::ErrorKind::NotFound {
                    let ofile = OpenOptions::new().write(true).create_new(true).open(path.as_path())?;
                    default()
                } else {
                    return Err(e)
                }
            }
        };
        Ok( 
            FileConfig {
                data,
                changed,
                path
            } 
        )
    }

    pub fn changed(&self) -> bool {
        self.changed
    }

    pub fn save(&mut self) -> io::Result<bool> {
        if self.changed {
            let mut ofile = File::create(self.path.as_path())?;
            serde_json::to_writer_pretty(&mut ofile, &self.data)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn get_data(&self) -> &D {
        &self.data
    }

    pub fn get_data_mut(&mut self) -> &mut D {
        self.changed = true;
        &mut self.data
    }

    pub fn modify<F: FnOnce(&mut D) -> Result<bool, E>, E>(&mut self, callback: F) -> Result<(), E> {
        match callback(&mut self.data) {
            Ok(changed) => {
                self.changed = changed;
                Ok(())
            }
            Err(e) => {
                self.changed = true;
                Err(e)
            }
        }
    }
}



impl<D: Serialize + DeserializeOwned> Drop for FileConfig<D> {
    
    fn drop(&mut self) {
        if let Err(e) = self.save() {
            eprintln!("{}", e)
        }
    }
}


