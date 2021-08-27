use std::fmt;
use std::error;
use std::str::FromStr;

use clap::ArgMatches;

use crate::api_v1 as api;
use super::http::RequsetError;

#[derive(Debug)]
pub struct ArgsError<'a> {
    name: &'static str,
    expecting: &'static str,
    value: Option<&'a str>,
}

impl<'a> fmt::Display for ArgsError<'a> {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(value) = self.value {
            f.write_fmt(format_args!("ArgsError({}): expecting {}, get `{}`", self.name, self.expecting, value))
        } else {
            f.write_fmt(format_args!("ArgsError({}): expecting {}, missing", self.name, self.expecting))
        }
    }
}

impl<'a> error::Error for ArgsError<'a> {

}

impl<'a> ArgsError<'a> {

    pub fn new(name: &'static str, expecting: &'static str, value: &'a str) -> Self {
        ArgsError {
            name,
            expecting,
            value: Some(value)
        }
    }

    pub fn parse<T: FromStr>(arg: &'a str, name: &'static str, expecting: &'static str) -> Result<T, Self> {
        match T::from_str(arg) {
            Ok(v) => Ok(v),
            Err(e) => Err(ArgsError { name, expecting, value: Some(arg) })    
        }
    }

    pub fn parse_matches_str(args: &'a ArgMatches, name: &'static str, expecting: &'static str) -> Result<&'a str, Self> {
        if let Some(arg) = args.value_of(name) {
            Ok(arg)
        } else {
            Err(ArgsError { name, expecting, value: None })
        }
    }

    pub fn parse_matches<T: FromStr>(args: &'a ArgMatches, name: &'static str, expecting: &'static str) -> Result<T, Self> {
        if let Some(arg) = args.value_of(name) {
            match T::from_str(arg) {
                Ok(v) => Ok(v),
                Err(e) => Err(ArgsError { name, expecting, value: Some(arg) })    
            }
        } else {
            Err(ArgsError { name, expecting, value: None })
        }
    }

    pub fn parse_matches_optional<T: FromStr>(args: &'a ArgMatches, name: &'static str, expecting: &'static str) -> Result<Option<T>, Self> {
        if let Some(arg) = args.value_of(name) {
            match T::from_str(arg) {
                Ok(v) => Ok(Some(v)),
                Err(e) => Err(ArgsError { name, expecting, value: Some(arg) })    
            }
        } else {
            Ok(None)
        }
    }
}


#[derive(Debug)]
pub struct ConfigMissing {
    name: &'static str,
}

impl fmt::Display for ConfigMissing {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("ConfigMissing({})", self.name))
    }
}

impl error::Error for ConfigMissing {

}

impl ConfigMissing {

    pub fn ok<T>(v: Option<T>, name: &'static str) -> Result<T, Self> {
        v.ok_or_else(|| ConfigMissing { name } )
    }
}


pub enum AppError<'a> {
    Args(ArgsError<'a>),
    Config(ConfigMissing),
    Response(api::ErrorResponse),
    Other(anyhow::Error),
}

impl<'a> AppError<'a> {

    pub fn new_other<E: error::Error + Send + Sync + 'static>(e: E) -> Self {
        Self::Other(anyhow::Error::from(e))
    }
}

pub type AppResult<'a> = Result<(), AppError<'a>>;

impl<'a> From<ArgsError<'a>> for AppError<'a> {

    fn from(e: ArgsError<'a>) -> Self {
        Self::Args(e)
    }
}

impl<'a> From<ConfigMissing> for AppError<'a> {

    fn from(e: ConfigMissing) -> Self {
        Self::Config(e)
    }
}

impl<'a> From<anyhow::Error> for AppError<'a> {

    fn from(e: anyhow::Error) -> Self {
        Self::Other(e)
    }
}

impl<'a> From<RequsetError> for AppError<'a> {

    fn from(e: RequsetError) -> Self {
        match e {
            RequsetError::Response(r) => Self::Response(r),
            RequsetError::Transport(e) => Self::Other(e),
        }
    }
}