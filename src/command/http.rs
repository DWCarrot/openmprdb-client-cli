use std::error;
use std::time::Duration;
use std::env;
use std::borrow::Borrow;

use serde::de::DeserializeOwned;
use anyhow::Result as GeneralResult;
use ureq::Agent;
use ureq::Transport;
use url::Url;

use crate::api_v1 as api;
use api::WriteTo;
use api::RequestInfo;
use api::RequestMethod;


pub enum RequsetError {
    Transport(anyhow::Error),
    Response(api::ErrorResponse),
}

impl RequsetError {
    fn as_transport_error<E: error::Error + Send + Sync + 'static>(e: E) -> Self {
        Self::Transport(e.into())
    }
}

impl From<anyhow::Error> for RequsetError {
    
    fn from(e: anyhow::Error) -> Self {
        Self::Transport(e)
    }
}







pub struct Client {
    agent: Agent,
}

impl Client {

    pub fn new() -> GeneralResult<Self> {
        use ureq::AgentBuilder;
        use ureq::Error;
        use ureq::Proxy;
    
        fn as_transport_error(e: Error) -> Transport {
            match e {
                Error::Transport(e) => e,
                Error::Status(_, _) => {
                    unreachable!()
                } 
            }
        }
    
        let mut ab = AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10));
        if let Ok(s) = env::var("HTTP_PROXY") {
            let proxy = Proxy::new(s).map_err(as_transport_error)?;
            ab = ab.proxy(proxy)
        } else {
            if let Ok(s) = env::var("SOCKS_PROXY") {
                let proxy = Proxy::new(s).map_err(as_transport_error)?;
                ab = ab.proxy(proxy)
            }
        }
        let agent = ab.build();
    
        Ok(
            Client {
                agent
            }
        )
    }

    pub fn request<I, O>(&self, api_url: &Url, req: I) -> Result<O, RequsetError> 
    where 
        I: WriteTo<Error = anyhow::Error> + RequestInfo,
        O: DeserializeOwned
    {
        
        let method = match req.method() {
            RequestMethod::GET => "GET",
            RequestMethod::PUT => "PUT",
            RequestMethod::POST => "POST",
            RequestMethod::DELETE => "DELETE",
            RequestMethod::PATCH => "PATCH",
        };
        let url = req.url(api_url);

        let request = self.agent.request_url(method, url.borrow());

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
                Ok(serde_json::from_reader(rdr).map_err(RequsetError::as_transport_error)?)
            },
            Err(e) => {
                match e {
                    ureq::Error::Status(code, response) => {
                        let s = response.into_string().map_err(RequsetError::as_transport_error)?;
                        let deserialized: Result<api::ErrorResponse, _> = serde_json::from_str(s.as_str());
                        let resp = match deserialized {
                            Ok(mut resp) => { resp.code = code; resp },
                            Err(e) => api::ErrorResponse { status: api::Status::Unexpected, reason: s , code }
                        };
                        Err(RequsetError::Response(resp))
                    },
                    ureq::Error::Transport(transport) => {
                        Err(RequsetError::as_transport_error(transport))
                    }
                }
            }
        }
    }
}

