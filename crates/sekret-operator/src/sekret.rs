use sekret_client::{ClientError, ClientOptions, HttpClient, SekretApi};

/// Builds sekret API clients, unauthenticated for login and token-scoped afterwards.
#[cfg_attr(test, mockall::automock)]
pub trait SekretApiFactory: Send + Sync {
    fn client(&self, token: Option<String>) -> Result<Box<dyn SekretApi>, ClientError>;
}

pub struct HttpSekretFactory {
    base_url: String,
    options: ClientOptions,
}

impl HttpSekretFactory {
    /// Validates the URL and CA bundle up front so misconfiguration fails at startup.
    pub fn new(base_url: String, options: ClientOptions) -> Result<Self, ClientError> {
        HttpClient::new(&base_url, None, options.clone())?;
        Ok(Self { base_url, options })
    }
}

impl SekretApiFactory for HttpSekretFactory {
    fn client(&self, token: Option<String>) -> Result<Box<dyn SekretApi>, ClientError> {
        Ok(Box::new(HttpClient::new(&self.base_url, token, self.options.clone())?))
    }
}
