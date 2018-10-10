use std::fmt::{Display, Formatter, Result};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum LoggerLevel {
    Error,
    Warning,
    Info,
    Debug,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoggerConfig {
    pub log_fifo: String,
    pub metrics_fifo: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<LoggerLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub show_level: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub show_log_origin: Option<bool>,
}

#[derive(Debug)]
pub enum LoggerConfigError {
    InitializationFailure(String),
}

impl Display for LoggerConfigError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        use self::LoggerConfigError::*;
        match *self {
            InitializationFailure(ref err_msg) => write!(f, "{}", err_msg),
        }
    }
}
