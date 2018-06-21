#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum LoggerLevel {
    Error,
    Warning,
    Info,
    Debug,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct LoggerDescription {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<LoggerLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub show_level: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub show_log_origin: Option<bool>,
}

#[derive(Debug)]
pub enum LoggerError {
    InitializationFailure(String),
}

pub enum PutLoggerOutcome {
    Initialized,
    Error(LoggerError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logger_level_format() {
        assert_eq!(format!("{:?}", LoggerLevel::Error), "Error");
        assert_eq!(format!("{:?}", LoggerLevel::Warning), "Warning");
        assert_eq!(format!("{:?}", LoggerLevel::Info), "Info");
        assert_eq!(format!("{:?}", LoggerLevel::Debug), "Debug");
    }
}
