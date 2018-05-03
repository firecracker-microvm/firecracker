use std::result;
use api_server::request::sync::{APILoggerDescription, APILoggerError, APILoggerLevel};
use logger::{Level, Logger};

type Result<T> = result::Result<T, APILoggerError>;

pub fn init_logger(api_logger: APILoggerDescription) -> Result<()> {
    //there are 3 things we need to get out: the level, whether to show it and whether to show the origin of the log
    let mut logger = Logger::new();
    let level = from_api_level(api_logger.level);

    if let Some(val) = level {
        logger.set_level(val);
    }

    if let Some(val) = api_logger.show_log_origin {
        logger.set_include_origin(val, val);
    }

    if let Some(val) = api_logger.show_level {
        logger.set_include_level(val);
    }

    if let Err(ref e) = logger.init(Some(api_logger.path)) {
        return Err(APILoggerError::InitializationFailure(e.to_string()));
    } else {
        Ok(())
    }
}

fn from_api_level(api_level: Option<APILoggerLevel>) -> Option<Level> {
    if let Some(val) = api_level {
        match val {
            APILoggerLevel::Error => Some(Level::Error),
            APILoggerLevel::Warning => Some(Level::Warn),
            APILoggerLevel::Info => Some(Level::Info),
            APILoggerLevel::Debug => Some(Level::Debug),
        }
    } else {
        None
    }
}
