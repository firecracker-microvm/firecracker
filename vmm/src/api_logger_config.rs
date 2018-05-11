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

#[cfg(test)]
mod tests {
    use super::*;
    use api_server::request::sync::{APILoggerDescription, APILoggerLevel};
    use std::fs::{self, File};
    use std::io::{BufRead, BufReader};

    fn validate_logs(
        log_path: &str,
        expected: &[(&'static str, &'static str, &'static str)],
    ) -> bool {
        let f = File::open(log_path).unwrap();
        let mut reader = BufReader::new(f);
        let mut res = true;
        let mut line = String::new();
        for tuple in expected {
            line.clear();
            reader.read_line(&mut line).unwrap();
            res &= line.contains(&tuple.0);
            res &= line.contains(&tuple.1);
            res &= line.contains(&tuple.2);
        }
        res
    }

    #[test]
    fn test_init_logger_from_api() {
        let desc = APILoggerDescription {
            path: String::from(""),
            level: None,
            show_level: None,
            show_log_origin: None,
        };
        assert!(init_logger(desc).is_err());

        let filename = "tmp.log";
        let desc = APILoggerDescription {
            path: String::from(filename),
            level: Some(APILoggerLevel::Warning),
            show_level: Some(true),
            show_log_origin: Some(true),
        };
        let res = init_logger(desc).is_ok();

        if !res {
            let _x = fs::remove_file(filename);
        }

        assert!(res);

        info!("info");
        warn!("warning");
        error!("error");

        // info should not be outputted
        let res = validate_logs(
            filename,
            &[
                ("[WARN", "logger_config.rs", "warn"),
                ("[ERROR", "logger_config.rs", "error"),
            ],
        );
        let _x = fs::remove_file(filename);
        assert!(res);
    }

    #[test]
    fn test_from_api_level() {
        assert_eq!(
            from_api_level(Some(APILoggerLevel::Error)),
            Some(Level::Error)
        );
        assert_eq!(
            from_api_level(Some(APILoggerLevel::Warning)),
            Some(Level::Warn)
        );
        assert_eq!(
            from_api_level(Some(APILoggerLevel::Info)),
            Some(Level::Info)
        );
        assert_eq!(
            from_api_level(Some(APILoggerLevel::Debug)),
            Some(Level::Debug)
        );
    }
}
