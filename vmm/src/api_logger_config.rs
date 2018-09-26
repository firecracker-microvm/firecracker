use std::result;

use api_server::request::logger::{APILoggerDescription, APILoggerError, APILoggerLevel};
use logger::{Level, LOGGER};

type Result<T> = result::Result<T, APILoggerError>;

pub fn init_logger(instance_id: &str, api_logger: APILoggerDescription) -> Result<()> {
    let level = from_api_level(api_logger.level);

    if let Some(val) = level {
        LOGGER.set_level(val);
    }

    if let Some(val) = api_logger.show_log_origin {
        LOGGER.set_include_origin(val, val);
    }

    if let Some(val) = api_logger.show_level {
        LOGGER.set_include_level(val);
    }

    if let Err(ref e) = LOGGER.init(
        instance_id,
        Some(api_logger.log_fifo),
        Some(api_logger.metrics_fifo),
    ) {
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
    use api_server::request::logger::{APILoggerDescription, APILoggerLevel};
    use std::fs::{self, File};
    use std::io::{BufRead, BufReader};
    use std::path::Path;

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
        let log_filename = "tmp.log";
        let metrics_filename = "metrics.log";

        let desc = APILoggerDescription {
            log_fifo: String::from(log_filename),
            metrics_fifo: String::from(metrics_filename),
            level: None,
            show_level: None,
            show_log_origin: None,
        };
        assert!(init_logger("TEST-ID", desc).is_err());

        File::create(&Path::new(&log_filename)).expect("Failed to create temporary log file.");

        File::create(&Path::new(&metrics_filename)).expect("Failed to create temporary log file.");

        let desc = APILoggerDescription {
            log_fifo: String::from(log_filename),
            metrics_fifo: String::from(metrics_filename),
            level: Some(APILoggerLevel::Warning),
            show_level: Some(true),
            show_log_origin: Some(true),
        };
        let res = init_logger("TEST-ID", desc).is_ok();

        if !res {
            let _x = fs::remove_file(log_filename);
            let _x = fs::remove_file(metrics_filename);
        }

        assert!(res);

        info!("info");
        warn!("warning");
        error!("error");

        // info should not be output
        let res = validate_logs(
            log_filename,
            &[
                ("WARN", "logger_config.rs", "warn"),
                ("ERROR", "logger_config.rs", "error"),
            ],
        );
        let _x = fs::remove_file(log_filename);
        let _x = fs::remove_file(metrics_filename);
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
