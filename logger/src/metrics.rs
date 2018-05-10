use error::LoggerError;
use std::collections::HashMap;
use std::fmt;
use std::result;
use std::sync::Mutex;
use time::{Duration, SteadyTime};

type Result<T> = result::Result<T, LoggerError>;

#[derive(Debug, Clone)]
enum Category {
    Api,
    #[allow(dead_code)]
    Performance,
    #[allow(dead_code)]
    UnexpectedEvents,
    #[allow(dead_code)]
    KVM,
}

#[derive(Debug, Clone)]
enum Unit {
    CountPerSecond,
    Count,
    #[allow(dead_code)]
    Seconds,
}

///  A metric definition
#[derive(Clone)]
pub struct Metric {
    /// Name of the key, forced to be unique as it is a value of an enum.
    key: LogMetric,
    /// The category of the metric (e.g. "API").
    category: Category,
    /// Unit of measurement
    unit: Unit,
    /// Increases every time a metric is called, resets to 0 whenever metric is written to file.
    counter: usize,
    /// Should provide a nice description for the unit as this goes to the log file.
    nice_unit: &'static str,
    /// Keep a timestamp for when the metric was flushed to disk.
    last_logged: SteadyTime,
    /// While logging metrics, the user can specify some crate specific stuff here.
    source: Option<String>,
}

impl Metric {
    // maybe an additional string parameter for crate specific info??
    // 2 outcomes
    // 1. Ok is returned only when the metric has been written to the file together with the message
    // 2. rate limiting related error when the metric should not be yet written to the file
    pub fn log_metric(&mut self) -> Result<String> {
        self.counter = self.counter + 1;

        // we will log stuff from one min plus, but for unit testing this
        // and not wait a lifetime, I will put 2 sec for now
        // let one_min = Duration::from_secs(60);
        let one_min = Duration::seconds(2);
        let diff = SteadyTime::now() - self.last_logged;
        if diff > one_min {
            let res = Ok(format!("{:?}", self));
            self.last_logged = SteadyTime::now();
            self.counter = 0;
            return res;
        }
        Err(LoggerError::LogMetricRateLimit)
    }
}

lazy_static! {
    pub static ref GLOBAL_METRICS: Mutex<HashMap<String, Metric>> = Mutex::new(build_metrics());
}

pub fn get_metrics() -> &'static GLOBAL_METRICS {
    &GLOBAL_METRICS
}

impl fmt::Debug for Metric {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let counter = match self.unit {
            Unit::CountPerSecond => {
                let diff = SteadyTime::now() - self.last_logged;
                self.counter as f32 / diff.num_seconds() as f32
            }
            Unit::Seconds => self.counter as f32,
            Unit::Count => self.counter as f32,
        };

        match self.unit {
            Unit::CountPerSecond => write!(
                f,
                "{:?} Metric: {} returned {:.3} {}",
                self.category,
                format!("{:?}", self.key),
                counter,
                self.nice_unit,
            ),
            _ => write!(
                f,
                "{:?} Metric: {} returned {:.0} {}",
                self.category,
                format!("{:?}", self.key),
                counter,
                self.nice_unit,
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub enum LogMetric {
    MetricGetInstanceInfoFailures,
    MetricGetInstanceInfoRate,
}

fn build_metrics() -> HashMap<String, Metric> {
    [
        (
            format!("{:?}", LogMetric::MetricGetInstanceInfoRate),
            Metric {
                key: LogMetric::MetricGetInstanceInfoRate,
                category: Category::Api,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricGetInstanceInfoFailures),
            Metric {
                key: LogMetric::MetricGetInstanceInfoFailures,
                category: Category::Api,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
    ].iter()
        .cloned()
        .collect()
}
