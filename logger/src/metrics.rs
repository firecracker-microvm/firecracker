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
    Vcpu,
    Device,
}

#[derive(Debug, Clone)]
enum Unit {
    CountPerSecond,
    Count,
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
    MetricGetActionInfoCount,
    MetricGetInstanceInfoFailures,
    MetricGetInstanceInfoCount,
    MetricGetMachineCfgFailures,
    MetricGetMachineCfgCount,
    MetricPutAsyncActionFailures,
    MetricPutAsyncActionCount,
    MetricPutBootSourceFailures,
    MetricPutBootSourceCount,
    MetricPutDriveFailures,
    MetricPutDriveCount,
    MetricPutLoggerFailures,
    MetricPutLoggerCount,
    MetricPutMachineCfgFailures,
    MetricPutMachineCfgCount,
    MetricPutNetworkFailures,
    MetricPutNetworkCount,
    MetricAsyncMissedActionsCount,
    MetricAsyncOutcomeFailures,
    MetricAsyncVMMSendTimeoutCount,
    MetricSyncOutcomeFailures,
    MetricSyncVMMSendTimeoutCount,
    MetricDeviceBlockActivateFailures,
    MetricDeviceBlockCfgFailures,
    MetricDeviceBlockEventFailures,
    MetricDeviceBlockExecuteFailures,
    MetricDeviceBlockFlushCount,
    MetricDeviceBlockQueueEventCount,
    MetricDeviceBlockRateLimiterEventCount,
    MetricDeviceBlockReadCount,
    MetricDeviceBlockWriteCount,
    MetricDeviceNetActivateFailures,
    MetricDeviceNetCfgFailures,
    MetricDeviceNetEventFailures,
    MetricDeviceNetReceiveCount,
    MetricDeviceNetReceiveEventRateLimiterCount,
    MetricDeviceNetReceiveFailures,
    MetricDeviceNetReceiveQueueEventCount,
    MetricDeviceNetReceiveTapEventCount,
    MetricDeviceNetTransmitCount,
    MetricDeviceNetTransmitEventRateLimiterCount,
    MetricDeviceNetTransmitFailures,
    MetricDeviceNetTransmitQueueEventCount,
    MetricDeviceI8042Failures,
    MetricDeviceI8042MissedReads,
    MetricDeviceI8042MissedWrites,
    MetricDeviceI8042ReadCount,
    MetricDeviceI8042ResetCount,
    MetricDeviceSerialFailure,
    MetricDeviceSerialFlushCount,
    MetricDeviceSerialMissedReads,
    MetricDeviceSerialMissedWrites,
    MetricDeviceSerialReadCount,
    MetricDeviceSerialWriteCount,
    MetricVcpuFailures,
    MetricVcpuExitIoInCount,
    MetricVcpuExitIoOutCount,
    MetricVcpuExitMmioReadCount,
    MetricVcpuExitMmioWriteCount,
}

fn build_metrics() -> HashMap<String, Metric> {
    [
        (
            format!("{:?}", LogMetric::MetricGetActionInfoCount),
            Metric {
                key: LogMetric::MetricGetActionInfoCount,
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
        (
            format!("{:?}", LogMetric::MetricGetInstanceInfoCount),
            Metric {
                key: LogMetric::MetricGetInstanceInfoCount,
                category: Category::Api,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricGetMachineCfgFailures),
            Metric {
                key: LogMetric::MetricGetMachineCfgFailures,
                category: Category::Api,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricGetMachineCfgCount),
            Metric {
                key: LogMetric::MetricGetMachineCfgCount,
                category: Category::Api,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricPutAsyncActionFailures),
            Metric {
                key: LogMetric::MetricPutAsyncActionFailures,
                category: Category::Api,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricPutAsyncActionCount),
            Metric {
                key: LogMetric::MetricPutAsyncActionCount,
                category: Category::Api,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricPutBootSourceFailures),
            Metric {
                key: LogMetric::MetricPutBootSourceFailures,
                category: Category::Api,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricPutBootSourceCount),
            Metric {
                key: LogMetric::MetricPutBootSourceCount,
                category: Category::Api,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricPutDriveFailures),
            Metric {
                key: LogMetric::MetricPutDriveFailures,
                category: Category::Api,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricPutDriveCount),
            Metric {
                key: LogMetric::MetricPutDriveCount,
                category: Category::Api,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricPutLoggerFailures),
            Metric {
                key: LogMetric::MetricPutLoggerFailures,
                category: Category::Api,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricPutLoggerCount),
            Metric {
                key: LogMetric::MetricPutLoggerCount,
                category: Category::Api,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricPutMachineCfgFailures),
            Metric {
                key: LogMetric::MetricPutMachineCfgFailures,
                category: Category::Api,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricPutMachineCfgCount),
            Metric {
                key: LogMetric::MetricPutMachineCfgCount,
                category: Category::Api,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricPutNetworkFailures),
            Metric {
                key: LogMetric::MetricPutNetworkFailures,
                category: Category::Api,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricPutNetworkCount),
            Metric {
                key: LogMetric::MetricPutNetworkCount,
                category: Category::Api,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricAsyncMissedActionsCount),
            Metric {
                key: LogMetric::MetricAsyncMissedActionsCount,
                category: Category::Api,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricAsyncOutcomeFailures),
            Metric {
                key: LogMetric::MetricAsyncOutcomeFailures,
                category: Category::Api,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricAsyncVMMSendTimeoutCount),
            Metric {
                key: LogMetric::MetricAsyncVMMSendTimeoutCount,
                category: Category::Api,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricSyncOutcomeFailures),
            Metric {
                key: LogMetric::MetricSyncOutcomeFailures,
                category: Category::Api,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricSyncVMMSendTimeoutCount),
            Metric {
                key: LogMetric::MetricSyncVMMSendTimeoutCount,
                category: Category::Api,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceBlockActivateFailures),
            Metric {
                key: LogMetric::MetricDeviceBlockActivateFailures,
                category: Category::Device,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceBlockCfgFailures),
            Metric {
                key: LogMetric::MetricDeviceBlockCfgFailures,
                category: Category::Device,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceBlockEventFailures),
            Metric {
                key: LogMetric::MetricDeviceBlockEventFailures,
                category: Category::Device,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceBlockExecuteFailures),
            Metric {
                key: LogMetric::MetricDeviceBlockExecuteFailures,
                category: Category::Device,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceBlockFlushCount),
            Metric {
                key: LogMetric::MetricDeviceBlockFlushCount,
                category: Category::Device,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceBlockQueueEventCount),
            Metric {
                key: LogMetric::MetricDeviceBlockQueueEventCount,
                category: Category::Device,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceBlockRateLimiterEventCount),
            Metric {
                key: LogMetric::MetricDeviceBlockRateLimiterEventCount,
                category: Category::Device,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceBlockReadCount),
            Metric {
                key: LogMetric::MetricDeviceBlockReadCount,
                category: Category::Device,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceBlockWriteCount),
            Metric {
                key: LogMetric::MetricDeviceBlockWriteCount,
                category: Category::Device,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceNetActivateFailures),
            Metric {
                key: LogMetric::MetricDeviceNetActivateFailures,
                category: Category::Device,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceNetCfgFailures),
            Metric {
                key: LogMetric::MetricDeviceNetCfgFailures,
                category: Category::Device,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceNetEventFailures),
            Metric {
                key: LogMetric::MetricDeviceNetEventFailures,
                category: Category::Device,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceNetReceiveQueueEventCount),
            Metric {
                key: LogMetric::MetricDeviceNetReceiveQueueEventCount,
                category: Category::Device,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceNetReceiveTapEventCount),
            Metric {
                key: LogMetric::MetricDeviceNetReceiveTapEventCount,
                category: Category::Device,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceNetTransmitQueueEventCount),
            Metric {
                key: LogMetric::MetricDeviceNetTransmitQueueEventCount,
                category: Category::Device,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceNetTransmitFailures),
            Metric {
                key: LogMetric::MetricDeviceNetTransmitFailures,
                category: Category::Device,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceNetTransmitCount),
            Metric {
                key: LogMetric::MetricDeviceNetTransmitCount,
                category: Category::Device,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceNetReceiveFailures),
            Metric {
                key: LogMetric::MetricDeviceNetReceiveFailures,
                category: Category::Device,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceNetReceiveCount),
            Metric {
                key: LogMetric::MetricDeviceNetReceiveCount,
                category: Category::Device,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceI8042Failures),
            Metric {
                key: LogMetric::MetricDeviceI8042Failures,
                category: Category::Device,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceI8042MissedReads),
            Metric {
                key: LogMetric::MetricDeviceI8042MissedReads,
                category: Category::Device,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceI8042MissedWrites),
            Metric {
                key: LogMetric::MetricDeviceI8042MissedWrites,
                category: Category::Device,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceI8042ReadCount),
            Metric {
                key: LogMetric::MetricDeviceI8042ReadCount,
                category: Category::Device,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceI8042ResetCount),
            Metric {
                key: LogMetric::MetricDeviceI8042ResetCount,
                category: Category::Device,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceSerialFailure),
            Metric {
                key: LogMetric::MetricDeviceSerialFailure,
                category: Category::Device,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceSerialFlushCount),
            Metric {
                key: LogMetric::MetricDeviceSerialFlushCount,
                category: Category::Device,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceSerialMissedReads),
            Metric {
                key: LogMetric::MetricDeviceSerialMissedReads,
                category: Category::Device,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceSerialMissedWrites),
            Metric {
                key: LogMetric::MetricDeviceSerialMissedWrites,
                category: Category::Device,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceSerialReadCount),
            Metric {
                key: LogMetric::MetricDeviceSerialReadCount,
                category: Category::Device,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricDeviceSerialWriteCount),
            Metric {
                key: LogMetric::MetricDeviceSerialWriteCount,
                category: Category::Device,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricVcpuFailures),
            Metric {
                key: LogMetric::MetricVcpuFailures,
                category: Category::Vcpu,
                unit: Unit::Count,
                counter: 0,
                nice_unit: "Failures",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricVcpuExitIoInCount),
            Metric {
                key: LogMetric::MetricVcpuExitIoInCount,
                category: Category::Vcpu,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricVcpuExitIoOutCount),
            Metric {
                key: LogMetric::MetricVcpuExitIoOutCount,
                category: Category::Vcpu,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricVcpuExitMmioReadCount),
            Metric {
                key: LogMetric::MetricVcpuExitMmioReadCount,
                category: Category::Vcpu,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
        (
            format!("{:?}", LogMetric::MetricVcpuExitMmioWriteCount),
            Metric {
                key: LogMetric::MetricVcpuExitMmioWriteCount,
                category: Category::Vcpu,
                unit: Unit::CountPerSecond,
                counter: 0,
                nice_unit: "Requests/Sec",
                last_logged: SteadyTime::now(),
                source: None,
            },
        ),
    ].iter()
        .cloned()
        .collect()
}
