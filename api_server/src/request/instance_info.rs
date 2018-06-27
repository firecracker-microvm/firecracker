#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum InstanceState {
    Uninitialized,
    Starting,
    Running,
    Halting,
    Halted,
}

// This struct represents the strongly typed equivalent of the json body of InstanceInfo
#[derive(Debug, Serialize)]
pub struct InstanceInfo {
    pub state: InstanceState,
}
