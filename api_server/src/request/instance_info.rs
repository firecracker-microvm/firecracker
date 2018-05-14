#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum InstanceState {
    Uninitialized,
    Starting,
    Running,
    Halting,
    Halted,
}

// This struct represents the strongly typed equivalent of the json body of InstanceInfo
#[derive(Debug, Deserialize, Serialize)]
pub struct InstanceInfo {
    pub state: InstanceState,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    fn test_ser_deser(j: &str) {
        let result: Result<InstanceState, serde_json::Error> = serde_json::from_str(j);
        assert!(result.is_ok());
        let result = serde_json::to_string(&result.unwrap());
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            String::from(j).replace("\n", "").replace(" ", "")
        );
    }

    #[test]
    fn test_instance_state_serde() {
        test_ser_deser("\"Uninitialized\"");
        test_ser_deser("\"Starting\"");
        test_ser_deser("\"Running\"");
        test_ser_deser("\"Halting\"");
        test_ser_deser("\"Halted\"");
    }

    #[test]
    fn test_instance_state_debug_eq() {
        assert_eq!(
            format!("{:?}", InstanceState::Uninitialized),
            "Uninitialized"
        );
        assert_eq!(format!("{:?}", InstanceState::Starting), "Starting");
        assert_eq!(format!("{:?}", InstanceState::Running), "Running");
        assert_eq!(format!("{:?}", InstanceState::Halting), "Halting");
        assert_eq!(format!("{:?}", InstanceState::Halted), "Halted");
    }

    #[test]
    fn test_instance_info() {
        let j = "{\"state\": \"Uninitialized\"}";
        let result: InstanceInfo = serde_json::from_str(j).unwrap();
        assert_eq!(
            format!("{:?}", result),
            "InstanceInfo { state: Uninitialized }"
        );

        assert_eq!(format!("{:?}", result.state.clone()), "Uninitialized");

        let result = serde_json::to_string(&result);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            String::from(j).replace("\n", "").replace(" ", "")
        );
    }
}
