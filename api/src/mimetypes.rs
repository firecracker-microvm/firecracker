/// mime types for requests and responses

pub mod responses {
    use hyper::mime::*;

    // The macro is called per-operation to beat the recursion limit
    /// Create Mime objects for the response content types for ApplyLimiterToDrive
    lazy_static! {
        pub static ref APPLY_LIMITER_TO_DRIVE_LIMITER_CANNOT_BE_APPLIED_DUE_TO_BAD_INPUT: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for ApplyLimiterToDrive
    lazy_static! {
        pub static ref APPLY_LIMITER_TO_DRIVE_INTERNAL_SERVER_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for ApplyLimiterToNetworkInterface
    lazy_static! {
        pub static ref APPLY_LIMITER_TO_NETWORK_INTERFACE_LIMITER_CANNOT_BE_APPLIED_DUE_TO_BAD_INPUT: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for ApplyLimiterToNetworkInterface
    lazy_static! {
        pub static ref APPLY_LIMITER_TO_NETWORK_INTERFACE_INTERNAL_SERVER_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for ApplyLimiterToVsock
    lazy_static! {
        pub static ref APPLY_LIMITER_TO_VSOCK_LIMITER_CANNOT_BE_APPLIED_DUE_TO_BAD_INPUT: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for ApplyLimiterToVsock
    lazy_static! {
        pub static ref APPLY_LIMITER_TO_VSOCK_INTERNAL_SERVER_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for CreateInstanceAction
    lazy_static! {
        pub static ref CREATE_INSTANCE_ACTION_UNEXPECTED_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for DeleteGuestDriveByID
    lazy_static! {
        pub static ref DELETE_GUEST_DRIVE_BY_ID_INTERNAL_SERVER_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for DeleteGuestNetworkInterfaceByID
    lazy_static! {
        pub static ref DELETE_GUEST_NETWORK_INTERFACE_BY_ID_INTERNAL_SERVER_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for DeleteGuestVsockByID
    lazy_static! {
        pub static ref DELETE_GUEST_VSOCK_BY_ID_INTERNAL_SERVER_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for DeleteLimiter
    lazy_static! {
        pub static ref DELETE_LIMITER_INTERNAL_SERVER_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for DescribeInstance
    lazy_static! {
        pub static ref DESCRIBE_INSTANCE_THE_INSTANCE_INFORMATION: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for DescribeInstance
    lazy_static! {
        pub static ref DESCRIBE_INSTANCE_UNEXPECTED_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for DescribeInstanceAction
    lazy_static! {
        pub static ref DESCRIBE_INSTANCE_ACTION_THE_INSTANCE_ACTION_INFORMATION: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for DescribeInstanceAction
    lazy_static! {
        pub static ref DESCRIBE_INSTANCE_ACTION_UNEXPECTED_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for DescribeLimiter
    lazy_static! {
        pub static ref DESCRIBE_LIMITER_SPECIFIED_LIMITER: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for DescribeLimiter
    lazy_static! {
        pub static ref DESCRIBE_LIMITER_LIMITER_DOES_NOT_EXIST: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for DescribeLimiter
    lazy_static! {
        pub static ref DESCRIBE_LIMITER_INTERNAL_SERVER_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetGuestBootSource
    lazy_static! {
        pub static ref GET_GUEST_BOOT_SOURCE_SPECIFIED_BOOT_SOURCE: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetGuestBootSource
    lazy_static! {
        pub static ref GET_GUEST_BOOT_SOURCE_BOOT_SOURCE_DOES_NOT_EXIST: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetGuestBootSource
    lazy_static! {
        pub static ref GET_GUEST_BOOT_SOURCE_INTERNAL_SERVER_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetGuestDriveByID
    lazy_static! {
        pub static ref GET_GUEST_DRIVE_BY_ID_SPECIFIED_DRIVE: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetGuestDriveByID
    lazy_static! {
        pub static ref GET_GUEST_DRIVE_BY_ID_DRIVE_DOES_NOT_EXIST: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetGuestDriveByID
    lazy_static! {
        pub static ref GET_GUEST_DRIVE_BY_ID_INTERNAL_SERVER_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetGuestDrives
    lazy_static! {
        pub static ref GET_GUEST_DRIVES_LIST_OF_GUEST_DRIVES: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetGuestDrives
    lazy_static! {
        pub static ref GET_GUEST_DRIVES_INTERNAL_SERVER_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetGuestNetworkInterfaceByID
    lazy_static! {
        pub static ref GET_GUEST_NETWORK_INTERFACE_BY_ID_SPECIFIED_NETWORK_INTERFACE: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetGuestNetworkInterfaceByID
    lazy_static! {
        pub static ref GET_GUEST_NETWORK_INTERFACE_BY_ID_NETWORK_INTERFACE_DOES_NOT_EXIST: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetGuestNetworkInterfaceByID
    lazy_static! {
        pub static ref GET_GUEST_NETWORK_INTERFACE_BY_ID_INTERNAL_SERVER_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetGuestNetworkInterfaces
    lazy_static! {
        pub static ref GET_GUEST_NETWORK_INTERFACES_LIST_OF_GUEST_NETWORK_INTERFACES: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetGuestNetworkInterfaces
    lazy_static! {
        pub static ref GET_GUEST_NETWORK_INTERFACES_INTERNAL_SERVER_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetGuestVsockByID
    lazy_static! {
        pub static ref GET_GUEST_VSOCK_BY_ID_SPECIFIED_VSOCK: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetGuestVsockByID
    lazy_static! {
        pub static ref GET_GUEST_VSOCK_BY_ID_VSOCK_DOES_NOT_EXIST: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetGuestVsockByID
    lazy_static! {
        pub static ref GET_GUEST_VSOCK_BY_ID_INTERNAL_SERVER_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetGuestVsocks
    lazy_static! {
        pub static ref GET_GUEST_VSOCKS_LIST_OF_GUEST_VSOCKS: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetGuestVsocks
    lazy_static! {
        pub static ref GET_GUEST_VSOCKS_INTERNAL_SERVER_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetLimitersForGuestDrive
    lazy_static! {
        pub static ref GET_LIMITERS_FOR_GUEST_DRIVE_LIST_OF_LIMITERS_I_DS_CURRENTLY_APPLIED_TO_THIS_DRIVE: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetLimitersForGuestDrive
    lazy_static! {
        pub static ref GET_LIMITERS_FOR_GUEST_DRIVE_DRIVE_DOES_NOT_EXIST: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetLimitersForGuestDrive
    lazy_static! {
        pub static ref GET_LIMITERS_FOR_GUEST_DRIVE_INTERNAL_SERVER_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetLimitersForGuestNetworkInterface
    lazy_static! {
        pub static ref GET_LIMITERS_FOR_GUEST_NETWORK_INTERFACE_LIST_OF_LIMITERS_I_DS_CURRENTLY_APPLIED_TO_THIS_NETWORK_INTERFACE: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetLimitersForGuestNetworkInterface
    lazy_static! {
        pub static ref GET_LIMITERS_FOR_GUEST_NETWORK_INTERFACE_NETWORK_INTERFACE_DOES_NOT_EXIST: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetLimitersForGuestNetworkInterface
    lazy_static! {
        pub static ref GET_LIMITERS_FOR_GUEST_NETWORK_INTERFACE_INTERNAL_SERVER_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetLimitersForGuestVsock
    lazy_static! {
        pub static ref GET_LIMITERS_FOR_GUEST_VSOCK_LIST_OF_LIMITERS_I_DS_CURRENTLY_APPLIED_TO_THIS_VSOCK: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetLimitersForGuestVsock
    lazy_static! {
        pub static ref GET_LIMITERS_FOR_GUEST_VSOCK_VSOCK_DOES_NOT_EXIST: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetLimitersForGuestVsock
    lazy_static! {
        pub static ref GET_LIMITERS_FOR_GUEST_VSOCK_INTERNAL_SERVER_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetMetadata
    lazy_static! {
        pub static ref GET_METADATA_THE_INSTANCE_METADATA: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for GetMetadata
    lazy_static! {
        pub static ref GET_METADATA_UNEXPECTED_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for ListInstanceActions
    lazy_static! {
        pub static ref LIST_INSTANCE_ACTIONS_THE_: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for ListInstanceActions
    lazy_static! {
        pub static ref LIST_INSTANCE_ACTIONS_UNEXPECTED_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for ListLimiters
    lazy_static! {
        pub static ref LIST_LIMITERS_LIST_OF_LIMITERS: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for ListLimiters
    lazy_static! {
        pub static ref LIST_LIMITERS_INTERNAL_SERVER_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for PutGuestBootSource
    lazy_static! {
        pub static ref PUT_GUEST_BOOT_SOURCE_BOOT_SOURCE_CANNOT_BE_CREATED_DUE_TO_BAD_INPUT: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for PutGuestBootSource
    lazy_static! {
        pub static ref PUT_GUEST_BOOT_SOURCE_INTERNAL_SERVER_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for PutGuestDriveByID
    lazy_static! {
        pub static ref PUT_GUEST_DRIVE_BY_ID_DRIVE_CANNOT_BE_CREATED_DUE_TO_BAD_INPUT: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for PutGuestDriveByID
    lazy_static! {
        pub static ref PUT_GUEST_DRIVE_BY_ID_INTERNAL_SERVER_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for PutGuestNetworkInterfaceByID
    lazy_static! {
        pub static ref PUT_GUEST_NETWORK_INTERFACE_BY_ID_NETWORK_INTERFACE_CANNOT_BE_CREATED_DUE_TO_BAD_INPUT: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for PutGuestNetworkInterfaceByID
    lazy_static! {
        pub static ref PUT_GUEST_NETWORK_INTERFACE_BY_ID_INTERNAL_SERVER_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for PutGuestVsockByID
    lazy_static! {
        pub static ref PUT_GUEST_VSOCK_BY_ID_VSOCK_CANNOT_BE_CREATED_DUE_TO_BAD_INPUT: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for PutGuestVsockByID
    lazy_static! {
        pub static ref PUT_GUEST_VSOCK_BY_ID_INTERNAL_SERVER_ERROR: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for UpdateLimiter
    lazy_static! {
        pub static ref UPDATE_LIMITER_LIMITER_CANNOT_BE_CREATED_DUE_TO_BAD_INPUT: Mime = mime!(Application/Json);
    }
    /// Create Mime objects for the response content types for UpdateLimiter
    lazy_static! {
        pub static ref UPDATE_LIMITER_INTERNAL_SERVER_ERROR: Mime = mime!(Application/Json);
    }

}

pub mod requests {
    use hyper::mime::*;
   /// Create Mime objects for the request content types for CreateInstanceAction
    lazy_static! {
        pub static ref CREATE_INSTANCE_ACTION: Mime = mime!(Application/Json);
    }
   /// Create Mime objects for the request content types for PutGuestBootSource
    lazy_static! {
        pub static ref PUT_GUEST_BOOT_SOURCE: Mime = mime!(Application/Json);
    }
   /// Create Mime objects for the request content types for PutGuestDriveByID
    lazy_static! {
        pub static ref PUT_GUEST_DRIVE_BY_ID: Mime = mime!(Application/Json);
    }
   /// Create Mime objects for the request content types for PutGuestNetworkInterfaceByID
    lazy_static! {
        pub static ref PUT_GUEST_NETWORK_INTERFACE_BY_ID: Mime = mime!(Application/Json);
    }
   /// Create Mime objects for the request content types for PutGuestVsockByID
    lazy_static! {
        pub static ref PUT_GUEST_VSOCK_BY_ID: Mime = mime!(Application/Json);
    }
   /// Create Mime objects for the request content types for UpdateLimiter
    lazy_static! {
        pub static ref UPDATE_LIMITER: Mime = mime!(Application/Json);
    }

}
