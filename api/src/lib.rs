#![allow(missing_docs, trivial_casts, non_camel_case_types)]

#[macro_use]
extern crate serde_derive;
extern crate serde_json;

extern crate futures;

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

// Logically this should be in the server modules, but rust doesn't allow `macro_use` from a module.
#[cfg(feature = "server")]
#[macro_use]
extern crate hyper;

extern crate swagger;

pub use futures::Future;

#[cfg(feature = "server")]
mod mimetypes;

pub use swagger::{ApiError, Context, ContextWrapper};


#[derive(Debug, PartialEq)]
pub enum ApplyLimiterToDriveResponse {
    LimiterApplied ,
    LimiterCannotBeAppliedDueToBadInput ( models::Error ) ,
    InternalServerError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum ApplyLimiterToNetworkInterfaceResponse {
    LimiterApplied ,
    LimiterCannotBeAppliedDueToBadInput ( models::Error ) ,
    InternalServerError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum ApplyLimiterToVsockResponse {
    LimiterApplied ,
    LimiterCannotBeAppliedDueToBadInput ( models::Error ) ,
    InternalServerError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum CreateInstanceActionResponse {
    NoPreviousActionExistedSoANewOneWasCreated ,
    ActionUpdated ,
    UnexpectedError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum DeleteGuestDriveByIDResponse {
    DriveDeleted ,
    InternalServerError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum DeleteGuestNetworkInterfaceByIDResponse {
    NetworkInterfaceDeleted ,
    InternalServerError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum DeleteGuestVsockByIDResponse {
    VsockDeleted ,
    InternalServerError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum DeleteLimiterResponse {
    LimiterDeleted ,
    InternalServerError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum DescribeInstanceResponse {
    TheInstanceInformation ( models::InstanceInfo ) ,
    UnexpectedError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum DescribeInstanceActionResponse {
    TheInstanceActionInformation ( models::InstanceActionInfo ) ,
    UnexpectedError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum DescribeLimiterResponse {
    SpecifiedLimiter ( models::Limiter ) ,
    LimiterDoesNotExist ( models::Error ) ,
    InternalServerError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum GetGuestBootSourceResponse {
    SpecifiedBootSource ( models::BootSource ) ,
    BootSourceDoesNotExist ( models::Error ) ,
    InternalServerError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum GetGuestDriveByIDResponse {
    SpecifiedDrive ( models::Drive ) ,
    DriveDoesNotExist ( models::Error ) ,
    InternalServerError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum GetGuestDrivesResponse {
    ListOfGuestDrives ( Vec<models::Drive> ) ,
    InternalServerError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum GetGuestNetworkInterfaceByIDResponse {
    SpecifiedNetworkInterface ( models::NetworkInterface ) ,
    NetworkInterfaceDoesNotExist ( models::Error ) ,
    InternalServerError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum GetGuestNetworkInterfacesResponse {
    ListOfGuestNetworkInterfaces ( Vec<models::NetworkInterface> ) ,
    InternalServerError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum GetGuestVsockByIDResponse {
    SpecifiedVsock ( models::Vsock ) ,
    VsockDoesNotExist ( models::Error ) ,
    InternalServerError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum GetGuestVsocksResponse {
    ListOfGuestVsocks ( Vec<models::Vsock> ) ,
    InternalServerError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum GetLimitersForGuestDriveResponse {
    ListOfLimitersIDsCurrentlyAppliedToThisDrive ( Vec<i32> ) ,
    DriveDoesNotExist ( models::Error ) ,
    InternalServerError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum GetLimitersForGuestNetworkInterfaceResponse {
    ListOfLimitersIDsCurrentlyAppliedToThisNetworkInterface ( Vec<i32> ) ,
    NetworkInterfaceDoesNotExist ( models::Error ) ,
    InternalServerError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum GetLimitersForGuestVsockResponse {
    ListOfLimitersIDsCurrentlyAppliedToThisVsock ( Vec<i32> ) ,
    VsockDoesNotExist ( models::Error ) ,
    InternalServerError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum GetMetadataResponse {
    TheInstanceMetadata ( models::InstanceMetadata ) ,
    UnexpectedError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum ListInstanceActionsResponse {
    The_ ( Vec<String> ) ,
    UnexpectedError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum ListLimitersResponse {
    ListOfLimiters ( models::LimiterList ) ,
    InternalServerError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum PutGuestBootSourceResponse {
    BootSourceCreated ,
    BootSourceUpdated ,
    BootSourceCannotBeCreatedDueToBadInput ( models::Error ) ,
    InternalServerError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum PutGuestDriveByIDResponse {
    DriveCreated ,
    DriveUpdated ,
    DriveCannotBeCreatedDueToBadInput ( models::Error ) ,
    InternalServerError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum PutGuestNetworkInterfaceByIDResponse {
    NetworkInterfaceCreated ,
    NetworkInterfaceUpdated ,
    NetworkInterfaceCannotBeCreatedDueToBadInput ( models::Error ) ,
    InternalServerError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum PutGuestVsockByIDResponse {
    VsockCreated ,
    VsockUpdated ,
    VsockCannotBeCreatedDueToBadInput ( models::Error ) ,
    InternalServerError ( models::Error ) ,
}

#[derive(Debug, PartialEq)]
pub enum UpdateLimiterResponse {
    LimiterCreated ,
    LimiterUpdated ,
    LimiterCannotBeCreatedDueToBadInput ( models::Error ) ,
    InternalServerError ( models::Error ) ,
}


/// API
pub trait Api {

    /// Applies limiter 'limiter_id' to drive 'drive_id'
    fn apply_limiter_to_drive(&self, drive_id: String, limiter_id: String, context: &Context) -> Box<Future<Item=ApplyLimiterToDriveResponse, Error=ApiError> + Send>;

    /// Applies limiter 'limiter_id' to network interface 'iface_id'
    fn apply_limiter_to_network_interface(&self, iface_id: String, limiter_id: String, context: &Context) -> Box<Future<Item=ApplyLimiterToNetworkInterfaceResponse, Error=ApiError> + Send>;

    /// Applies limiter 'limiter_id' to vsock 'vsock_id'
    fn apply_limiter_to_vsock(&self, vsock_id: String, limiter_id: String, context: &Context) -> Box<Future<Item=ApplyLimiterToVsockResponse, Error=ApiError> + Send>;

    /// Create an instance action.
    fn create_instance_action(&self, action_id: String, info: models::InstanceActionInfo, context: &Context) -> Box<Future<Item=CreateInstanceActionResponse, Error=ApiError> + Send>;

    /// Deletes drive with ID specified by 'drive_id' path parameter. Will clean up any resources associated with this drive.
    fn delete_guest_drive_by_id(&self, drive_id: String, context: &Context) -> Box<Future<Item=DeleteGuestDriveByIDResponse, Error=ApiError> + Send>;

    /// Deletes network interface with ID specified by 'iface_id' path parameter. Will clean up any resources associated with this network interface.
    fn delete_guest_network_interface_by_id(&self, iface_id: String, context: &Context) -> Box<Future<Item=DeleteGuestNetworkInterfaceByIDResponse, Error=ApiError> + Send>;

    /// Deletes vsock with ID specified by 'vsock_id' path parameter. Will clean up any resources associated with this vsock.
    fn delete_guest_vsock_by_id(&self, vsock_id: String, context: &Context) -> Box<Future<Item=DeleteGuestVsockByIDResponse, Error=ApiError> + Send>;

    /// Deletes limiter with ID specified by 'limiter_id' path parameter. Will clean up any resources associated with this limiter.
    fn delete_limiter(&self, limiter_id: String, context: &Context) -> Box<Future<Item=DeleteLimiterResponse, Error=ApiError> + Send>;

    /// Return general information about an instance.
    fn describe_instance(&self, context: &Context) -> Box<Future<Item=DescribeInstanceResponse, Error=ApiError> + Send>;

    /// Return detailed information about an action.
    fn describe_instance_action(&self, action_id: String, context: &Context) -> Box<Future<Item=DescribeInstanceActionResponse, Error=ApiError> + Send>;

    /// Retrieves limiter specified by 'limiter_id' path parameter.
    fn describe_limiter(&self, limiter_id: String, context: &Context) -> Box<Future<Item=DescribeLimiterResponse, Error=ApiError> + Send>;

    /// Get configured boot source.
    fn get_guest_boot_source(&self, context: &Context) -> Box<Future<Item=GetGuestBootSourceResponse, Error=ApiError> + Send>;

    /// Get guest drive by 'drive_id' path parameter.
    fn get_guest_drive_by_id(&self, drive_id: String, context: &Context) -> Box<Future<Item=GetGuestDriveByIDResponse, Error=ApiError> + Send>;

    /// All guest drives
    fn get_guest_drives(&self, context: &Context) -> Box<Future<Item=GetGuestDrivesResponse, Error=ApiError> + Send>;

    /// Get guest network interface by 'iface_id' path parameter.
    fn get_guest_network_interface_by_id(&self, iface_id: String, context: &Context) -> Box<Future<Item=GetGuestNetworkInterfaceByIDResponse, Error=ApiError> + Send>;

    /// All guest network interfaces
    fn get_guest_network_interfaces(&self, context: &Context) -> Box<Future<Item=GetGuestNetworkInterfacesResponse, Error=ApiError> + Send>;

    /// Get guest vsock by 'vsock_id' path parameter.
    fn get_guest_vsock_by_id(&self, vsock_id: String, context: &Context) -> Box<Future<Item=GetGuestVsockByIDResponse, Error=ApiError> + Send>;

    /// All guest vsocks
    fn get_guest_vsocks(&self, context: &Context) -> Box<Future<Item=GetGuestVsocksResponse, Error=ApiError> + Send>;

    /// Retrieves list of limiters IDs currently applied to the drive with 'drive_id'.
    fn get_limiters_for_guest_drive(&self, drive_id: String, context: &Context) -> Box<Future<Item=GetLimitersForGuestDriveResponse, Error=ApiError> + Send>;

    /// Retrieves list of limiters IDs currently applied to the network interface with 'iface_id'.
    fn get_limiters_for_guest_network_interface(&self, iface_id: String, context: &Context) -> Box<Future<Item=GetLimitersForGuestNetworkInterfaceResponse, Error=ApiError> + Send>;

    /// Retrieves list of limiters IDs currently applied to the vsock with 'vsock_id'.
    fn get_limiters_for_guest_vsock(&self, vsock_id: String, context: &Context) -> Box<Future<Item=GetLimitersForGuestVsockResponse, Error=ApiError> + Send>;

    /// Return metadata about an instance.
    fn get_metadata(&self, context: &Context) -> Box<Future<Item=GetMetadataResponse, Error=ApiError> + Send>;

    /// Return the list of (most recent) actions for an instance.
    fn list_instance_actions(&self, context: &Context) -> Box<Future<Item=ListInstanceActionsResponse, Error=ApiError> + Send>;

    /// Retrieves list of currently created limiters.
    fn list_limiters(&self, next_token: Option<String>, context: &Context) -> Box<Future<Item=ListLimitersResponse, Error=ApiError> + Send>;

    /// Creates new boot source. If boot source already exists, updates its state based on new input. May fail if update is not possible.
    fn put_guest_boot_source(&self, body: models::BootSource, context: &Context) -> Box<Future<Item=PutGuestBootSourceResponse, Error=ApiError> + Send>;

    /// Creates new drive with ID specified by 'drive_id' path parameter. If drive with specified ID already exists, updates its state based on new input. May fail if update is not possible.
    fn put_guest_drive_by_id(&self, drive_id: String, body: models::Drive, context: &Context) -> Box<Future<Item=PutGuestDriveByIDResponse, Error=ApiError> + Send>;

    /// Creates new network interface with ID specified by 'iface_id' path parameter. If network interface with specified ID already exists, updates its state based on new input. May fail if update is not possible.
    fn put_guest_network_interface_by_id(&self, iface_id: String, body: models::NetworkInterface, context: &Context) -> Box<Future<Item=PutGuestNetworkInterfaceByIDResponse, Error=ApiError> + Send>;

    /// Creates new vsock with ID specified by 'vsock_id' path parameter. If vsock with specified ID already exists, updates its state based on new input. May fail if update is not possible.
    fn put_guest_vsock_by_id(&self, vsock_id: String, body: models::Vsock, context: &Context) -> Box<Future<Item=PutGuestVsockByIDResponse, Error=ApiError> + Send>;

    /// Creates new limiter with ID specified by 'limiter_id' path parameter. If limiter with specified ID already exists, updates its state based on new input. May fail if update is not possible.
    fn update_limiter(&self, limiter_id: String, limiter: models::Limiter, context: &Context) -> Box<Future<Item=UpdateLimiterResponse, Error=ApiError> + Send>;

}

/// API without a `Context`
pub trait ApiNoContext {

    /// Applies limiter 'limiter_id' to drive 'drive_id'
    fn apply_limiter_to_drive(&self, drive_id: String, limiter_id: String) -> Box<Future<Item=ApplyLimiterToDriveResponse, Error=ApiError> + Send>;

    /// Applies limiter 'limiter_id' to network interface 'iface_id'
    fn apply_limiter_to_network_interface(&self, iface_id: String, limiter_id: String) -> Box<Future<Item=ApplyLimiterToNetworkInterfaceResponse, Error=ApiError> + Send>;

    /// Applies limiter 'limiter_id' to vsock 'vsock_id'
    fn apply_limiter_to_vsock(&self, vsock_id: String, limiter_id: String) -> Box<Future<Item=ApplyLimiterToVsockResponse, Error=ApiError> + Send>;

    /// Create an instance action.
    fn create_instance_action(&self, action_id: String, info: models::InstanceActionInfo) -> Box<Future<Item=CreateInstanceActionResponse, Error=ApiError> + Send>;

    /// Deletes drive with ID specified by 'drive_id' path parameter. Will clean up any resources associated with this drive.
    fn delete_guest_drive_by_id(&self, drive_id: String) -> Box<Future<Item=DeleteGuestDriveByIDResponse, Error=ApiError> + Send>;

    /// Deletes network interface with ID specified by 'iface_id' path parameter. Will clean up any resources associated with this network interface.
    fn delete_guest_network_interface_by_id(&self, iface_id: String) -> Box<Future<Item=DeleteGuestNetworkInterfaceByIDResponse, Error=ApiError> + Send>;

    /// Deletes vsock with ID specified by 'vsock_id' path parameter. Will clean up any resources associated with this vsock.
    fn delete_guest_vsock_by_id(&self, vsock_id: String) -> Box<Future<Item=DeleteGuestVsockByIDResponse, Error=ApiError> + Send>;

    /// Deletes limiter with ID specified by 'limiter_id' path parameter. Will clean up any resources associated with this limiter.
    fn delete_limiter(&self, limiter_id: String) -> Box<Future<Item=DeleteLimiterResponse, Error=ApiError> + Send>;

    /// Return general information about an instance.
    fn describe_instance(&self) -> Box<Future<Item=DescribeInstanceResponse, Error=ApiError> + Send>;

    /// Return detailed information about an action.
    fn describe_instance_action(&self, action_id: String) -> Box<Future<Item=DescribeInstanceActionResponse, Error=ApiError> + Send>;

    /// Retrieves limiter specified by 'limiter_id' path parameter.
    fn describe_limiter(&self, limiter_id: String) -> Box<Future<Item=DescribeLimiterResponse, Error=ApiError> + Send>;

    /// Get configured boot source.
    fn get_guest_boot_source(&self) -> Box<Future<Item=GetGuestBootSourceResponse, Error=ApiError> + Send>;

    /// Get guest drive by 'drive_id' path parameter.
    fn get_guest_drive_by_id(&self, drive_id: String) -> Box<Future<Item=GetGuestDriveByIDResponse, Error=ApiError> + Send>;

    /// All guest drives
    fn get_guest_drives(&self) -> Box<Future<Item=GetGuestDrivesResponse, Error=ApiError> + Send>;

    /// Get guest network interface by 'iface_id' path parameter.
    fn get_guest_network_interface_by_id(&self, iface_id: String) -> Box<Future<Item=GetGuestNetworkInterfaceByIDResponse, Error=ApiError> + Send>;

    /// All guest network interfaces
    fn get_guest_network_interfaces(&self) -> Box<Future<Item=GetGuestNetworkInterfacesResponse, Error=ApiError> + Send>;

    /// Get guest vsock by 'vsock_id' path parameter.
    fn get_guest_vsock_by_id(&self, vsock_id: String) -> Box<Future<Item=GetGuestVsockByIDResponse, Error=ApiError> + Send>;

    /// All guest vsocks
    fn get_guest_vsocks(&self) -> Box<Future<Item=GetGuestVsocksResponse, Error=ApiError> + Send>;

    /// Retrieves list of limiters IDs currently applied to the drive with 'drive_id'.
    fn get_limiters_for_guest_drive(&self, drive_id: String) -> Box<Future<Item=GetLimitersForGuestDriveResponse, Error=ApiError> + Send>;

    /// Retrieves list of limiters IDs currently applied to the network interface with 'iface_id'.
    fn get_limiters_for_guest_network_interface(&self, iface_id: String) -> Box<Future<Item=GetLimitersForGuestNetworkInterfaceResponse, Error=ApiError> + Send>;

    /// Retrieves list of limiters IDs currently applied to the vsock with 'vsock_id'.
    fn get_limiters_for_guest_vsock(&self, vsock_id: String) -> Box<Future<Item=GetLimitersForGuestVsockResponse, Error=ApiError> + Send>;

    /// Return metadata about an instance.
    fn get_metadata(&self) -> Box<Future<Item=GetMetadataResponse, Error=ApiError> + Send>;

    /// Return the list of (most recent) actions for an instance.
    fn list_instance_actions(&self) -> Box<Future<Item=ListInstanceActionsResponse, Error=ApiError> + Send>;

    /// Retrieves list of currently created limiters.
    fn list_limiters(&self, next_token: Option<String>) -> Box<Future<Item=ListLimitersResponse, Error=ApiError> + Send>;

    /// Creates new boot source. If boot source already exists, updates its state based on new input. May fail if update is not possible.
    fn put_guest_boot_source(&self, body: models::BootSource) -> Box<Future<Item=PutGuestBootSourceResponse, Error=ApiError> + Send>;

    /// Creates new drive with ID specified by 'drive_id' path parameter. If drive with specified ID already exists, updates its state based on new input. May fail if update is not possible.
    fn put_guest_drive_by_id(&self, drive_id: String, body: models::Drive) -> Box<Future<Item=PutGuestDriveByIDResponse, Error=ApiError> + Send>;

    /// Creates new network interface with ID specified by 'iface_id' path parameter. If network interface with specified ID already exists, updates its state based on new input. May fail if update is not possible.
    fn put_guest_network_interface_by_id(&self, iface_id: String, body: models::NetworkInterface) -> Box<Future<Item=PutGuestNetworkInterfaceByIDResponse, Error=ApiError> + Send>;

    /// Creates new vsock with ID specified by 'vsock_id' path parameter. If vsock with specified ID already exists, updates its state based on new input. May fail if update is not possible.
    fn put_guest_vsock_by_id(&self, vsock_id: String, body: models::Vsock) -> Box<Future<Item=PutGuestVsockByIDResponse, Error=ApiError> + Send>;

    /// Creates new limiter with ID specified by 'limiter_id' path parameter. If limiter with specified ID already exists, updates its state based on new input. May fail if update is not possible.
    fn update_limiter(&self, limiter_id: String, limiter: models::Limiter) -> Box<Future<Item=UpdateLimiterResponse, Error=ApiError> + Send>;

}

/// Trait to extend an API to make it easy to bind it to a context.
pub trait ContextWrapperExt<'a> where Self: Sized {
    /// Binds this API to a context.
    fn with_context(self: &'a Self, context: Context) -> ContextWrapper<'a, Self>;
}

impl<'a, T: Api + Sized> ContextWrapperExt<'a> for T {
    fn with_context(self: &'a T, context: Context) -> ContextWrapper<'a, T> {
         ContextWrapper::<T>::new(self, context)
    }
}

impl<'a, T: Api> ApiNoContext for ContextWrapper<'a, T> {

    /// Applies limiter 'limiter_id' to drive 'drive_id'
    fn apply_limiter_to_drive(&self, drive_id: String, limiter_id: String) -> Box<Future<Item=ApplyLimiterToDriveResponse, Error=ApiError> + Send> {
        self.api().apply_limiter_to_drive(drive_id, limiter_id, &self.context())
    }

    /// Applies limiter 'limiter_id' to network interface 'iface_id'
    fn apply_limiter_to_network_interface(&self, iface_id: String, limiter_id: String) -> Box<Future<Item=ApplyLimiterToNetworkInterfaceResponse, Error=ApiError> + Send> {
        self.api().apply_limiter_to_network_interface(iface_id, limiter_id, &self.context())
    }

    /// Applies limiter 'limiter_id' to vsock 'vsock_id'
    fn apply_limiter_to_vsock(&self, vsock_id: String, limiter_id: String) -> Box<Future<Item=ApplyLimiterToVsockResponse, Error=ApiError> + Send> {
        self.api().apply_limiter_to_vsock(vsock_id, limiter_id, &self.context())
    }

    /// Create an instance action.
    fn create_instance_action(&self, action_id: String, info: models::InstanceActionInfo) -> Box<Future<Item=CreateInstanceActionResponse, Error=ApiError> + Send> {
        self.api().create_instance_action(action_id, info, &self.context())
    }

    /// Deletes drive with ID specified by 'drive_id' path parameter. Will clean up any resources associated with this drive.
    fn delete_guest_drive_by_id(&self, drive_id: String) -> Box<Future<Item=DeleteGuestDriveByIDResponse, Error=ApiError> + Send> {
        self.api().delete_guest_drive_by_id(drive_id, &self.context())
    }

    /// Deletes network interface with ID specified by 'iface_id' path parameter. Will clean up any resources associated with this network interface.
    fn delete_guest_network_interface_by_id(&self, iface_id: String) -> Box<Future<Item=DeleteGuestNetworkInterfaceByIDResponse, Error=ApiError> + Send> {
        self.api().delete_guest_network_interface_by_id(iface_id, &self.context())
    }

    /// Deletes vsock with ID specified by 'vsock_id' path parameter. Will clean up any resources associated with this vsock.
    fn delete_guest_vsock_by_id(&self, vsock_id: String) -> Box<Future<Item=DeleteGuestVsockByIDResponse, Error=ApiError> + Send> {
        self.api().delete_guest_vsock_by_id(vsock_id, &self.context())
    }

    /// Deletes limiter with ID specified by 'limiter_id' path parameter. Will clean up any resources associated with this limiter.
    fn delete_limiter(&self, limiter_id: String) -> Box<Future<Item=DeleteLimiterResponse, Error=ApiError> + Send> {
        self.api().delete_limiter(limiter_id, &self.context())
    }

    /// Return general information about an instance.
    fn describe_instance(&self) -> Box<Future<Item=DescribeInstanceResponse, Error=ApiError> + Send> {
        self.api().describe_instance(&self.context())
    }

    /// Return detailed information about an action.
    fn describe_instance_action(&self, action_id: String) -> Box<Future<Item=DescribeInstanceActionResponse, Error=ApiError> + Send> {
        self.api().describe_instance_action(action_id, &self.context())
    }

    /// Retrieves limiter specified by 'limiter_id' path parameter.
    fn describe_limiter(&self, limiter_id: String) -> Box<Future<Item=DescribeLimiterResponse, Error=ApiError> + Send> {
        self.api().describe_limiter(limiter_id, &self.context())
    }

    /// Get configured boot source.
    fn get_guest_boot_source(&self) -> Box<Future<Item=GetGuestBootSourceResponse, Error=ApiError> + Send> {
        self.api().get_guest_boot_source(&self.context())
    }

    /// Get guest drive by 'drive_id' path parameter.
    fn get_guest_drive_by_id(&self, drive_id: String) -> Box<Future<Item=GetGuestDriveByIDResponse, Error=ApiError> + Send> {
        self.api().get_guest_drive_by_id(drive_id, &self.context())
    }

    /// All guest drives
    fn get_guest_drives(&self) -> Box<Future<Item=GetGuestDrivesResponse, Error=ApiError> + Send> {
        self.api().get_guest_drives(&self.context())
    }

    /// Get guest network interface by 'iface_id' path parameter.
    fn get_guest_network_interface_by_id(&self, iface_id: String) -> Box<Future<Item=GetGuestNetworkInterfaceByIDResponse, Error=ApiError> + Send> {
        self.api().get_guest_network_interface_by_id(iface_id, &self.context())
    }

    /// All guest network interfaces
    fn get_guest_network_interfaces(&self) -> Box<Future<Item=GetGuestNetworkInterfacesResponse, Error=ApiError> + Send> {
        self.api().get_guest_network_interfaces(&self.context())
    }

    /// Get guest vsock by 'vsock_id' path parameter.
    fn get_guest_vsock_by_id(&self, vsock_id: String) -> Box<Future<Item=GetGuestVsockByIDResponse, Error=ApiError> + Send> {
        self.api().get_guest_vsock_by_id(vsock_id, &self.context())
    }

    /// All guest vsocks
    fn get_guest_vsocks(&self) -> Box<Future<Item=GetGuestVsocksResponse, Error=ApiError> + Send> {
        self.api().get_guest_vsocks(&self.context())
    }

    /// Retrieves list of limiters IDs currently applied to the drive with 'drive_id'.
    fn get_limiters_for_guest_drive(&self, drive_id: String) -> Box<Future<Item=GetLimitersForGuestDriveResponse, Error=ApiError> + Send> {
        self.api().get_limiters_for_guest_drive(drive_id, &self.context())
    }

    /// Retrieves list of limiters IDs currently applied to the network interface with 'iface_id'.
    fn get_limiters_for_guest_network_interface(&self, iface_id: String) -> Box<Future<Item=GetLimitersForGuestNetworkInterfaceResponse, Error=ApiError> + Send> {
        self.api().get_limiters_for_guest_network_interface(iface_id, &self.context())
    }

    /// Retrieves list of limiters IDs currently applied to the vsock with 'vsock_id'.
    fn get_limiters_for_guest_vsock(&self, vsock_id: String) -> Box<Future<Item=GetLimitersForGuestVsockResponse, Error=ApiError> + Send> {
        self.api().get_limiters_for_guest_vsock(vsock_id, &self.context())
    }

    /// Return metadata about an instance.
    fn get_metadata(&self) -> Box<Future<Item=GetMetadataResponse, Error=ApiError> + Send> {
        self.api().get_metadata(&self.context())
    }

    /// Return the list of (most recent) actions for an instance.
    fn list_instance_actions(&self) -> Box<Future<Item=ListInstanceActionsResponse, Error=ApiError> + Send> {
        self.api().list_instance_actions(&self.context())
    }

    /// Retrieves list of currently created limiters.
    fn list_limiters(&self, next_token: Option<String>) -> Box<Future<Item=ListLimitersResponse, Error=ApiError> + Send> {
        self.api().list_limiters(next_token, &self.context())
    }

    /// Creates new boot source. If boot source already exists, updates its state based on new input. May fail if update is not possible.
    fn put_guest_boot_source(&self, body: models::BootSource) -> Box<Future<Item=PutGuestBootSourceResponse, Error=ApiError> + Send> {
        self.api().put_guest_boot_source(body, &self.context())
    }

    /// Creates new drive with ID specified by 'drive_id' path parameter. If drive with specified ID already exists, updates its state based on new input. May fail if update is not possible.
    fn put_guest_drive_by_id(&self, drive_id: String, body: models::Drive) -> Box<Future<Item=PutGuestDriveByIDResponse, Error=ApiError> + Send> {
        self.api().put_guest_drive_by_id(drive_id, body, &self.context())
    }

    /// Creates new network interface with ID specified by 'iface_id' path parameter. If network interface with specified ID already exists, updates its state based on new input. May fail if update is not possible.
    fn put_guest_network_interface_by_id(&self, iface_id: String, body: models::NetworkInterface) -> Box<Future<Item=PutGuestNetworkInterfaceByIDResponse, Error=ApiError> + Send> {
        self.api().put_guest_network_interface_by_id(iface_id, body, &self.context())
    }

    /// Creates new vsock with ID specified by 'vsock_id' path parameter. If vsock with specified ID already exists, updates its state based on new input. May fail if update is not possible.
    fn put_guest_vsock_by_id(&self, vsock_id: String, body: models::Vsock) -> Box<Future<Item=PutGuestVsockByIDResponse, Error=ApiError> + Send> {
        self.api().put_guest_vsock_by_id(vsock_id, body, &self.context())
    }

    /// Creates new limiter with ID specified by 'limiter_id' path parameter. If limiter with specified ID already exists, updates its state based on new input. May fail if update is not possible.
    fn update_limiter(&self, limiter_id: String, limiter: models::Limiter) -> Box<Future<Item=UpdateLimiterResponse, Error=ApiError> + Send> {
        self.api().update_limiter(limiter_id, limiter, &self.context())
    }

}

#[cfg(feature = "server")]
pub mod server;

// Re-export router() as a top-level name
#[cfg(feature = "server")]
pub use self::server::router;

pub mod models;
