/// Follows a C3 template in setting up the CPUID.
pub mod c3;
/// Follows a T2 template in setting up the CPUID.
pub mod t2;

use crate::common::{get_vendor_id, VENDOR_ID_INTEL};
use crate::transformer::Error;

pub fn validate_vendor_id() -> Result<(), Error> {
    let vendor_id = get_vendor_id().map_err(Error::InternalError)?;
    if &vendor_id != VENDOR_ID_INTEL {
        return Err(Error::InvalidVendor);
    }

    Ok(())
}
