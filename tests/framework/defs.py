"""Some common defines used in different modules of the testing framework."""
API_USOCKET_URL_PREFIX = 'http+unix://'
"""URL prefix used for the API calls through a UNIX domain socket."""
API_USOCKET_NAME = 'api.socket'
"""Default name for the socket used for API calls."""
FC_BINARY_NAME = 'firecracker'
"""Firecracker's binary name."""
JAILER_BINARY_NAME = 'jailer'
"""Jailer's binary name."""
JAILER_DEFAULT_CHROOT = '/srv/jailer'
"""The default location for the chroot."""
MAX_API_CALL_DURATION_MS = 100
"""Maximum accepted duration of an API call, in milliseconds."""
MICROVM_KERNEL_RELPATH = 'kernel/'
"""Relative path to the location of the kernel file."""
MICROVM_FSFILES_RELPATH = 'fsfiles/'
"""Relative path to the location of the filesystems."""
