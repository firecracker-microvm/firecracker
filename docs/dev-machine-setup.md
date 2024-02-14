# Setting up a Development Environment for Firecracker

Firecracker uses KVM for the actual resource virtualization, hence setting up a
development environment requires either a bare-metal machine (with hardware
virtualization), or a virtual machine that supports nested virtualization. The
different options are outlined below. Once the environment is set up, one can
continue with the specific steps of setting up Firecracker (e.g., as outlined in
the [Getting Started](getting-started.md) instructions).

## Local

### Local Bare-Metal Machine

`[TODO]`

### Local Virtual Machine

#### macOS with VMware Fusion

Note that Firecracker development on macOS has no hard dependency on VMware
Fusion or Ubuntu. All that is required is a Linux VM that supports nested
virtualization. This is but one example of that setup:

1. Download and install
   [VMware Fusion](https://www.vmware.com/products/fusion/fusion-evaluation.html).
1. Download an [Ubuntu 18.04.2 LTS](https://www.ubuntu.com/download/desktop) ISO
   image.
1. Open VMware Fusion, open the **File** menu, and select **New...** to bring up
   the **Select the Installation Method** window.
1. Find the ISO image you downloaded in step 2, and drag it onto the VMware
   window opened in step 3.
1. You should now be at the **Create a New Virtual Machine** window. Ensure the
   Ubuntu 18.04.2 image is highlighted, and click **Continue**.
1. On the **Linux Easy Install** window, leave the **Use Easy Install** option
   checked, enter a password, and click **Continue**.
1. On the **Finish** window, click **Finish**, and save the `.vmwarevm` file if
   prompted.
1. After the VM starts up, open the **Virtual Machine** menu, and select **Shut
   Down**.
1. After the VM shuts down, open the **Virtual Machine** menu, and select
   **Settings...**.
1. From the settings window, select **Processors & Memory**, and then unfurl the
   **Advanced options** section.
1. Check the **Enable hypervisor applications in this virtual machine** option,
   close the settings window, open the **Virtual Machine** menu, and select
   **Start Up**.
1. If you receive a **Cannot connect the virtual device sata0:1 because no
   corresponding device is available on the host.** error, you can respond
   **No** to the prompt.
1. Once the VM starts up, log in as the user you created in step 6.
1. After logging in, open the **Terminal** app, and run
   `sudo apt install curl -y` to install cURL.
1. Now you can continue with the Firecracker
   [Getting Started](getting-started.md) instructions to install and configure
   Firecracker in the new VM.

## Cloud

### AWS

Firecracker development environment on AWS can be setup using bare metal
instances. Follow these steps to create a bare metal instance.

1. If you don't already have an AWS account, create one using the
   [AWS Portal](https://portal.aws.amazon.com/billing/signup).

1. Login to [AWS console](https://console.aws.amazon.com/console/home). You must
   select a region that offers bare metal EC2 instances. To check which regions
   support bare-metal, visit
   [Amazon EC2 On-Demand Pricing](https://aws.amazon.com/ec2/pricing/on-demand/)
   and look for `*.metal` instance types.

1. Click on `Launch a virtual machine` in `Build Solution` section.

1. Firecracker requires a relatively new kernel, so you should use a recent
   Linux distribution - such as
   `Ubuntu Server 22.04 LTS (HVM), SSD Volume Type`.

1. In `Step 2`, scroll to the bottom and select `c5.metal` instance type. Click
   on `Next: Configure Instance Details`.

1. In `Step 3`, click on `Next: Add Storage`.

1. In `Step 4`, click on `Next: Add Tags`.

1. In `Step 5`, click on `Next: Configure Security Group`.

1. In `Step 6`, take the default security group. This opens up port 22 and is
   needed so that you can ssh into the machine later. Click on
   `Review and Launch`.

1. Verify the details and click on `Launch`. If you do not have an existing key
   pair, then you can select `Create a new key pair` to create a key pair. This
   is needed so that you can use it later to ssh into the machine.

1. Click on the instance id in the green box. Copy `Public DNS` from the
   `Description` tab of the selected instance.

1. Login to the newly created instance:

   ```console
   ssh -i <ssh-key> ubuntu@<public-ip>
   ```

Now you can continue with the Firecracker [Getting Started](getting-started.md)
instructions to use Firecracker to create a microVM.

### GCP

One of the options to set up Firecracker for development purposes is to use a VM
on Google Compute Engine (GCE), which supports nested virtualization and allows
to run KVM. If you don't have a Google Cloud Platform (GCP) account, you can
find brief instructions in the Addendum [below](#addendum).

Here is a brief summary of steps to create such a setup (full instructions to
set up a Ubuntu-based VM on GCE with nested KVM enablement can be found in GCE
[documentation](https://cloud.google.com/compute/docs/instances/enable-nested-virtualization-vm-instances)).

1. Select a GCP project and zone

   ```console
   $ FC_PROJECT=your_name-firecracker
   $ FC_REGION=us-east1
   $ FC_ZONE=us-east1-b
   ```

   <details><summary>Click here for instructions to create a new project</summary>
    <p>
    It might be convenient to keep your Firecracker-related GCP resources in
    a separate project, so that you can keep track of resources more easily
    and remove everything easily once your are done.

   For convenience, give the project a unique name (e.g.,
   your_name-firecracker), so that GCP does not need to create a project id
   different than project name (by appending randomized numbers to the name you
   provide).

   ```console
   $ gcloud projects create ${FC_PROJECT} --enable-cloud-apis --set-as-default
   ```

   </p>
    </details>

   ```console
   $ gcloud config set project ${FC_PROJECT}
   $ gcloud config set compute/region ${FC_REGION}
   $ gcloud config set compute/zone ${FC_ZONE}
   ```

1. The next step is to create a VM image able to run nested KVM (as outlined
   [here](https://cloud.google.com/compute/docs/instances/nested-virtualization/enabling)).

1. Now we create the VM:

   Keep in mind that you will need an instance type that supports nested
   virtualization. `E2` and `N2D` instances will not work. If you want to use a
   `N1` instance (default in some regions), make sure it uses at least a
   processor of the `Haswell` architecture by specifying
   `--min-cpu-platform="Intel Haswell"` when you create the instance.
   Alternatively, use `N2` instances (such as with
   `--machine-type="n2-standard-2"`).

   ```console
   $ FC_VM=firecracker-vm
   $ gcloud compute instances create ${FC_VM} --enable-nested-virtualization \
   --zone=${FC_ZONE} --min-cpu-platform="Intel Haswell" \
   --machine-type=n1-standard-2
   ```

1. Connect to the VM via SSH.

   ```console
   $ gcloud compute ssh ${FC_VM}
   ```

   When doing it for the first time, a key-pair will be created for you (you
   will be propmpted for a passphrase - can just keep it empty) and uploaded to
   GCE. Done! You should see the prompt of the new VM:

   ```console
   [YOUR_USER_NAME]@firecracker-vm:~$
   ```

1. Verify that VMX is enabled, enable KVM

   ```console
   $ grep -cw vmx /proc/cpuinfo
   1
   $ apt-get update
   $ apt-get install acl
   $ sudo setfacl -m u:${USER}:rw /dev/kvm
   $ [ -r /dev/kvm ] && [ -w /dev/kvm ] && echo "OK" || echo "FAIL"
   OK
   ```

Depending on your machine you will get a different number, but anything except 0
means `KVM` is enabled.

Now you can continue with the Firecracker [Getting Started](getting-started.md)
instructions to install and configure Firecracker in the new VM.

#### Addendum

##### Setting up a Google Cloud Platform account

In a nutshell, setting up a GCP account involves the following steps:

1. Log in to GCP [console](https://console.cloud.google.com/) with your Google
   credentials. If you don't have account, you will be prompted to join the
   trial.

1. Install GCP CLI & SDK (full instructions can be found
   [here](https://cloud.google.com/sdk/docs/quickstart-debian-ubuntu)).

   ```console
   $ export CLOUD_SDK_REPO="cloud-sdk-$(lsb_release -c -s)"
   $ echo "deb http://packages.cloud.google.com/apt $CLOUD_SDK_REPO main" \
   | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
   $ curl https://packages.cloud.google.com/apt/doc/apt-key.gpg \
   | sudo apt-key add -
   $ sudo apt-get update && sudo apt-get install -y google-cloud-sdk
   ```

1. Configure the `gcloud` CLI by running:

   ```console
   $ gcloud init --console-only
   ```

   Follow the prompts to authenticate (open the provided link, authenticate,
   copy the token back to console) and select the default project.

### Microsoft Azure

`[TODO]`
