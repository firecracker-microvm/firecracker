# Setting up a Development Environment for Firecracker

Firecracker uses KVM for the actual resource virtualization, hence setting up
a development environment requires either a bare-metal machine (with hardware
virtualization), or a virtual machine that supports nested virtualization.
The different options are outlined below. Once the environment is set up, one
can continue with the specific steps of setting up Firecracker (e.g., as
outlined in the [Getting Started](getting-started.md) instructions).

## Local

### Local Bare-Metal Machine

`[TODO]`

### Local Virtual Machine

`[TODO]`

## Cloud

### AWS

`[TODO]`

### GCP

One of the options to set up Firecracker for development purposes is to use a
VM on Google Compute Engine (GCE), which supports nested virtualization and
allows to run KVM. If you don't have a Google Cloud Platform (GCP) account,
you can find brief instructions in the Addendum [below](#addendum).

Here is a brief summary of steps to create such a setup (full instructions to
set up a Ubuntu-based VM on GCE with nested KVM enablement can be found in GCE
[documentation](https://cloud.google.com/compute/docs/instances/enable-nested-virtualization-vm-instances)).
 
  1. Select a GCP project and zone

     ```
     $ FC_PROJECT = your_name-firecracker
     $ FC_REGION = us-east1
     $ FC_ZONE = us-east1-b
     ```

     <details><summary>Click here for instructions to create a new project</summary>
     <p>
     It might be convenient to keep your Firecracker-related GCP resources in
     a separate project, so that you can keep track of resources more easily
     and remove everything easily once your are done.
     
     For convenience, give the project a unique name (e.g., 
     your_name-firecracker), so that GCP does not need to create a project
     id different than project name (by appending randomized numbers to the
     name you provide).
 
     ```
     $ gcloud projects create ${FC_PROJECT} --enable-cloud-apis --set-as-default
     ```

     </p>
     </details>
     
     ```
     $ gcloud config set project ${FC_PROJECT}
     $ gcloud config set compute/region ${FC_REGION}
     $ gcloud config set compute/zone ${FC_ZONE}
     ```

  1. The next step is to create a VM image able to run nested KVM (as outlined
     [here](https://cloud.google.com/compute/docs/instances/enable-nested-virtualization-vm-instances)).
     
     **IMPORTANT:** Notice that Firecracker requires a relatively new kernel,
     so you should use a recent Linux distribution image - such as Ubuntu 18
     (used in the commands below), or equivalent.

     ```
     $ FC_VDISK=disk-ub18
     $ FC_IMAGE=ub18-nested-kvm
     $ gcloud compute disks create ${FC_VDISK}\
        --image-project ubuntu-os-cloud --image-family ubuntu-1804-lts
     $ gcloud compute images create ${FC_IMAGE} --source-disk ${FC_VDISK}\
        --licenses "https://www.googleapis.com/compute/v1/projects/vm-options/global/licenses/enable-vmx"\
        --source-disk-zone ${FC_ZONE}
     ```

  1. Now we create the VM:

     ```
     $ FC_VM = firecracker-vm
     $ gcloud compute instances create ${FC_VM} --zone ${FC_ZONE}\
        --image ${FC_IMAGE}
     ```

  1. Connect to the VM via SSH.  

     ```
     $ gcloud compute ssh ${FC_VM}
     ```

     When doing it for the first time, a key-pair will be created for you
     (you will be propmpted for a passphrase - can just keep it empty) and
     uploaded to GCE. Done! You should see the prompt of the new VM: 

     ```
     ubuntu@firecracker-vm:~$
     ```  

  1. Verify that VMX is enabled, enable KVM

     ```
     $ grep -cw vmx /proc/cpuinfo
     1
     $ sudo setfacl -m u:${USER}:rw /dev/kvm
     $ [ -r /dev/kvm ] && [ -w /dev/kvm ] && echo "OK" || echo "FAIL"
     OK
     ```
  
  Now you can continue with the Firecracker [Getting Started](getting-started.md)
  instructions to install and configure Firecracker in the new VM.

#### Addendum

##### Setting up a Google Cloud Platform account

In a nutshell, setting up a GCP account involves the following steps:

  1. Log in to GCP [console](https://console.cloud.google.com/) with your
  Google credentials. If you don't have account, you will be prompted to join
  the trial.

  1. Install GCP CLI & SDK (full instructions can be found 
  [here](https://cloud.google.com/sdk/docs/quickstart-debian-ubuntu))

     ```
     $ export CLOUD_SDK_REPO="cloud-sdk-$(lsb_release -c -s)"
     $ echo "deb http://packages.cloud.google.com/apt $CLOUD_SDK_REPO main"\
       | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
     $ curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
     $ sudo apt-get update && sudo apt-get install -y google-cloud-sdk
     ```        

  1. Configure the `gcloud` CLI by running:

     ```
     $ gcloud init --console-only
     ```

     Follow the prompts to authenticate (open the provided link, authenticate,
     copy the token back to console) and select the default project.

### Microsoft Azure

`[TODO]`

