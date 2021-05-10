# Publishing a New Container Image

## About the Container Image

Firecracker uses a [Docker container](https://www.docker.com/) to standardize
the build process. This also fixes the build tools and dependencies to specific
versions. Every once in a while, something needs to be updated. To do this, a
new container image needs to be built locally, then published to the [AWS ECR](https://aws.amazon.com/ecr/)
registry. The Firecracker CI suite must also be updated to use the new image.

## Prerequisites

1. Access to the
   [`fcuvm` ECR repository](https://gallery.ecr.aws/firecracker/fcuvm).
1. The `docker` package installed locally. You should already have this if
   you've ever built Firecracker from source.
1. Access to both an `x86_64` and `aarch64` machines to build the container
   images.

## Steps

### `x86_64`

1. Login to the Docker organization in a shell. Make sure that your account has
   access to the repository:

    ```bash
    aws ecr-public get-login-password --region us-east-1 \
   | docker login --username AWS --password-stdin public.ecr.aws
    ```

1. Navigate to the Firecracker directory. Verify that you have the latest
   container image locally.

    ```bash
    docker images
    REPOSITORY                         TAG     IMAGE ID        CREATED         SIZE
    public.ecr.aws/firecracker/fcuvm   v26     8d00deb17f7a    2 weeks ago     2.41GB
    ```

1. Make your necessary changes, if any, to the
   [Dockerfile](https://docs.docker.com/engine/reference/builder/)(s). There's
   one for each supported architecture in the Firecracker source tree.

1. Commit the changes, if any.

1. Build a new container image with the updated Dockerfile.

   a: Additionally also checks for any outdated python packages
   and tries to update them. This makes sure that python packages
   versions are up to date with latest versions.

   ```bash
    tools/devtool build_devctr
   ```

   b: Builds a container image but skips performing updates of python
   packages. The container image will use the locked versions of python packages.

   ```bash
    tools/devtool build_devctr --no-python-package-update
   ```

1. Verify that the new image exists.

    ```bash
    docker images
    REPOSITORY                         TAG       IMAGE ID         CREATED       SIZE
    public.ecr.aws/firecracker/fcuvm   latest    1f9852368efb     2 weeks ago   2.36GB
    public.ecr.aws/firecracker/fcuvm   v26       8d00deb17f7a     2 weeks ago   2.41GB
    ```

1. Tag the new image with the next available version and the architecture
   you're on.

    ```bash
    docker tag 1f9852368efb public.ecr.aws/firecracker/fcuvm:v26_x86_64

    docker images
    REPOSITORY                         TAG          IMAGE ID       CREATED
    public.ecr.aws/firecracker/fcuvm   latest       1f9852368efb   1 week ago
    public.ecr.aws/firecracker/fcuvm   v27_x86_64   1f9852368efb   1 week ago
    public.ecr.aws/firecracker/fcuvm   v26          8d00deb17f7a   2 weeks ago
    ```

1. Push the image.

    ```bash
    docker push public.ecr.aws/firecracker/fcuvm:v27_x86_64
    ```

### `aarch64`

Login to the `aarch64` build machine.

Steps 1-4 are identical across architectures, change `x86_64` to `aarch64`.

Then continue with the above steps:

1. Build a new container image with the updated Dockerfile.

    ```bash
    tools/devtool build_devctr
    ```

1. Verify that the new image exists.

    ```bash
    docker images
    REPOSITORY                         TAG        IMAGE ID            CREATED
    public.ecr.aws/firecracker/fcuvm   latest     1f9852368efb        2 minutes ago
    public.ecr.aws/firecracker/fcuvm   v26        8d00deb17f7a        2 weeks ago
    ```

1. Tag the new image with the next available version and the architecture
   you're on.

    ```bash
    docker tag 1f9852368efb public.ecr.aws/firecracker/fcuvm:v26_aarch64

    docker images
    REPOSITORY                         TAG            IMAGE ID
    public.ecr.aws/firecracker/fcuvm   latest         1f9852368efb
    public.ecr.aws/firecracker/fcuvm   v27_aarch64    1f9852368efb
    public.ecr.aws/firecracker/fcuvm   v26            8d00deb17f7a
    ```

1. Push the image.

    ```bash
    docker push public.ecr.aws/firecracker/fcuvm:v27_aarch64
    ```

1. Create a manifest to point the latest container version to each specialized
   image, per architecture.

    ```bash
    docker manifest create public.ecr.aws/firecracker/fcuvm:v27 \
        public.ecr.aws/firecracker/fcuvm:v27_x86_64 public.ecr.aws/firecracker/fcuvm:v27_aarch64

    docker manifest push public.ecr.aws/firecracker/fcuvm:v27
    ```

1. Update the image tag in the
   [`devtool` script](https://github.com/firecracker-microvm/firecracker/blob/main/tools/devtool).
   Commit and push the change.

    ```bash
    PREV_TAG=v26
    CURR_TAG=v27
    sed -i "s%DEVCTR_IMAGE_TAG=\"$PREV_TAG\"%DEVCTR_IMAGE_TAG=\"$CURR_TAG\"%" tools/devtool
    ```

## Troubleshooting

Check out the
[`rust-vmm-container` readme](https://github.com/rust-vmm/rust-vmm-container)
for additional troubleshooting steps and guidelines.

### I can't push the manifest

```bash
docker manifest is only supported when experimental cli features are enabled
```

See
[this article](https://medium.com/@mauridb/docker-multi-architecture-images-365a44c26be6)
for explanations and fix.

### How to test the image after pushing it to the Docker registry

Either fetch and run it locally on another machine than the one you used to
build it, or clean up any artifacts from the build machine and fetch.

```bash
docker system prune -a

docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE

tools/devtool shell
[Firecracker devtool] About to pull docker image public.ecr.aws/firecracker/fcuvm:v15
[Firecracker devtool] Continue?
```

### I don't have access to the AWS ECR registry

```bash
docker push public.ecr.aws/firecracker/fcuvm:v27
The push refers to repository [public.ecr.aws/firecracker/fcuvm]
e2b5ee0c4e6b: Preparing
0fbb5fd5f156: Preparing
...
a1aa3da2a80a: Waiting
denied: requested access to the resource is denied
```

Only a Firecracker maintainer can update the container image. If you are one,
ask a member of the team to add you to the AWS ECR repository and retry.

### I pushed the wrong tag

Tags can be deleted from the [AWS ECR interface](https://aws.amazon.com/ecr/).

Also, pushing the same tag twice will overwrite the initial content.

### I did everything right and nothing works anymore

If you see unrelated `Python` errors, it's likely because the dev container
pulls `Python 3` at build time. `Python 3` means different minor versions on
different platforms, and is not backwards compatible. So it's entirely possible
that `docker build` has pulled in unwanted `Python` dependencies.

To include **only your** changes, an alternative to the method described above
is to make the changes *inside* the container, instead of in the `Dockerfile`.

Let's say you want to update
[`cargo-audit`](https://github.com/RustSec/cargo-audit) (random example).

1. Enter the container as `root`.

    ```bash
    tools/devtool shell -p
    ```

1. Make the changes locally. Do not exit the container.

    ```bash
    cargo install cargo-audit --force
    ```

1. Find your running container.

    ```bash
    docker ps
    CONTAINER ID        IMAGE               COMMAND             CREATED
    e9f0487fdcb9        fcuvm:v14       "bash"              53 seconds ago
    ```

1. Commit the modified container to a new image. Use the `container ID`.

    ```bash
    docker commit e9f0487fdcb9 fcuvm:v15_x86_64
    ```

    ```bash
    docker image ls
    REPOSITORY      TAG                 IMAGE ID            CREATED
    fcuvm           v15_x86_64          514581e654a6        18 seconds ago
    fcuvm           v14                 c8581789ead3        2 months ago
    ```

1. Repeat for `aarch64`.

1. Create and push the manifest.
