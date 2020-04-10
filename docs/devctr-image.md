# Publishing a New Container Image

## What's the Container Image?

Firecracker uses a [Docker container](https://www.docker.com/) to standardize
the build process. This also fixes the build tools and dependencies to specific
versions. Every once in a while, something needs to be updated. To do this, a
new container image needs to be built locally, then published to the Docker
registry. The Firecracker CI suite must also be updated to use the new image.

## Prerequisites

1. A Docker account. You must create this by yourself on
   [Docker hub](https://hub.docker.com/).
1. Access to the
   [`fcuvm` Docker organization](https://cloud.docker.com/u/fcuvm/).
1. The `docker` package installed locally. You should already have this if
   you've ever built Firecracker from source.
1. Access to both an `x86_64` and `aarch64` machines to build the container
   images.

## Steps

### `x86_64`

1. Login to the Docker organization in a shell. Use your username and password
(not `fcuvm`).

    ```bash
    docker login
    ```

1. Navigate to the Firecracker directory. Verify that you have the latest
   container image locally.

    ```bash
    docker images
    REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
    fcuvm/dev           v14                 9bbc159ad600        2 months ago        2.31GB
    ```

1. Make your necessary changes, if any, to the
   [Dockerfile](https://docs.docker.com/engine/reference/builder/)(s). There's
   one for each supported architecture in the Firecracker source tree.

1. Commit the changes, if any.

1. Build a new container image with the updated Dockerfile.

   ```bash
    docker build -t fcuvm/dev -f tools/devctr/Dockerfile.x86_64 .
    ```

1. Verify that the new image exists.

    ```bash
    docker images
    REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
    fcuvm/dev           latest              402b87586d11        5 minutes ago       2.31GB
    fcuvm/dev           v14                 9bbc159ad600        2 months ago        2.31GB
    ```

1. Tag the new image with the next available version and the architecture
   you're on.

    ```bash
    docker tag 402b87586d11 fcuvm/dev:v15_x86_64

    docker images
    REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
    fcuvm/dev           latest              402b87586d11        5 minutes ago       2.31GB
    fcuvm/dev           v15_x86_64          402b87586d11        5 minutes ago       2.31GB
    fcuvm/dev           v14                 9bbc159ad600        2 months ago        2.31GB
    ```

1. Push the image.

    ```bash
    docker push fcuvm/dev:v15_x86_64
    ```

### `aarch64`

Login to the `aarch64` build machine.

Steps 1-4 are identical across architectures, change `x86_64` to `aarch64`.

Then:

5. Build a new container image with the updated Dockerfile.

    ```bash
    docker build -t fcuvm/dev -f tools/devctr/Dockerfile.aarch64  .
    ```

5. Verify that the new image exists.

    ```bash
    docker images
    REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
    fcuvm/dev           latest              402b87586d11        5 minutes ago       2.31GB
    fcuvm/dev           v14                 c8581789ead3        2 months ago        2.31GB
    ```

5. Tag the new image with the next available version and the architecture
   you're on.

    ```bash
    docker tag 402b87586d11 fcuvm/dev:v15_aarch64
    ```

    ```bash
    docker images
    REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
    fcuvm/dev           latest              402b87586d11        5 minutes ago       2.31GB
    fcuvm/dev           v15_aarch64         402b87586d11        5 minutes ago       2.31GB
    fcuvm/dev           v14                 c8581789ead3        2 months ago        2.31GB
    ```

5. Push the image.

    ```bash
    docker push fcuvm/dev:v15_aarch64
    ```

5. Create a manifest to point the latest container version to each specialized
   image, per architecture.

    ```bash
    docker manifest create fcuvm/dev:v15 fcuvm/dev:v15_x86_64 fcuvm/dev:v15_aarch64
    docker manifest push fcuvm/dev:v15
    ```

5. Update the image tag in the
   [`devtool` script](https://github.com/firecracker-microvm/firecracker/blob/master/tools/devtool).
   Commit and push the change.

    ```bash
    sed -i 's%DEVCTR_IMAGE="fcuvm/dev:v14"%DEVCTR_IMAGE="fcuvm/dev:v15"%' tools/devtool
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

### How can I test the image after pushing it to the Docker registry?

Either fetch and run it locally on another machine than the one you used to
build it, or clean up any artifacts from the build machine and fetch.

```bash
docker system prune -a

docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE

tools/devtool shell
[Firecracker devtool] About to pull docker image fcuvm/dev:v15
[Firecracker devtool] Continue?
```

### I don't have access to the Docker registry

```bash
docker push fcuvm/dev:v15
The push refers to repository [docker.io/fcuvm/dev]
e2b5ee0c4e6b: Preparing
0fbb5fd5f156: Preparing
...
a1aa3da2a80a: Waiting
denied: requested access to the resource is denied
```

Only a Firecracker maintainer can update the container image. If you are one,
ask a member of the team to add you to the `fcuvm` organization and retry.

### I pushed the wrong tag

Tags can be deleted from the
[Docker's repository WebUI](https://cloud.docker.com/u/fcuvm/repository/registry-1.docker.io/fcuvm/dev/tags).

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
    CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
    e9f0487fdcb9        fcuvm/dev:v14       "bash"              53 seconds ago      Up 52 seconds                           zen_beaver
    ```

1. Commit the modified container to a new image. Use the `container ID`.

    ```bash
    docker commit e9f0487fdcb9 fcuvm/dev:v15_x86_64
    ```

    ```bash
    docker image ls
    REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
    fcuvm/dev           v15_x86_64          514581e654a6        18 seconds ago      2.31GB
    fcuvm/dev           v14                 c8581789ead3        2 months ago        2.31GB
    ```

1. Repeat for `aarch64`.

1. Create and push the manifest.
