{
  description = "Firecracker flake";

  inputs = {
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    let
      name = "firecracker";
    in
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        # Rust toolchain
        arch = builtins.head (pkgs.lib.strings.splitString "-" "${system}");
        target = "${arch}-unknown-linux-musl";
        rust_version = pkgs.rust-bin.stable.latest.default;
        rust_toolchain = (rust_version.override { targets = [ target ]; });

        # Python packages
        python_poetry = pkgs.poetry2nix.mkPoetryEnv {
          projectDir = ./tmp_poetry;

          python = pkgs.python311;

          overrides = pkgs.poetry2nix.defaultPoetryOverrides.extend
            (self: super: {
              argparse = super.argparse.overridePythonAttrs
                (
                  old: {
                    buildInputs = (old.buildInputs or [ ]) ++ [ super.setuptools ];
                  }
                );
              dataclasses = super.dataclasses.overridePythonAttrs
                (
                  old: {
                    buildInputs = (old.buildInputs or [ ]) ++ [ super.setuptools ];
                  }
                );
              gitlint = super.gitlint.overridePythonAttrs
                (
                  old: {
                    buildinputs = (old.buildinputs or [ ]) ++ [ super.setuptools ];
                  }
                );
              pytest-metadata = super.pytest-metadata.overridePythonAttrs
                (
                  old: {
                    nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ super.poetry ];
                  }
                );

              pathlib = super.pathlib.overridePythonAttrs
                (
                  old: {
                    buildinputs = (old.buildinputs or [ ]) ++ [ self.setuptools ];
                    nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ self.setuptools ];
                  }
                );

              aws-embedded-metrics = super.aws-embedded-metrics.overridePythonAttrs
                (
                  old: {
                    nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ super.setuptools ];
                  }
                );
              astroid = super.astroid.overridePythonAttrs
                (
                  old: {
                    nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ self.wrapt ];
                  }
                );
              pylint = super.pylint.overridePythonAttrs
                (
                  old: {
                    nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ self.dill self.wrapt ];
                  }
                );
            });
        };
      in
      {
        devShells = {
          default = pkgs.mkShell
            {
              buildInputs = [
                rust_toolchain
                python_poetry
              ];

              CPATH = with pkgs; lib.makeSearchPath "include" [ linuxHeaders ];
              LIBCLANG_PATH = with pkgs; lib.makeLibraryPath [ libclang ];
            };
          rust_only = pkgs.mkShell
            {
              buildInputs = [
                rust_toolchain
              ];

              CPATH = with pkgs; lib.makeSearchPath "include" [ linuxHeaders ];
              LIBCLANG_PATH = with pkgs; lib.makeLibraryPath [ libclang ];
            };
          python_only = pkgs.mkShell
            {
              buildInputs = [
                python_poetry
              ];

              CPATH = with pkgs; lib.makeSearchPath "include" [ linuxHeaders ];
              LIBCLANG_PATH = with pkgs; lib.makeLibraryPath [ libclang ];
            };
        };

        packages = {
          firecracker =
            (pkgs.makeRustPlatform {
              cargo = rust_toolchain;
              rustc = rust_toolchain;
            }).buildRustPackage {
              name = "firecracker";
              src = ./.;

              cargoLock = {
                lockFile = ./Cargo.lock;
                outputHashes."kvm-bindings-0.6.0" = "w+u8FJ31N8C2MHZdOvFyVn59R/Cu3z5JOXxGvWYYeRM=";
                outputHashes."micro_http-0.1.0" = "Mz/KoxUqaqB9BHru1I9pg0IYe4gwm6c6/tcMOC5aYyE=";
              };

              CPATH = with pkgs; lib.makeSearchPath "include" [ linuxHeaders ];
              LIBCLANG_PATH = with pkgs; lib.makeLibraryPath [ libclang ];
            };
        };

      });
}
