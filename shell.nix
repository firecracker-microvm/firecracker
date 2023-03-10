let
  pkgs = import <nixpkgs> { };
  fenix = import (fetchTarball "https://github.com/nix-community/fenix/archive/main.tar.gz") { };
  poetryEnv = pkgs.poetry2nix.mkPoetryEnv {
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
              # buildinputs = (old.buildinputs or [ ]) ++ [ super.poetry ];
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
              # buildinputs = (old.buildinputs or [ ]) ++ [ super.setuptools ];
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
pkgs.mkShell {
  buildInputs = with fenix; with pkgs; [
    (fenix.combine [
      stable.rustc
      stable.cargo
      targets.x86_64-unknown-linux-musl.stable.rust-std
    ])
    poetryEnv
    python310Packages.setuptools
    python310Packages.setuptools-rust
  ];


  CPATH = with pkgs; lib.makeSearchPath "include" [ linuxHeaders ];
  LIBCLANG_PATH = with pkgs; lib.makeLibraryPath [ libclang ];
}

