{
  inputs = {
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "nixpkgs/nixos-unstable";
  };

  outputs = { self, fenix, flake-utils, nixpkgs }:
    flake-utils.lib.eachDefaultSystem (system: {
      packages.default =
        let
          arch = builtins.head(pkgs.lib.strings.splitString "-" "${system}");
          target = "${arch}-unknown-linux-musl";
          toolchain = with fenix.packages.${system}; combine [
            stable.cargo
            stable.rustc
            targets.${target}.stable.rust-std
          ];
          pkgs = nixpkgs.legacyPackages.${system};
        in

        (pkgs.makeRustPlatform {
          cargo = toolchain;
          rustc = toolchain;
        }).buildRustPackage {

          CPATH = with pkgs; lib.makeSearchPath "include" [ linuxHeaders ];
          LIBCLANG_PATH = with pkgs; lib.makeLibraryPath [ libclang ];

          pname = "firecracker";
          version = "0.1.2";

          src = ./.;

          cargoLock.lockFile = ./Cargo.lock;
          cargoLock.outputHashes."kvm-bindings-0.6.0" = "w+u8FJ31N8C2MHZdOvFyVn59R/Cu3z5JOXxGvWYYeRM=";
          cargoLock.outputHashes."micro_http-0.1.0" = "Mz/KoxUqaqB9BHru1I9pg0IYe4gwm6c6/tcMOC5aYyE=";
        };
    });
}
