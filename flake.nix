{
  description = "Firecracker dependecies for developer environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [
          (import rust-overlay)
        ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
      in
      with pkgs;
      {
        devShells.default = mkShell.override { stdenv = pkgs.clangStdenv; } {
          # Point bindgen to where the clang library would be
          LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
          # Make clang aware of a few headers (stdbool.h, wchar.h)
          BINDGEN_EXTRA_CLANG_ARGS = with pkgs; ''
            -isystem ${llvmPackages.libclang.lib}/lib/clang/${lib.getVersion clang}/include
            -isystem ${llvmPackages.libclang.out}/lib/clang/${lib.getVersion clang}/include
            -isystem ${glibc.dev}/include
          '';

          buildInputs = [
            cmake
            openssl
            pkg-config
            rust-bin.stable.latest.default
          ];
        };
      }
    );
}