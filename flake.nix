{
  description = "gated-inference-rs — signature-gated LLM inference, reproducibly built via Nix";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane = {
      url = "github:ipetkov/crane";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane }:
    flake-utils.lib.eachSystem [
      "x86_64-linux"
      "aarch64-linux"
      "x86_64-darwin"
      "aarch64-darwin"
    ] (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        # Exact rustc pinned by rust-toolchain.toml → exact channel hash in flake.lock.
        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        nativeBuildInputs = with pkgs; [
          pkg-config
          cmake
          clang # llama-cpp-sys-2's build.rs invokes cmake → c/c++ toolchain.
          # Exports LIBCLANG_PATH + BINDGEN_EXTRA_CLANG_ARGS so llama-cpp-sys-2's
          # bindgen step can find libclang.so and the standard-library headers.
          rustPlatform.bindgenHook
        ];

        buildInputs = with pkgs; [
          secp256k1
        ] ++ lib.optionals stdenv.isDarwin [
          darwin.apple_sdk.frameworks.Security
          darwin.apple_sdk.frameworks.Accelerate
          darwin.apple_sdk.frameworks.Metal
          darwin.apple_sdk.frameworks.MetalKit
          darwin.apple_sdk.frameworks.Foundation
        ];

        # llama-cpp-sys-2 vendors llama.cpp source and compiles it via cmake in its
        # build.rs. That runs inside the Nix sandbox with only declared inputs, so
        # it's fully reproducible: same crate version + same cmake/clang → same libllama.
        commonArgs = {
          src = craneLib.cleanCargoSource ./.;
          strictDeps = true;
          inherit nativeBuildInputs buildInputs;
          # Force Cargo to honour Cargo.lock — no resolver drift between devs/CI.
          cargoExtraArgs = "--locked";
          # Skip tests that need weights / a network.
          doCheck = false;
        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        gatedInference = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "gated-inference";
        });

        # Deterministic OCI image. The digest is a pure function of the pinned inputs
        # (flake.lock + Cargo.lock + the source tree). Paste this digest into
        # tinfoil-config.yml; it will be stable across build hosts.
        dockerImage = pkgs.dockerTools.buildLayeredImage {
          name = "gated-inference-rs";
          tag = "latest";
          contents = [ gatedInference pkgs.cacert ];
          config = {
            Cmd = [ "${gatedInference}/bin/gated-inference-server" ];
            ExposedPorts = { "8080/tcp" = { }; };
            Env = [
              "PORT=8080"
              "RUST_LOG=info"
              "LLM_MODEL_PATH=/models/main.gguf"
            ];
          };
        };

        pythonClient = pkgs.python3.withPackages (ps: [
          ps.coincurve
          ps.requests
        ]);
      in
      {
        packages = {
          default = gatedInference;
          server = gatedInference;
          docker = dockerImage;
          python-client = pythonClient;
        };

        apps.default = {
          type = "app";
          program = "${gatedInference}/bin/gated-inference-server";
        };

        devShells.default = craneLib.devShell {
          checks = self.checks.${system};
          packages = with pkgs; [
            rust-analyzer
            pythonClient
            jq
          ];
        };

        checks = {
          build = gatedInference;
          clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          });
          fmt = craneLib.cargoFmt { src = ./.; };
          test = craneLib.cargoTest (commonArgs // {
            inherit cargoArtifacts;
          });
        };

        formatter = pkgs.nixpkgs-fmt;
      });
}
