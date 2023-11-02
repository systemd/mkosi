import tempfile
import textwrap
import os

from mkosi.state import MkosiState
from mkosi.run import bwrap
from mkosi.util import INVOKING_USER


def setup_nix(state: MkosiState) -> None:

    (state.root / "etc/nixos").mkdir(parents=True, exist_ok=True)
    (state.root / "etc/nixos/flake.nix").write_text(
        textwrap.dedent(
            """\
            {
                inputs.nixpkgs.url = github:NixOS/nixpkgs/%(release)s;

                outputs = { self, nixpkgs }: {
                    nixosConfigurations.nixos = nixpkgs.lib.nixosSystem {
                        system = "x86_64-linux";
                        modules = [ ./configuration.nix ];
                    };
                };
            }
            """ % dict(release=state.config.release)
        )
    )

    (state.root / "etc/nixos/configuration.nix").write_text(
        textwrap.dedent(
        """\
        { config, lib, pkgs , ... }:

        {
            boot.loader.grub.enable = false;
            boot.initrd.enable = false;
            boot.kernel.enable = false;
            system.stateVersion = "23.05";

            environment.systemPackages = with pkgs; [
                vim
            ];
        }
        """
        )
    )


def invoke_nix(state: MkosiState) -> None:
    bwrap([
        "nix",
        "--experimental-features", "nix-command flakes",
        "build",
        "$flake#nixosConfigurations.nixos.config.system.build.toplevel",
         "--store", state.root,
         "--extra-substituters", "auto?trusted=1",
         "--option", "build-users-group", str(INVOKING_USER.uid),
         "-vvv",
    ], network=True, env={"NIX_PATH": ""} | state.config.environment)

        # bwrap([
        #     "nixos-install",
        #     "--root", state.root,
        #     "--flake", state.root / "etc/nixos/flake.nix#nixos",
        #     "--no-channel-copy",
        #     "--show-trace",
        #     "--option", "build-users-group", "root",
        #     "--no-bootloader",
        # ],
        # )
