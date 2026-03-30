{ system ? builtins.currentSystem }:

let
  pkgs = import <nixpkgs> { inherit system; };
in
pkgs.nixosTest ({
  name = "transparenz-go-integration";

  nodes.machine = { pkgs, ... }: {
    environment.systemPackages = [
      pkgs.transparenz-go
    ];
  };

  testScript = ''
    machine.succeed("transparenz --help")
    machine.succeed("transparenz version")
    machine.succeed("transparenz generate --help")
  '';
})
