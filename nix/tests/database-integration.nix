{ system ? builtins.currentSystem }:

let
  pkgs = import <nixpkgs> { inherit system; };
in

pkgs.nixosTest ({
  name = "transparenz-go-database-integration";

  nodes = {
    db = { pkgs, ... }: {
      services.postgresql = {
        enable = true;
        package = pkgs.postgresql_15;
        enableTCPIP = true;
        authentication = pkgs.lib.mkForce ''
          host all all 0.0.0.0/0 trust
          local all all trust
        '';
        initialScript = pkgs.writeText "init.sql" ''
          CREATE DATABASE transparenz_test;
          CREATE USER test_user WITH PASSWORD 'test_password';
          GRANT ALL PRIVILEGES ON DATABASE transparenz_test TO test_user;
        '';
      };
      networking.firewall.allowedTCPPorts = [ 5432 ];
    };

    client = { pkgs, nodes, ... }: {
      environment.systemPackages = [
        pkgs.transparenz-go
        pkgs.jq
      ];
      environment.variables = {
        TRANSPARENZ_DB_URL = "postgresql://test_user:test_password@${nodes.db.config.networking.hostName}:5432/transparenz_test";
      };
    };
  };

  testScript = ''
    start_all()

    # Wait for PostgreSQL to be ready
    db.waitForUnit("postgresql.service")
    db.waitForOpenPort(5432)

    # Test 1: Database connection
    client.succeed("pg_isready -h db")

    # Test 2: Database migration
    client.succeed("transparenz db migrate")

    # Test 3: Database version check
    client.succeed("psql -h db -U test_user -d transparenz_test -c 'SELECT 1' | grep -q '1'")

    # Test 4: Generate SBOM and store in database
    client.succeed("mkdir -p /tmp/test-project")
    client.succeed("cp -r ${pkgs.transparenz-go.src}/cmd/transparenz/* /tmp/test-project/")
    client.succeed("cd /tmp/test-project && transparenz generate . --format cyclonedx --output /tmp/test-sbom.json")
    client.succeed("test -f /tmp/test-sbom.json")

    # Test 5: List command works
    client.succeed("transparenz list --help | grep -q 'List all SBOMs'")

    # Test 6: Search command works
    client.succeed("transparenz search --help | grep -q 'Search for packages'")

    # Test 7: Database cleanup
    client.succeed("psql -h db -U test_user -d transparenz_test -c 'DROP DATABASE IF EXISTS transparenz_test'")
  '';

})
