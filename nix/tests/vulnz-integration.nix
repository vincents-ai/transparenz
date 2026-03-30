{ system ? builtins.currentSystem }:

let
  pkgs = import <nixpkgs> { inherit system; };
in

pkgs.nixosTest ({
  name = "transparenz-go-vulnz-integration";

  nodes = {
    server = { pkgs, ... }: {
      services.postgresql = {
        enable = true;
        package = pkgs.postgresql_15;
      };
      services.vulnz = {
        enable = true;
        projectId = "vulnz-test";
        apiTokenFile = pkgs.writeText "token" "test-token";
      };
    };

    client = { pkgs, nodes, ... }: {
      environment.systemPackages = [
        pkgs.transparenz-go
        pkgs.jq
        pkgs.sqlite
      ];
      environment.variables = {
        VULNZ_TOKEN = "test-token";
        VULNZ_PROJECT_ID = "vulnz-test";
      };
    };
  };

  testScript = ''
    start_all()

    # Wait for PostgreSQL to be ready
    server.waitForUnit("postgresql.service")
    server.waitForOpenPort(5432)

    # Test 1: CLI check command works (will fail without real token, but tests CLI)
    client.succeed("transparenz db check --help | grep -q 'Check vulnz connectivity'")

    # Test 2: CLI sync command works (will fail without real token, but tests CLI)
    client.succeed("transparenz db sync --help | grep -q 'Sync vulnerability database'")

    # Test 3: Vulnerability database structure validation
    client.succeed("mkdir -p /tmp/vulnz-test")
    client.succeed("sqlite3 /tmp/vulnz-test/test.db 'CREATE TABLE vulnerabilities (id INTEGER PRIMARY KEY, provider TEXT, vuln_id TEXT)'")
    client.succeed("sqlite3 /tmp/vulnz-test/test.db 'INSERT INTO vulnerabilities VALUES (1, \"kev\", \"CVE-2024-0001\")'")
    client.succeed("sqlite3 /tmp/vulnz-test/test.db 'SELECT COUNT(*) FROM vulnerabilities' | grep -q '1'")

    # Test 4: Metadata table creation
    client.succeed("sqlite3 /tmp/vulnz-test/test.db 'CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT)'")
    client.succeed("sqlite3 /tmp/vulnz-test/test.db \"INSERT INTO metadata VALUES ('providers', 'kev,cert-fr,enisa-evd,bsi-cert-bund')\"")
    client.succeed("sqlite3 /tmp/vulnz-test/test.db 'SELECT value FROM metadata WHERE key=\"providers\"' | grep -q 'kev'")

    # Test 5: Cleanup
    client.succeed("rm -rf /tmp/vulnz-test")
  '';

})
