# Transparenz-Go Deployment Guide

## Production Deployment Instructions

This guide covers deploying the Transparenz Go binary in production environments.

## Deployment Methods

### 1. Single Binary Deployment (Recommended)

The simplest deployment method - just copy the binary:

```bash
# Download the latest release
curl -L https://github.com/deutschland-stack/transparenz-go/releases/latest/download/transparenz-linux-amd64 -o transparenz
chmod +x transparenz
sudo mv transparenz /usr/local/bin/

# Verify installation
transparenz --version
```

**Advantages:**
- Zero dependencies (static binary with embedded Syft/Grype libraries)
- No Python runtime required
- No package manager needed
- No external Syft/Grype binaries required
- Works on minimal systems

**Supported Platforms:**
- Linux (amd64, arm64)
- macOS (amd64, arm64)
- Windows (amd64, arm64)

### 2. Docker Deployment

Use the official Docker image (FROM scratch, <10MB):

```bash
# Pull image
docker pull ghcr.io/deutschland-stack/transparenz:latest

# Run generate command
docker run --rm -v $(pwd):/workspace ghcr.io/deutschland-stack/transparenz:latest \
  generate /workspace --format spdx --output /workspace/sbom.json

# Run with database
docker run --rm \
  -e DATABASE_URL="postgresql://user:pass@host:5432/transparenz" \
  -v $(pwd):/workspace \
  ghcr.io/deutschland-stack/transparenz:latest \
  generate /workspace --format spdx --save
```

**Docker Compose Example:**

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: transparenz
      POSTGRES_PASSWORD: transparenz_secret
      POSTGRES_DB: transparenz
    volumes:
      - pgdata:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  transparenz:
    image: ghcr.io/deutschland-stack/transparenz:latest
    depends_on:
      - postgres
    environment:
      DATABASE_URL: "postgresql://transparenz:transparenz_secret@postgres:5432/transparenz"
    volumes:
      - ./projects:/projects
    command: ["generate", "/projects", "--format", "spdx", "--save"]

volumes:
  pgdata:
```

### 3. Nix Flake Deployment

For NixOS or systems with Nix installed:

```bash
# Run directly via flake
nix run github:deutschland-stack/transparenz-go -- generate .

# Install to profile
nix profile install github:deutschland-stack/transparenz-go

# Add to NixOS configuration.nix
environment.systemPackages = [
  (import (builtins.fetchTarball {
    url = "https://github.com/deutschland-stack/transparenz-go/archive/main.tar.gz";
  })).packages.${pkgs.system}.default
];
```

### 4. Homebrew (macOS/Linux)

```bash
brew tap deutschland-stack/transparenz
brew install transparenz
```

## Database Setup

Transparenz requires PostgreSQL 15+ for database operations.

### PostgreSQL Installation

**Debian/Ubuntu:**
```bash
sudo apt install postgresql-15 postgresql-client-15
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

**macOS:**
```bash
brew install postgresql@15
brew services start postgresql@15
```

**Docker:**
```bash
docker run -d \
  --name transparenz-db \
  -e POSTGRES_USER=transparenz \
  -e POSTGRES_PASSWORD=transparenz_secret \
  -e POSTGRES_DB=transparenz \
  -p 5432:5432 \
  -v pgdata:/var/lib/postgresql/data \
  postgres:15-alpine
```

### Database Configuration

1. Create database and user:

```sql
CREATE DATABASE transparenz;
CREATE USER transparenz_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE transparenz TO transparenz_user;
```

2. Set environment variable:

```bash
export DATABASE_URL="postgresql://transparenz_user:secure_password@localhost:5432/transparenz"
```

3. Run migrations (automatic on first use):

```bash
transparenz list  # First run will create schema
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://shift@localhost:5432/transparenz` |
| `LOG_LEVEL` | Logging level (debug, info, warn, error) | `info` |

## Production Configuration

### systemd Service (Linux)

Create `/etc/systemd/system/transparenz-worker.service`:

```ini
[Unit]
Description=Transparenz SBOM Generator Worker
After=postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=transparenz
Group=transparenz
WorkingDirectory=/opt/transparenz
Environment="DATABASE_URL=postgresql://transparenz_user:secure_password@localhost:5432/transparenz"
ExecStart=/usr/local/bin/transparenz generate /data/projects --format spdx --save
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable transparenz-worker
sudo systemctl start transparenz-worker
sudo systemctl status transparenz-worker
```

### Kubernetes Deployment

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: transparenz-config
data:
  DATABASE_URL: "postgresql://transparenz:password@postgres-service:5432/transparenz"

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: transparenz
  labels:
    app: transparenz
spec:
  replicas: 3
  selector:
    matchLabels:
      app: transparenz
  template:
    metadata:
      labels:
        app: transparenz
    spec:
      containers:
      - name: transparenz
        image: ghcr.io/deutschland-stack/transparenz:latest
        envFrom:
        - configMapRef:
            name: transparenz-config
        volumeMounts:
        - name: projects
          mountPath: /projects
        command: ["transparenz", "generate", "/projects", "--save"]
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: projects
        persistentVolumeClaim:
          claimName: projects-pvc
```

## CI/CD Integration

### GitLab CI

```yaml
# .gitlab-ci.yml
sbom_generate:
  stage: build
  image: ghcr.io/deutschland-stack/transparenz:latest
  variables:
    DATABASE_URL: "postgresql://transparenz:$DB_PASSWORD@postgres:5432/transparenz"
  services:
    - postgres:15-alpine
  before_script:
    - export POSTGRES_DB=transparenz
    - export POSTGRES_USER=transparenz
    - export POSTGRES_PASSWORD=$DB_PASSWORD
  script:
    - transparenz generate . --format spdx --output sbom.json --bsi-compliant
    - transparenz bsi-check sbom.json --output compliance-report.json
    - transparenz generate . --save  # Save to database
  artifacts:
    paths:
      - sbom.json
      - compliance-report.json
    reports:
      cyclonedx: sbom.json  # If using CycloneDX format
```

### GitHub Actions

```yaml
# .github/workflows/sbom.yml
name: Generate SBOM

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  sbom:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15-alpine
        env:
          POSTGRES_USER: transparenz
          POSTGRES_PASSWORD: transparenz
          POSTGRES_DB: transparenz
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - uses: actions/checkout@v4

      - name: Download Transparenz
        run: |
          curl -L https://github.com/deutschland-stack/transparenz-go/releases/latest/download/transparenz-linux-amd64 -o transparenz
          chmod +x transparenz
          sudo mv transparenz /usr/local/bin/

      - name: Generate SBOM
        env:
          DATABASE_URL: postgresql://transparenz:transparenz@localhost:5432/transparenz
        run: |
          transparenz generate . --format spdx --output sbom.json --bsi-compliant
          transparenz bsi-check sbom.json --output compliance-report.json

      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: |
            sbom.json
            compliance-report.json

      - name: Save to Database
        env:
          DATABASE_URL: postgresql://transparenz:transparenz@localhost:5432/transparenz
        run: transparenz generate . --save
```

### Jenkins Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any
    
    environment {
        DATABASE_URL = credentials('transparenz-db-url')
    }
    
    stages {
        stage('Setup') {
            steps {
                sh '''
                    curl -L https://github.com/deutschland-stack/transparenz-go/releases/latest/download/transparenz-linux-amd64 -o transparenz
                    chmod +x transparenz
                '''
            }
        }
        
        stage('Generate SBOM') {
            steps {
                sh './transparenz generate . --format spdx --output sbom.json --bsi-compliant'
            }
        }
        
        stage('BSI Compliance Check') {
            steps {
                sh './transparenz bsi-check sbom.json --output compliance-report.json'
            }
        }
        
        stage('Save to Database') {
            steps {
                sh './transparenz generate . --save'
            }
        }
        
        stage('Archive') {
            steps {
                archiveArtifacts artifacts: 'sbom.json,compliance-report.json', fingerprint: true
            }
        }
    }
}
```

## Performance Tuning

### Database Connection Pooling

GORM handles connection pooling automatically. Tune via environment:

```bash
# Note: connection pool settings are currently hardcoded; these env vars are not yet implemented
# Max open connections
export DB_MAX_OPEN_CONNS=25

# Max idle connections
export DB_MAX_IDLE_CONNS=5

# Connection max lifetime
export DB_CONN_MAX_LIFETIME=5m
```

### Parallel SBOM Generation

For bulk operations:

```bash
# Generate SBOMs for multiple projects in parallel
find /projects -type d -maxdepth 1 | \
  xargs -I {} -P 4 transparenz generate {} --format spdx --save
```

### Resource Requirements

**Minimum:**
- CPU: 1 core
- Memory: 256MB RAM
- Disk: 50MB (binary size varies by platform + working space)

**Recommended (production):**
- CPU: 2 cores
- Memory: 512MB RAM
- Disk: 1GB (binary size varies by platform + database)

## Security Considerations

### Binary Verification

Verify binary integrity using checksums:

```bash
# Download checksum file
curl -L https://github.com/deutschland-stack/transparenz-go/releases/latest/download/checksums.txt -o checksums.txt

# Verify binary
sha256sum -c checksums.txt --ignore-missing
```

### Database Security

1. **Use TLS for database connections:**

```bash
export DATABASE_URL="postgresql://user:pass@host:5432/transparenz?sslmode=require"
```

2. **Restrict database user privileges:**

```sql
REVOKE ALL ON DATABASE transparenz FROM PUBLIC;
GRANT CONNECT ON DATABASE transparenz TO transparenz_user;
GRANT USAGE ON SCHEMA public TO transparenz_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO transparenz_user;
```

3. **Use secrets management:**

```bash
# Kubernetes secret
kubectl create secret generic transparenz-db \
  --from-literal=url='postgresql://user:password@host:5432/transparenz'

# Use in pod
envFrom:
- secretRef:
    name: transparenz-db
```

### Network Security

**Firewall rules (iptables):**

```bash
# Allow PostgreSQL only from application server
sudo iptables -A INPUT -p tcp -s 10.0.1.0/24 --dport 5432 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 5432 -j DROP
```

**PostgreSQL pg_hba.conf:**

```
# Allow only application server
host    transparenz     transparenz_user     10.0.1.0/24     scram-sha-256
```

## Monitoring & Logging

### Logging Configuration

```bash
# Set log level
export LOG_LEVEL=info

# Log to file
transparenz generate . 2>&1 | tee -a /var/log/transparenz.log
```

### Prometheus Metrics (Future)

Planned metrics endpoint:

```
# HELP transparenz_sbom_generation_total Total SBOMs generated
# TYPE transparenz_sbom_generation_total counter
transparenz_sbom_generation_total{format="spdx"} 1234

# HELP transparenz_bsi_compliance_score BSI compliance score
# TYPE transparenz_bsi_compliance_score gauge
transparenz_bsi_compliance_score 0.573
```

### Health Checks

```bash
# Database health check
transparenz list --limit 1

# Exit code 0 = healthy
# Exit code non-zero = unhealthy
```

## Troubleshooting

### Common Issues

**1. "connection refused" error**

```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Check DATABASE_URL is correct
echo $DATABASE_URL

# Test connection manually
psql "$DATABASE_URL" -c "SELECT 1"
```

**2. "permission denied" on binary**

```bash
chmod +x transparenz
```

**3. Low BSI compliance scores**

```bash
# Use --bsi-compliant flag
transparenz generate . --bsi-compliant

# Check go.sum exists (for Go projects)
ls go.sum

# Check source has LICENSE files
find . -name LICENSE -o -name COPYING
```

## Backup & Recovery

### Database Backup

```bash
# Backup database
pg_dump -U transparenz_user transparenz > transparenz_backup.sql

# Restore database
psql -U transparenz_user transparenz < transparenz_backup.sql
```

### Automated Backups

```bash
# Add to crontab
0 2 * * * pg_dump -U transparenz_user transparenz | gzip > /backups/transparenz_$(date +\%Y\%m\%d).sql.gz

# Retention (keep 30 days)
find /backups -name "transparenz_*.sql.gz" -mtime +30 -delete
```

## Support

- GitHub Issues: https://github.com/deutschland-stack/transparenz-go/issues
- Documentation: https://github.com/deutschland-stack/transparenz-go/blob/main/README.md
- Python Version: https://github.com/deutschland-stack/transparenz

> **Commands reference:** See README.md for the full commands reference, including `enrich`, `submit`, and `db export`.

## License

AGPL-3.0-or-later
