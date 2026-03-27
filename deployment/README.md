# Transparenz-Go Deployment Guide

Production deployment for the Go-based Transparenz SBOM generator.

## Quick Start

### Build Docker Image

```bash
# Build production image
docker build -f deployment/docker/Dockerfile.production -t transparenz-go:1.0.0 .

# Image size: ~18-22MB (static binary + CA certs)
docker images transparenz-go:1.0.0
```

### Deploy to Kubernetes

```bash
# Create namespace
kubectl create namespace transparenz-go

# Deploy
kubectl apply -f deployment/kubernetes/deployment.yaml

# Verify
kubectl get pods -n transparenz-go
```

### Run Locally

```bash
# Using Docker
docker run --rm transparenz-go:1.0.0 generate /path/to/project

# Direct binary
./transparenz generate --format spdx --output sbom.json .
```

## Key Features

- **Minimal Size**: ~20MB Docker image (scratch-based)
- **Zero Dependencies**: Static binary, no runtime deps
- **Native Performance**: Go implementation with native Syft/Grype
- **Kubernetes-Ready**: Runs as non-root, read-only filesystem

## Deployment Commands

### Development
```bash
kubectl apply -f deployment/kubernetes/deployment.yaml -n dev
```

### Production
```bash
kubectl apply -f deployment/kubernetes/deployment.yaml -n prod
kubectl scale deployment transparenz-go --replicas=5 -n prod
```

## Integration with Python Service

Use transparenz-go as a faster alternative for batch SBOM generation:

```bash
# In Kubernetes Job
apiVersion: batch/v1
kind: Job
metadata:
  name: sbom-batch-job
spec:
  template:
    spec:
      containers:
        - name: transparenz-go
          image: ghcr.io/deutschland-stack/transparenz-go:1.0.0
          command: ["/transparenz", "generate", "--batch", "/data"]
          volumeMounts:
            - name: data
              mountPath: /data
      restartPolicy: Never
```

## Performance

- **Speed**: 10-50x faster than Python implementation for large codebases
- **Memory**: ~50MB typical usage
- **Concurrency**: Native Go concurrency for parallel processing

## License

Apache-2.0
