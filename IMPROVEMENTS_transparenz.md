# transparenz - Interface Design Improvement Plan

## Current State Assessment

**Status**: Not interface-designed (uses concrete types)
**Effort Required**: Medium-Large

### Existing Interfaces

**None found** - transparenz primarily uses concrete struct types:

| Concrete Type | Location | Purpose |
|---------------|----------|---------|
| `bsi.Enricher` | `pkg/bsi/enricher.go:44` | BSI TR-03183-2 compliance enrichment |
| `sbom.Generator` | `pkg/sbom/generator.go:35` | SBOM generation using Syft |
| `sbom.VulnzMatcher` | `pkg/sbom/vulnz_matcher.go:48` | Vulnerability matching |
| `sbom.MatchIndex` | `pkg/sbom/vulnz_matcher.go:28` | Index for vulnerability matching |

### Current Usage Pattern

All components are used as concrete types:

```go
// pkg/bsi/enricher.go
func NewEnricher(sourcePath string) *Enricher { ... }

// pkg/sbom/generator.go
func NewGenerator(verbose bool) *Generator { ... }

// pkg/sbom/vulnz_matcher.go
func NewVulnzMatcher() *VulnzMatcher { ... }
```

No dependency injection - all code uses concrete return types.

## Required Refactoring

### 1. Extract SBOM Generator Interface (Priority: High)

**Problem**: `Generator` is used as concrete type throughout `cmd/` and `pkg/`.

**Solution**:
```go
// pkg/sbom/generator.go
type SBOMGenerator interface {
    // Generate creates an SBOM from the specified source
    Generate(ctx context.Context, source string, opts ...GenerateOption) (*sbom.SBOM, error)
    
    // SupportedFormats returns list of supported output formats
    SupportedFormats() []string
    
    // ValidateFormat checks if the format is supported
    ValidateFormat(format string) bool
}

type GenerateOption func(*GenerateConfig)

type GenerateConfig struct {
    Format string
    Scope  string
}

// Keep concrete type for internal implementation
type generator struct { /* ... */ }

func NewGenerator(verbose bool) SBOMGenerator {
    return &generator{verbose: verbose}
}
```

**Files to modify**:
- `pkg/sbom/generator.go` - extract interface, update constructor
- `cmd/generate.go` - accept `SBOMGenerator` interface
- `cmd/bsi.go` - accept `SBOMGenerator` interface
- All test files using `Generator`

### 2. Extract BSI Enricher Interface (Priority: High)

**Problem**: `Enricher` is used as concrete type, making testing difficult.

**Solution**:
```go
// pkg/bsi/enricher.go
type BSIEnricher interface {
    // Enrich adds BSI TR-03183-2 compliance data to an SBOM
    Enrich(sbom *sbom.SBOM) error
    
    // Validate checks if an SBOM meets BSI TR-03183-2 requirements
    Validate(sbom *sbom.SBOM) (*ComplianceResult, error)
    
    // EnrichWithBSD enriches an SBOM with BSD file-level annotations
    EnrichWithBSD(sbom *sbom.SBOM) error
}

type ComplianceResult struct {
    Compliant bool
    Findings  []BSIFinding
    Score     float64
}

// Keep concrete type
type enricher struct { /* ... */ }

func NewEnricher(sourcePath string) BSIEnricher {
    return &enricher{sourcePath: sourcePath}
}
```

**Files to modify**:
- `pkg/bsi/enricher.go` - extract interface, update constructor
- `cmd/bsi.go` - accept `BSIEnricher` interface
- `cmd/validate.go` - accept `BSIEnricher` interface
- All test files using `Enricher`

### 3. Extract Vulnerability Matcher Interface (Priority: High)

**Problem**: `VulnzMatcher` is used as concrete type.

**Solution**:
```go
// pkg/sbom/vulnz_matcher.go
type VulnerabilityMatcher interface {
    // Match matches SBOM components against vulnerability data
    Match(ctx context.Context, sbom *sbom.SBOM, vulnzData []VulnerabilityMatch) error
    
    // BuildIndex builds the match index from vulnerability data
    BuildIndex(vulnzData []VulnerabilityMatch) error
    
    // GetMatches returns matches for a specific component
    GetMatches(component SBOMComponent) []VulnerabilityMatch
}

// Keep concrete type
type vulnzMatcher struct { /* ... */ }

func NewVulnzMatcher() VulnerabilityMatcher {
    return &vulnzMatcher{
        matchIdx: NewMatchIndex(),
    }
}
```

**Files to modify**:
- `pkg/sbom/vulnz_matcher.go` - extract interface, update constructor
- Files using `VulnzMatcher`
- Test files

### 4. Extract Validator Interface (Priority: Medium)

**Problem**: BSI validation logic is embedded in `Enricher`.

**Solution**:
```go
// pkg/bsi/validator.go (new file)
type BSIValidator interface {
    Validate(sbom *sbom.SBOM) (*ValidationResult, error)
}

type ValidationResult struct {
    Valid    bool
    Findings []ValidationFinding
}
```

**Files to create/modify**:
- `pkg/bsi/validator.go` (new file)
- `pkg/bsi/enricher.go` - use `BSIValidator`

### 5. Add CLI Command Interface (Priority: Medium)

**Problem**: CLI commands don't use interfaces.

**Solution**:
```go
// cmd/command.go (new file)
type CLICommand interface {
    Execute(ctx context.Context, args []string) error
    Name() string
    Description() string
}

// Each command implements this interface
type GenerateCommand struct { /* ... */ }
type BSICommand struct { /* ... */ }
type ValidateCommand struct { /* ... */ }
```

**Files to modify**:
- `cmd/generate.go`
- `cmd/bsi.go`
- `cmd/validate.go`
- `cmd/root.go`

### 6. Create Dependency Injection Container (Priority: Low)

**Problem**: No dependency injection - all components created inline.

**Solution**:
```go
// pkg/container.go (new file)
type Container struct {
    Generator    sbom.SBOMGenerator
    Enricher     bsi.BSIEnricher
    Matcher      sbom.VulnerabilityMatcher
    // ... other dependencies
}

func NewContainer(opts ...ContainerOption) *Container { /* ... */ }
```

**Files to create**:
- `pkg/container.go`

## Implementation Order

1. **Phase 1** (3-4 hours): Extract `SBOMGenerator` interface
2. **Phase 2** (3-4 hours): Extract `BSIEnricher` interface
3. **Phase 3** (2-3 hours): Extract `VulnerabilityMatcher` interface
4. **Phase 4** (2-3 hours): Extract `BSIValidator` interface
5. **Phase 5** (2-3 hours): Add CLI Command interface
6. **Phase 6** (2-3 hours): Create Dependency Injection Container

**Total estimated effort**: 14-20 hours

## Testing Strategy

- Create mock implementations for each interface
- Update all existing tests to use interfaces
- Add interface-based unit tests
- Ensure integration tests still pass
- Use `testify/mock` or similar for mock generation

## Success Criteria

- [ ] `SBOMGenerator` interface extracted and used throughout
- [ ] `BSIEnricher` interface extracted and used throughout
- [ ] `VulnerabilityMatcher` interface extracted and used throughout
- [ ] `BSIValidator` interface extracted (optional)
- [ ] CLI commands use interfaces (optional)
- [ ] Dependency injection container created (optional)
- [ ] All existing tests pass with interface changes
- [ ] New mock-based tests added
- [ ] Documentation updated with interface usage examples

## Migration Notes

- This is a **breaking change** for any external code using transparenz as a library
- Consider using a deprecation period where both concrete types and interfaces are supported
- Tag a new major version (v2.0.0) after completion
