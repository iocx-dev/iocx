```mermaid
flowchart TD

    subgraph User Environment
        U[User / Analyst]
        CLI[IOCX CLI]
    end

    subgraph IOCX Engine
        DET[Detectors<br/>Transformers<br/>Enrichers]
        PE[PE Parser (pefile)]
        MAGIC[File Type Detection (python-magic)]
        CACHE[Local Cache]
    end

    subgraph Untrusted Input
        F[Untrusted File<br/>(binary, text, logs)]
    end

    U --> CLI
    CLI -->|Input path or stdin| F
    F -->|Read & Parse| MAGIC
    F -->|Binary parsing| PE
    MAGIC --> DET
    PE --> DET
    DET --> CACHE
    DET -->|Extracted IOCs| CLI
    CLI -->|JSON Output| U

    %% Threat Boundaries
    classDef boundary fill:#f0f0f0,stroke:#555,stroke-width:2px;
    class Untrusted Input boundary;
    class IOCX Engine boundary;
    class User Environment boundary;

    %% Threat Indicators
    F -. Potentially malicious content .-> DET
    F -. Potentially malformed binaries .-> PE

```

```mermaid
flowchart TD

    subgraph External Actors
        A[Attacker]
        U[User]
    end

    subgraph IOCX CLI
        CLI[CLI Frontend]
    end

    subgraph Engine
        DET[Detectors / Transformers]
        PE[PE Parser]
        MAGIC[File Type Detection]
        CACHE[Local Cache]
    end

    subgraph Data
        F[Untrusted Input File]
        O[JSON Output]
    end

    %% Data Flows
    U --> CLI
    CLI --> F
    F --> MAGIC
    F --> PE
    MAGIC --> DET
    PE --> DET
    DET --> CACHE
    DET --> O
    CLI --> O
    O --> U

    %% Threats
    A -. Supplies malformed binaries .-> F
    A -. Attempts parser abuse .-> PE
    A -. Attempts type confusion .-> MAGIC
    A -. Attempts detector bypass .-> DET

    %% Boundaries
    classDef boundary fill:#f0f0f0,stroke:#333,stroke-width:2px;
    class IOCX CLI boundary;
    class Engine boundary;
    class Data boundary;
```
