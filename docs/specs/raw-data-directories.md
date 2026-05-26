# **Design Decision: Why Only the Optional‑Header Validator Uses Raw Data Directories**

## **Summary**
PE files contain up to **16 data directory entries**, but the PE header also includes a field called **NumberOfRvaAndSizes**, which declares how many of those entries are valid.
This field can be **manipulated** in adversarial binaries.

To handle this safely and correctly:

- **Only the Optional Header validator** uses the **raw 16‑entry directory table**.
- **All other validators** use the **declared directory list** (`analysis.data_directories`), which is already truncated to `NumberOfRvaAndSizes` by pefile.

This separation is intentional and required for correctness.

---

# **1. Two Different Concepts of “Data Directories”**

## **1. Raw table (always 16 entries)**
- Comes directly from the Optional Header.
- Contains whatever bytes are in the file.
- May include garbage, uninitialized data, or attacker‑controlled values.
- Must be used when validating **header consistency**.

## **2. Declared directory list (0..NumberOfRvaAndSizes‑1)**
- Produced by pefile.
- Truncated to the declared count.
- Contains only directories the PE *claims* to have.
- Used for **semantic validation** (RVA mapping, Load Config, TLS, etc.).

These two lists serve different purposes and must not be mixed.

---

# **2. Why the Optional Header Validator Uses the Raw Table**

The field **NumberOfRvaAndSizes** can be abused:

- Declared count too small (hiding real directories)
- Declared count too large (>16)
- Declared count inconsistent with actual non‑zero entries

Only the raw 16‑entry table allows us to detect:

- **actual number of non‑zero directories**
- **mismatches between declared and actual**
- **invalid declared counts**

This is why the optional‑header validator uses:

- `internalMetadata.data_directories_raw`
- `internalMetadata.number_of_rva_and_sizes`

This validator is responsible for detecting **header lies**.

---

# **3. Why All Other Validators Use the Declared Directory List**

Once header consistency is checked, all other validators operate under **PE semantics**, not raw bytes.

According to the PE spec:

> Only the first *NumberOfRvaAndSizes* entries are valid.
> Entries beyond that must be ignored.

Therefore:

- `rva_graph`
- `load_config` validator
- `import` validator
- `resource` validator
- `TLS` validator
- etc.

must use:

```python
analysis.data_directories
```

This list:

- is truncated to the declared count
- contains only meaningful entries
- is named (e.g., `"IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"`)
- matches how Windows loaders interpret the file

Validating undeclared directories would:

- produce false positives
- violate the PE spec
- break normal binaries
- break most fixtures
- misinterpret garbage bytes as real directories

So these validators intentionally ignore the raw table.

---

# **4. Example: Why Fixture 32 Works Correctly**

Fixture 32:

- Writes **2** real directory entries
- Declares **1** directory

### Optional‑header validator:
- Sees raw table → detects mismatch → flags it
- ✔ Correct

### Other validators:
- See declared list of length 1
- Validate only directory 0
- Ignore directory 1 (undeclared)
- ✔ Correct

This is exactly how Windows behaves.

---

# **5. Architectural Responsibilities**

| Component | Uses Raw Table? | Purpose |
|----------|------------------|---------|
| **Optional Header Validator** | **Yes** | Detect header inconsistencies, adversarial manipulation |
| **rva_graph** | No | Validate RVA ranges, section mapping, overlay |
| **Load Config Validator** | No | Validate declared Load Config directory |
| **Import/Export/TLS Validators** | No | Validate declared directories only |
| **Parser (`analysis.data_directories`)** | No | Provide declared directory list |

This separation ensures:

- correctness
- spec compliance
- adversarial robustness
- maintainability

---

# **6. Final Statement**

**Only the Optional Header validator should ever inspect the raw 16‑entry directory table.
All other validators must operate solely on the declared directory list.**

This design is intentional, spec‑aligned, and required for correct handling of adversarial PE files.
