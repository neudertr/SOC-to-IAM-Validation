# TIIR reviewer notebook: pipeline plan and call graph

## Notebook structure

### Cell 0 — setup
Loads the setup script and prepares:
- Python dependencies
- GPU/device selection
- Mistral + LoRA text2CPE model
- RAG artifacts (`cpe_meta.parquet`, `cpe_tfidf.npz`, `vectorizer.pkl`)
- reviewer runtime scripts
- demo data files (`attack_json_succ.json`, `attack_json_fail.json`, `Accounts.CSV`, `Permissions.CSV`)

### Cell 1 — run pipeline
Sets one variable:
- `input_payload`

Then executes exactly one runner:
- `tiir_pipeline_runner_reviewer_v1.py`

---

## Script call graph

### Setup path
`setup_env_reviewer_v4.py`
- loads `tiir_process_log_utils_v2.py`
- installs/validates environment
- loads model + tokenizer + RAG
- downloads runtime reviewer scripts and demo files

### Runtime path
`tiir_pipeline_runner_reviewer_v1.py`
1. loads `tiir_process_log_utils_v2.py`
2. loads `tiir_input_router_reviewer_v1.py`
3. loads `text2CPE_inference_reviewer_v3.py`
4. loads `orchestrator_stix_reviewer_v3.py`
5. loads `Loader_reviewer_v3.py`
6. runs the pipeline

---

## Routing logic

### Route 1 — raw text with explicit CPE
Condition:
- `input_payload` is raw text
- regex finds at least one `cpe:2.3:...`

Path:
- router → direct CPE path
- inference skipped
- orchestrator writes canonical `Test_STIX.json`
- loader updates permissions/accounts

Reason string:
- `direct_cpe_found_in_text`

### Route 2 — raw text without explicit CPE
Condition:
- `input_payload` is raw text
- regex finds no CPE

Path:
- router → inference path
- `text2CPE_inference_reviewer_v3.py`
- `orchestrator_stix_reviewer_v3.py`
- `Loader_reviewer_v3.py`

Reason string:
- `text_without_cpe_requires_inference`

### Route 3 — JSON with direct CPE evidence
Condition:
- `input_payload` is a local `.json` file
- router finds direct CPE evidence in:
  - `cpe`
  - `cpe23`
  - `x_cpe23`
  - `x_detected_cpes[*].cpe23`
  - any string field matching the CPE regex

Path:
- router → direct CPE path
- inference skipped
- orchestrator normalizes into canonical `Test_STIX.json`
- loader updates permissions/accounts

Reason string:
- `direct_cpe_found_in_json`

### Route 4 — JSON without CPE but with extractable text
Condition:
- `.json` file
- no direct CPE found
- extractable description/product text exists

Path:
- router extracts text context
- inference path
- `text2CPE_inference_reviewer_v3.py`
- `orchestrator_stix_reviewer_v3.py`
- `Loader_reviewer_v3.py`

Reason string:
- `json_without_cpe_but_with_extractable_text`

### Route 5 — JSON without CPE and without usable text
Condition:
- `.json` file
- no direct CPE found
- no extractable text found

Path:
- router aborts before inference
- pipeline prints block A/B only
- process log records the failure

Reason string:
- `json_without_cpe_and_without_extractable_text`

### Route 6 — empty raw text
Condition:
- empty or whitespace input

Path:
- router aborts before inference
- process log records the failure

Reason string:
- `empty_text_input`

---

## Block semantics in Cell 1 output

### A. INPUT
Shows:
- input kind
- source name
- preview
- JSON summary if applicable

### B. CPE RESOLUTION
Shows one of two modes:
- direct CPE evidence found → inference skipped
- no direct CPE found → text2CPE inference result shown

### C. ORCHESTRATOR / CTI OBJECT
Shows:
- canonical `Test_STIX.json` written
- route mode
- primary CPE
- number of detected CPE entries

### D. IMPACTED PERMISSIONS
Shows:
- table of permission hits if any
- otherwise `No permission hits`

### E. IMPACTED IDENTITIES
Shows:
- table of linked accounts if any
- otherwise `No linked identities`

---

## Output artifacts written by the runtime pipeline

Always intended:
- `Test_STIX.json`
- `permissions_modified.csv`
- `accounts_modified.csv`
- `modification_report.txt`
- `tiir_proces_log.jsonl`

If the router aborts before orchestration/loading:
- only `tiir_proces_log.jsonl` is guaranteed
