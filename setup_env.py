# filename: setup_env.py
# ============================================================
# TIIR Pipeline – Environment Bootstrap (CPE-only Edition)
# ============================================================
# Änderungen gegenüber v1:
#   - text2technique komplett entfernt (SBERT, MITRE Excel, Mapper)
#   - GPU-Logik vereinfacht: Ein Modell → ein Device
#   - run_command gibt stderr zurück statt zu schlucken (Debuggability)
#   - Explizite Versionsangaben bei pip-Paketen (Reproduzierbarkeit)
#   - Robustere Fehlerbehandlung mit klaren Fehlermeldungen
# ============================================================

import os
import sys
import subprocess
import time

# --- SAFETY CHECK ---
if "BASE_URL" not in globals():
    raise ValueError("❌ FEHLER: 'BASE_URL' fehlt. Bitte in der Kaggle-Zelle definieren!")


def log(msg):
    print(f"\n[{time.strftime('%H:%M:%S')}] ℹ️  {msg}")


def run_command(command, task_name):
    """Führt Shell-Befehl aus. Gibt bei Fehler stderr aus statt es zu schlucken."""
    print(f"   ⏳ {task_name}...", end=" ", flush=True)
    try:
        result = subprocess.run(
            command, shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,      # <-- v1 hatte DEVNULL → Fehler unsichtbar
            text=True,
        )
        if result.returncode != 0:
            print(f"⚠️  Warning: {result.stderr.strip()[:120]}")
        else:
            print("✅ Done.")
    except Exception as e:
        print(f"❌ Exception: {e}")


# ==========================================
# 1. INSTALLATION & ENVIRONMENT
# ==========================================
log("STEP 1/4: Checking Environment & Libraries...")

# Protobuf-Crash verhindern (Kaggle-spezifisch)
run_command("pip install -q -U --force-reinstall 'protobuf>=3.20.3'", "Fixing Protobuf")

try:
    import bitsandbytes
    import kagglehub
    print("   ✅ Core libraries already installed.")
except ImportError:
    run_command(
        "pip install -q -U bitsandbytes",
        "Installing bitsandbytes"
    )
    run_command(
        "pip install -q -U 'transformers>=4.41.2' 'peft>=0.11.1' "
        "'accelerate>=0.30.1' 'datasets>=2.19.1'",
        "Installing HF Stack"
    )
    run_command(
        "pip install -q kagglehub",
        "Installing KaggleHub"
    )
    run_command(
        "pip install -q scipy scikit-learn pandas",
        "Installing Data-Science Stack"
    )

os.environ["LD_LIBRARY_PATH"] = (
    "/usr/local/cuda/lib64:" + os.environ.get("LD_LIBRARY_PATH", "")
)

import torch
import pandas as pd
import scipy.sparse
import pickle
import kagglehub
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
from peft import PeftModel


# ==========================================
# 2. GPU SETUP  (vereinfacht – nur 1 Modell)
# ==========================================
log("STEP 2/4: Configuring GPU...")

n_gpus = torch.cuda.device_count()
print(f"   🖥️  Found {n_gpus} GPU(s).")

# Begründung: Nur noch Mistral-CPE, daher reicht immer cuda:0.
# Bei >=2 GPUs liegt die zweite brach – könnte für Batch-Inference
# genutzt werden, ist aber für den PoC nicht nötig.
device_cpe = "cuda:0" if n_gpus > 0 else "cpu"
print(f"   → text2CPE device: {device_cpe}")


# ==========================================
# 3. LOAD TEXT2CPE (Mistral + LoRA)
# ==========================================
log(f"STEP 3/4: Loading text2CPE Model on {device_cpe}...")

try:
    MODEL_HANDLE = "mathismller/mistral-cpe-extractor/pyTorch/default/1"

    try:
        adapter_path = kagglehub.model_download(MODEL_HANDLE)
        print("      ✅ Found in Model Registry.")
    except Exception:
        print("      ⚠️  Model-Registry fehlgeschlagen – versuche Dataset-Registry...")
        adapter_path = kagglehub.dataset_download("mathismller/mistral-cpe-extractor")

    base_model_id = "mistralai/Mistral-7B-Instruct-v0.3"
    print("   ⏳ Loading Base Model...")

    # HF-Token (optional, für Gated Models)
    hf_token = None
    try:
        from kaggle_secrets import UserSecretsClient
        hf_token = UserSecretsClient().get_secret("HF_TOKEN")
    except Exception:
        pass

    tokenizer_cpe = AutoTokenizer.from_pretrained(base_model_id, token=hf_token)
    tokenizer_cpe.pad_token = tokenizer_cpe.eos_token

    # BitsAndBytesConfig für 4-bit Quantisierung
    # (load_in_4bit als direkter Parameter ist in neueren transformers-Versionen entfernt,
    #  torch_dtype ist zu dtype umbenannt)
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_compute_dtype=torch.bfloat16,
    )

    model_cpe = AutoModelForCausalLM.from_pretrained(
        base_model_id,
        quantization_config=bnb_config,
        device_map=device_cpe,
        dtype=torch.bfloat16,
        token=hf_token,
    )
    model_cpe = PeftModel.from_pretrained(model_cpe, adapter_path)
    model_cpe.eval()
    print("   ✅ text2CPE Model loaded successfully.")

except Exception as e:
    print(f"   ❌ Error loading text2CPE: {e}")
    raise


# ==========================================
# 4. LOAD RAG ARTIFACTS
# ==========================================
log("STEP 4/4: Loading RAG Knowledge Base...")

rag_files = ["cpe_meta.parquet", "cpe_tfidf.npz", "vectorizer.pkl"]
rag_path = os.getcwd()

print(f"   ⬇️  Fetching artifacts from: {BASE_URL}")

for file_name in rag_files:
    if not os.path.exists(file_name):
        url = f"{BASE_URL}{file_name}"
        print(f"      Downloading {file_name}...", end=" ")
        try:
            subprocess.check_call(f"wget -q -O {file_name} {url}", shell=True)
            print("✅")
        except subprocess.CalledProcessError:
            print("❌ Failed.")
            raise RuntimeError(f"Download failed for {file_name}")
    else:
        print(f"      ✅ {file_name} already present.")

print(f"   📂 Reading RAG data from: {rag_path}")

try:
    df_meta = pd.read_parquet(os.path.join(rag_path, "cpe_meta.parquet"))
    tfidf_matrix = scipy.sparse.load_npz(os.path.join(rag_path, "cpe_tfidf.npz"))
    with open(os.path.join(rag_path, "vectorizer.pkl"), "rb") as f:
        vectorizer = pickle.load(f)

    # CPE-Spalte dynamisch ermitteln
    cpe_col = next(
        (c for c in ["cpe_uri", "cpe_2_3", "cpe"] if c in df_meta.columns),
        df_meta.columns[0],
    )
    print(f"   ✅ RAG Database loaded ({len(df_meta)} entries). Target Column: '{cpe_col}'")

except Exception as e:
    print(f"   ❌ Error loading RAG artifacts: {e}")
    raise


# ==========================================
# 5. DOWNLOAD RUNTIME SCRIPTS & DATA
# ==========================================
log("FINAL: Fetching Runtime Scripts & Data...")

scripts = [
    "json_to_cti_parser.py",
    "text2CPE_inference.py",
    "orchestrator_stix.py",
    "Loader.py",
]
data_files = [
    "attack_json_fail.json",
    "attack_json_succ.json",
    "Accounts.CSV",
    "Permissions.CSV",
]

for fname in scripts + data_files:
    if not os.path.exists(fname):
        url = f"{BASE_URL}{fname}"
        subprocess.run(f"wget -q -O {fname} {url}", shell=True)
    else:
        print(f"   ✅ {fname} present.")

log("🎉 SYSTEM READY. Proceed to next cell.")
