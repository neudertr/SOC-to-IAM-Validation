# filename: setup_env.py
import os
import sys
import subprocess
import time

def log(msg):
    print(f"\n[{time.strftime('%H:%M:%S')}] ℹ️  {msg}")

def run_command(command, task_name):
    print(f"   ⏳ {task_name}...", end=" ", flush=True)
    try:
        subprocess.check_call(command, shell=True)
        print("✅ Done.")
    except subprocess.CalledProcessError as e:
        print("❌ Failed.")
        raise e

# ==========================================
# 1. INSTALLATION & ENVIRONMENT
# ==========================================
log("STEP 1/5: Checking Environment & Libraries...")

# Check if libraries are already installed to speed up re-runs
try:
    import bitsandbytes
    import kagglehub
    import sentence_transformers
    print("   ✅ Libraries already installed.")
except ImportError:
    run_command("pip install -q -U bitsandbytes", "Installing bitsandbytes")
    run_command("pip install -q -U 'transformers>=4.41.2' 'peft>=0.11.1' 'accelerate>=0.30.1' 'datasets>=2.19.1'", "Installing HuggingFace Stack")
    run_command("pip install -q -U sentence-transformers kagglehub", "Installing SBERT & KaggleHub")
    run_command("pip install -q scipy scikit-learn pandas", "Installing Data Science Stack")

# Set paths for CUDA
os.environ["LD_LIBRARY_PATH"] = "/usr/local/cuda/lib64:" + os.environ.get("LD_LIBRARY_PATH", "")

import torch
import pandas as pd
import scipy.sparse
import pickle
import kagglehub
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel
from sentence_transformers import SentenceTransformer, util

# ==========================================
# 2. GPU SETUP
# ==========================================
log("STEP 2/5: Configuring GPU Strategy...")
n_gpus = torch.cuda.device_count()
print(f"   🖥️  Found {n_gpus} GPU(s).")

if n_gpus < 2:
    print("   ⚠️  Single GPU mode. Warning: High VRAM usage expected.")
    device_cpe = "cuda:0"
    device_techn = "cuda:0"
else:
    print("   ✅ Dual-GPU mode active.")
    device_cpe = "cuda:0"  # Mistral
    device_techn = "cuda:1" # SBERT

# ==========================================
# 3. LOAD TEXT2CPE (Mistral)
# ==========================================
log(f"STEP 3/5: Loading text2CPE Model on {device_cpe}...")

try:
    # ---------------------------------------------------------
    # FIX: Try downloading as a MODEL first (since your screenshot shows Models)
    # ---------------------------------------------------------
    # ⚠️ REPLACE 'mathismller' WITH YOUR EXACT KAGGLE HANDLE (Check your URL!)
    # ⚠️ If your model URL ends in .../pyTorch/default/1, use that full path.
    
    MODEL_HANDLE = 'mathismller/mistral-cpe-extractor/pyTorch/default/1'
    
    print(f"   ⬇️  Attempting to download Model: {MODEL_HANDLE}...")
    try:
        adapter_path = kagglehub.model_download(MODEL_HANDLE)
        print("      ✅ Found in Model Registry.")
    except Exception:
        print("      ⚠️ Model registry failed. Trying as Dataset...")
        # Fallback: Try as dataset if you re-uploaded it
        adapter_path = kagglehub.dataset_download('mathismller/mistral-cpe-extractor')

    print(f"   📂 Adapter path: {adapter_path}")

    # 2. Load Base Model
    base_model_id = "mistralai/Mistral-7B-Instruct-v0.3"
    print("   ⏳ Loading Base Model (4-bit)...")
    
    # Check for HF Token (optional, if model is gated)
    from kaggle_secrets import UserSecretsClient
    try:
        hf_token = UserSecretsClient().get_secret("HF_TOKEN")
    except:
        hf_token = None

    tokenizer_cpe = AutoTokenizer.from_pretrained(base_model_id, token=hf_token)
    tokenizer_cpe.pad_token = tokenizer_cpe.eos_token
    
    model_cpe = AutoModelForCausalLM.from_pretrained(
        base_model_id,
        load_in_4bit=True,
        device_map=device_cpe, 
        torch_dtype=torch.bfloat16,
        token=hf_token
    )

    # 3. Load Adapter
    model_cpe = PeftModel.from_pretrained(model_cpe, adapter_path)
    model_cpe.eval()
    print("   ✅ text2CPE Model loaded successfully.")
    
except Exception as e:
    print(f"   ❌ Error loading text2CPE: {e}")
    raise e

# ==========================================
# 4. LOAD RAG ARTIFACTS
# ==========================================
log("STEP 4/5: Loading RAG Knowledge Base...")

rag_files = ["cpe_meta.parquet", "cpe_tfidf.npz", "vectorizer.pkl"]
rag_path = os.getcwd() # Save to current working directory

print(f"   ⬇️  Fetching RAG artifacts from GitHub ({REPO})...")

for file_name in rag_files:
    # Only download if not already present (speeds up re-runs)
    if not os.path.exists(file_name):
        url = f"{BASE_URL}{file_name}"
        print(f"      Downloading {file_name}...", end=" ")
        try:
            # -q = quiet, -O = output filename
            subprocess.check_call(f"wget -q -O {file_name} {url}", shell=True)
            print("✅")
        except subprocess.CalledProcessError:
            print("❌ Failed.")
            print(f"      ⚠️ Critical: Could not download {file_name}. Check if it exists in the repo root.")
            raise Exception(f"Download failed for {file_name}")
    else:
        print(f"      ✅ {file_name} already present.")

print(f"   📂 Reading RAG data from: {rag_path}")

try:
    # Load directly from current directory
    df_meta = pd.read_parquet(os.path.join(rag_path, "cpe_meta.parquet"))
    tfidf_matrix = scipy.sparse.load_npz(os.path.join(rag_path, "cpe_tfidf.npz"))
    with open(os.path.join(rag_path, "vectorizer.pkl"), "rb") as f:
        vectorizer = pickle.load(f)
    print("   ✅ RAG Database loaded.")
except Exception as e:
    print(f"   ❌ Error loading RAG artifacts: {e}")
    print("      (Hint: If you get 'UnpicklingError' or 'Parquet error', your file on GitHub might be an LFS pointer!)")
    raise e

# ==========================================
# 5. LOAD TEXT2TECHN (SBERT & MITRE)
# ==========================================
log(f"STEP 5/5: Loading text2techn on {device_techn}...")

class MitreMapper:
    def __init__(self, model_path, excel_path, index_path, device):
        self.device = device
        self.model = SentenceTransformer(model_path, device=self.device)
        self.techniques = []
        self.embeddings = None
        
        if os.path.exists(index_path):
            print("   📦 Loading cached index...")
            with open(index_path, "rb") as f:
                data = pickle.load(f)
                self.techniques = data["techniques"]
                self.embeddings = data["embeddings"].to(self.device)
        else:
            print("   🏗️  Building index (this runs once)...")
            self.build_index(excel_path, index_path)

    def build_index(self, excel_path, save_path):
        df = pd.read_excel(excel_path)
        # Simplified logic for brevity
        corpus = []
        col_id = next(c for c in df.columns if "id" in c.lower() and "matrix" not in c.lower())
        col_name = next(c for c in df.columns if "name" in c.lower())
        
        for _, row in df.iterrows():
            if str(row[col_id]).startswith("T"):
                corpus.append(f"{row[col_name]} {row.get('description', '')}")
                self.techniques.append({"id": row[col_id], "name": row[col_name]})
        
        self.embeddings = self.model.encode(corpus, convert_to_tensor=True, show_progress_bar=False, device=self.device)
        with open(save_path, "wb") as f:
            pickle.dump({"techniques": self.techniques, "embeddings": self.embeddings.cpu()}, f)

# Download dependencies
try:
    # ---------------------------------------------------------
    # FIX: Same logic for the second model
    # ---------------------------------------------------------
    SBERT_HANDLE = 'mathismller/sbert-mitre-technique-extractor/pyTorch/default/1'
    
    print(f"   ⬇️  Attempting to download SBERT Model: {SBERT_HANDLE}...")
    try:
        sbert_path = kagglehub.model_download(SBERT_HANDLE)
    except:
        sbert_path = kagglehub.dataset_download('mathismller/sbert-mitre-technique-extractor')

except Exception as e:
    print("   ❌ Error: Could not download SBERT model.")
    print(f"   Detailed Error: {e}")
    raise Exception("SBERT Download Failed")
excel_url = "https://raw.githubusercontent.com/neudertr/SOC-to-IAM-Validation/main/enterprise-attack-v18.1-techniques.xlsx"
subprocess.run(f"wget -q -O enterprise.xlsx {excel_url}", shell=True)

# Init Mapper
mapper_engine = MitreMapper(sbert_path, "enterprise.xlsx", "mitre_index.pkl", device_techn)
print("   ✅ text2techn System ready.")

# ==========================================
# 6. DOWNLOAD INFERENCE SCRIPTS
# ==========================================
log("FINAL: Fetching Inference Logic...")

base_url = "https://raw.githubusercontent.com/neudertr/SOC-to-IAM-Validation/main/"
scripts = ["text2technique_inference.py", "text2CPE_inference.py"]

for script in scripts:
    if not os.path.exists(script):
        print(f"   ⬇️  Downloading {script}...")
        subprocess.run(f"wget -q -O {script} {base_url}{script}", shell=True)
    else:
        print(f"   ✅ {script} present.")

log("🎉 SYSTEM READY. PROCEED TO NEXT CELL.")
