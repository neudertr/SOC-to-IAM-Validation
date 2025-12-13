# filename: setup_env.py
import os
import sys
import subprocess
import time

# --- SAFETY CHECK ---
# Wir prüfen, ob die Variablen aus der Kaggle-Zelle da sind.
if "BASE_URL" not in globals():
    raise ValueError("❌ FEHLER: 'BASE_URL' fehlt. Bitte in Kaggle definieren!")

def log(msg):
    print(f"\n[{time.strftime('%H:%M:%S')}] ℹ️  {msg}")

def run_command(command, task_name):
    print(f"   ⏳ {task_name}...", end=" ", flush=True)
    try:
        subprocess.check_call(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("✅ Done.")
    except subprocess.CalledProcessError:
        print("⚠️ Warning (proceeding anyway).")

# ==========================================
# 1. INSTALLATION & ENVIRONMENT
# ==========================================
log("STEP 1/5: Checking Environment & Libraries...")

# Protobuf Crash verhindern
run_command("pip install -q -U --force-reinstall 'protobuf>=3.20.3'", "Fixing Protobuf")

try:
    import bitsandbytes
    import kagglehub
    from sentence_transformers import SentenceTransformer, util # WICHTIG für Step 5
    print("   ✅ Libraries already installed.")
except ImportError:
    run_command("pip install -q -U bitsandbytes", "Installing bitsandbytes")
    run_command("pip install -q -U 'transformers>=4.41.2' 'peft>=0.11.1' 'accelerate>=0.30.1' 'datasets>=2.19.1'", "Installing HF Stack")
    run_command("pip install -q -U sentence-transformers kagglehub", "Installing SBERT & KaggleHub")
    run_command("pip install -q scipy scikit-learn pandas", "Installing Data Science Stack")

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
    print("   ⚠️  Single GPU mode.")
    device_cpe = "cuda:0"
    device_techn = "cuda:0"
else:
    print("   ✅ Dual-GPU mode active.")
    device_cpe = "cuda:0"
    device_techn = "cuda:1"

# ==========================================
# 3. LOAD TEXT2CPE (Mistral)
# ==========================================
log(f"STEP 3/5: Loading text2CPE Model on {device_cpe}...")

try:
    # Screenshot Name: mistral_CPE_extractor (Unterstriche!)
    MODEL_HANDLE = 'mathismller/mistral-cpe-extractor/pyTorch/default/1'
    
    print(f"   ⬇️  Attempting to download Model: {MODEL_HANDLE}...")
    try:
        adapter_path = kagglehub.model_download(MODEL_HANDLE)
        print("      ✅ Found in Model Registry.")
    except Exception:
        print("      ⚠️ Model registry failed. Trying as Dataset...")
        adapter_path = kagglehub.dataset_download('mathismller/mistral-cpe-extractor')

    base_model_id = "mistralai/Mistral-7B-Instruct-v0.3"
    print("   ⏳ Loading Base Model...")
    
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

    model_cpe = PeftModel.from_pretrained(model_cpe, adapter_path)
    model_cpe.eval()
    print("   ✅ text2CPE Model loaded successfully.")
    
except Exception as e:
    print(f"   ❌ Error loading text2CPE: {e}")
    raise e

# ==========================================
# 4. LOAD RAG ARTIFACTS (Inkl. cpe_col Fix)
# ==========================================
log(f"STEP 4/5: Loading RAG Knowledge Base from Git...")

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
            raise Exception(f"Download failed for {file_name}")
    else:
        print(f"      ✅ {file_name} already present.")

print(f"   📂 Reading RAG data from: {rag_path}")

try:
    df_meta = pd.read_parquet(os.path.join(rag_path, "cpe_meta.parquet"))
    tfidf_matrix = scipy.sparse.load_npz(os.path.join(rag_path, "cpe_tfidf.npz"))
    with open(os.path.join(rag_path, "vectorizer.pkl"), "rb") as f:
        vectorizer = pickle.load(f)

    # --- WICHTIGER FIX: Variable cpe_col definieren ---
    # Das fehlte vorher und verursachte den NameError im Inference Script
    cpe_col = next((c for c in ["cpe_uri", "cpe_2_3", "cpe"] if c in df_meta.columns), df_meta.columns[0])
    print(f"   ✅ RAG Database loaded. Target Column: '{cpe_col}'")
    # --------------------------------------------------
    
except Exception as e:
    print(f"   ❌ Error loading RAG artifacts: {e}")
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
        corpus = []
        col_id = next(c for c in df.columns if "id" in c.lower() and "matrix" not in c.lower())
        col_name = next(c for c in df.columns if "name" in c.lower())
        col_desc = next(c for c in df.columns if "description" in c.lower())
        
        for _, row in df.iterrows():
            if str(row[col_id]).startswith("T"):
                combined = f"{row[col_name]}. {str(row[col_desc])}"
                corpus.append(combined)
                self.techniques.append({"id": row[col_id], "name": row[col_name]})
        
        self.embeddings = self.model.encode(corpus, convert_to_tensor=True, show_progress_bar=False, device=self.device)
        with open(save_path, "wb") as f:
            pickle.dump({"techniques": self.techniques, "embeddings": self.embeddings.cpu()}, f)

    # --- WICHTIGER FIX: predict Methode hinzugefügt ---
    # Das fehlte vorher und verursachte den AttributeError
    def predict(self, text, top_k=5):
        if self.embeddings is None: return []
        
        # Query Encoding
        query_emb = self.model.encode([text], convert_to_tensor=True, device=self.device)
        
        # Semantic Search
        hits = util.semantic_search(query_emb, self.embeddings, top_k=top_k)[0]
        
        results = []
        for hit in hits:
            tech = self.techniques[hit['corpus_id']]
            results.append((tech['id'], tech['name'], hit['score']))
        return results
    # --------------------------------------------------

try:
    # Screenshot Name: sBERT_MITRE_technique_extractor
    SBERT_HANDLE = 'mathismller/sbert-mitre-technique-extractor/pyTorch/default/1'
    print(f"   ⬇️  Attempting to download SBERT Model: {SBERT_HANDLE}...")
    try:
        sbert_path = kagglehub.model_download(SBERT_HANDLE)
    except:
        sbert_path = kagglehub.dataset_download('mathismller/sbert-mitre-technique-extractor')

except Exception as e:
    print("   ❌ Error: Could not download SBERT model.")
    raise Exception("SBERT Download Failed")

excel_file = "enterprise-attack-v18.1-techniques.xlsx"
excel_url = f"{BASE_URL}{excel_file}"

if not os.path.exists("enterprise.xlsx"):
    subprocess.run(f"wget -q -O enterprise.xlsx {excel_url}", shell=True)

mapper_engine = MitreMapper(sbert_path, "enterprise.xlsx", "mitre_index.pkl", device_techn)
print("   ✅ text2techn System ready.")

# ==========================================
# 6. DOWNLOAD INFERENCE SCRIPTS
# ==========================================
log("FINAL: Fetching Inference Logic...")

scripts = ["text2technique_inference.py", "text2CPE_inference.py"]

for script in scripts:
    if not os.path.exists(script):
        url = f"{BASE_URL}{script}"
        subprocess.run(f"wget -q -O {script} {url}", shell=True)
    else:
        print(f"   ✅ {script} present.")

log("🎉 SYSTEM READY. PROCEED TO NEXT CELL.")
