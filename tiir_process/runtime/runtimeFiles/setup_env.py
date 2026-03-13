import io
import logging
import os
import subprocess
import time
import warnings
from contextlib import redirect_stdout, redirect_stderr

if "BASE_URL" not in globals():
    raise ValueError("Error: 'BASE_URL' missing. Please define in notebook cell 0.")

_LOG_UTIL = "tiir_process_log_utils.py"
if not os.path.exists(_LOG_UTIL):
    subprocess.check_call(["wget", "-q", "-O", _LOG_UTIL, f"{BASE_URL}{_LOG_UTIL}"])
with open(_LOG_UTIL, "r", encoding="utf-8") as _f:
    exec(_f.read(), globals())

tiir_logger.reset({
    "component": "setup_env",
    "base_url": BASE_URL,
})

os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("TRANSFORMERS_NO_ADVISORY_WARNINGS", "1")

warnings.filterwarnings("ignore", message=r".*Trying to unpickle estimator.*")
warnings.filterwarnings("ignore", message=r".*unauthenticated requests to the HF Hub.*")
for logger_name in ["huggingface_hub", "transformers", "urllib3", "filelock"]:
    logging.getLogger(logger_name).setLevel(logging.ERROR)


def log(msg):
    print(f"\n[{time.strftime('%H:%M:%S')}] {msg}")


def stage(msg):
    print(f"   {msg}...", end=" ", flush=True)


def done(msg="Done."):
    print(msg)


def fail(msg):
    print(f"FAILED: {msg}")


def run_command(command, task_name):
    result = subprocess.run(
        command,
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        tail = (result.stderr or "").strip().splitlines()
        tail = tail[-1] if tail else "unknown error"
        raise RuntimeError(f"{task_name} failed: {tail[:160]}")


class _QuietSection:
    def __enter__(self):
        self.sink = io.StringIO()
        self.redirect_out = redirect_stdout(self.sink)
        self.redirect_err = redirect_stderr(self.sink)
        self.redirect_out.__enter__()
        self.redirect_err.__enter__()
        self.warn_ctx = warnings.catch_warnings()
        self.warn_ctx.__enter__()
        warnings.filterwarnings("ignore", message=r".*Trying to unpickle estimator.*")
        warnings.filterwarnings("ignore", message=r".*unauthenticated requests to the HF Hub.*")
        return self

    def __exit__(self, exc_type, exc, tb):
        self.warn_ctx.__exit__(exc_type, exc, tb)
        self.redirect_err.__exit__(exc_type, exc, tb)
        self.redirect_out.__exit__(exc_type, exc, tb)
        return False


log("STEP 1/4: Checking environment")
stage("Checking and installing required libraries")
step1_start = time.time()
install_actions = []
try:
    run_command("pip install -q -U --force-reinstall 'protobuf>=3.20.3'", "Fixing Protobuf")
    try:
        import bitsandbytes  # noqa: F401
        import kagglehub  # noqa: F401
        install_actions.append("core_libraries_already_present")
    except ImportError:
        run_command("pip install -q -U bitsandbytes", "Installing bitsandbytes")
        run_command(
            "pip install -q -U 'transformers>=4.41.2' 'peft>=0.11.1' 'accelerate>=0.30.1' 'datasets>=2.19.1'",
            "Installing HF stack",
        )
        run_command("pip install -q kagglehub", "Installing KaggleHub")
        run_command("pip install -q scipy scikit-learn pandas", "Installing data-science stack")
        install_actions.extend(["bitsandbytes", "hf_stack", "kagglehub", "data_science_stack"])
    tiir_logger.log("setup.step1_environment", "completed", {
        "elapsed_s": round(time.time() - step1_start, 3),
        "install_actions": install_actions,
    })
    done()
except Exception as exc:
    tiir_logger.log("setup.step1_environment", "failed", {
        "elapsed_s": round(time.time() - step1_start, 3),
        "error": str(exc),
    }, status="ERROR")
    fail(str(exc))
    raise

os.environ["LD_LIBRARY_PATH"] = "/usr/local/cuda/lib64:" + os.environ.get("LD_LIBRARY_PATH", "")

import torch
import pandas as pd
import scipy.sparse
import pickle
import kagglehub
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
from peft import PeftModel

log("STEP 2/4: Configuring device")
stage("Inspecting available GPU devices")
step2_start = time.time()
try:
    n_gpus = torch.cuda.device_count()
    device_cpe = "cuda:0" if n_gpus > 0 else "cpu"
    tiir_logger.log("setup.step2_device", "completed", {
        "elapsed_s": round(time.time() - step2_start, 3),
        "gpu_count": n_gpus,
        "device_cpe": device_cpe,
    })
    done()
    print(f"   GPU count: {n_gpus}")
    print(f"   text2CPE device: {device_cpe}")
except Exception as exc:
    tiir_logger.log("setup.step2_device", "failed", {
        "elapsed_s": round(time.time() - step2_start, 3),
        "error": str(exc),
    }, status="ERROR")
    fail(str(exc))
    raise

log("STEP 3/4: Loading text2CPE model")
hf_token = None
try:
    from kaggle_secrets import UserSecretsClient
    hf_token = UserSecretsClient().get_secret("HF_TOKEN")
except Exception:
    pass

MODEL_HANDLE = "mathismller/mistral-cpe-extractor/pyTorch/default/1"
base_model_id = "mistralai/Mistral-7B-Instruct-v0.3"

stage("Loading LoRA adapter and base model")
step3_start = time.time()
try:
    with _QuietSection():
        try:
            adapter_path = kagglehub.model_download(MODEL_HANDLE)
            model_source = "model registry"
        except Exception:
            adapter_path = kagglehub.dataset_download("mathismller/mistral-cpe-extractor")
            model_source = "dataset registry"

        tokenizer_cpe = AutoTokenizer.from_pretrained(base_model_id, token=hf_token)
        tokenizer_cpe.pad_token = tokenizer_cpe.eos_token

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

    tiir_logger.log("setup.step3_model", "completed", {
        "elapsed_s": round(time.time() - step3_start, 3),
        "device": device_cpe,
        "adapter_source": model_source,
        "adapter_path": adapter_path,
    })
    done()
    print(f"   Adapter source: {model_source}")
    print("   text2CPE model loaded successfully.")
except Exception as exc:
    tiir_logger.log("setup.step3_model", "failed", {
        "elapsed_s": round(time.time() - step3_start, 3),
        "device": device_cpe,
        "error": str(exc),
    }, status="ERROR")
    fail(str(exc))
    raise

log("STEP 4/4: Loading RAG knowledge base")
rag_files = ["cpe_meta.parquet", "cpe_tfidf.npz", "vectorizer.pkl"]
reviewer_runtime_files = [
    "tiir_process_log_utils.py",
    "tiir_input_router.py",
    "text2CPE_inference.py",
    "orchestrator_stix.py",
    "Loader.py",
    "tiir_pipeline_runner.py",
    "attack_json_fail.json",
    "attack_json_succ.json",
    "Accounts.CSV",
    "Permissions.CSV",
]
rag_path = os.getcwd()
stage("Fetching RAG artifacts and runtime files")
step4_start = time.time()
try:
    fetched_rag = []
    for file_name in rag_files:
        if not os.path.exists(file_name):
            run_command(f"wget -q -O {file_name} {BASE_URL}{file_name}", f"Downloading {file_name}")
            fetched_rag.append(file_name)

    with _QuietSection():
        df_meta = pd.read_parquet(os.path.join(rag_path, "cpe_meta.parquet"))
        tfidf_matrix = scipy.sparse.load_npz(os.path.join(rag_path, "cpe_tfidf.npz"))
        with open(os.path.join(rag_path, "vectorizer.pkl"), "rb") as f:
            vectorizer = pickle.load(f)

    cpe_col = next(
        (c for c in ["cpe_uri", "cpe_2_3", "cpe"] if c in df_meta.columns),
        df_meta.columns[0],
    )

    fetched_runtime = []
    for fname in reviewer_runtime_files:
        if not os.path.exists(fname):
            run_command(f"wget -q -O {fname} {BASE_URL}{fname}", f"Fetching {fname}")
            fetched_runtime.append(fname)

    tiir_logger.log("setup.step4_rag", "completed", {
        "elapsed_s": round(time.time() - step4_start, 3),
        "rag_entries": len(df_meta),
        "cpe_col": cpe_col,
        "fetched_rag": fetched_rag,
        "runtime_files_fetched": fetched_runtime,
        "base_url": BASE_URL,
    })
    done()
    print(f"   RAG entries: {len(df_meta)} | target column: {cpe_col}")
    if fetched_runtime:
        print(f"   Runtime files fetched: {len(fetched_runtime)}")
    else:
        print("   Runtime files already present.")
except Exception as exc:
    tiir_logger.log("setup.step4_rag", "failed", {
        "elapsed_s": round(time.time() - step4_start, 3),
        "error": str(exc),
    }, status="ERROR")
    fail(str(exc))
    raise

log("SYSTEM READY")
