# text2technique_inference.py

# --- 1. SAFETY CHECK: Get Input ---
if 'input_text' not in globals() and 'input_text' not in locals():
    print("⚠️ No input found. Using default test case.")
    input_text = "The adversary dumped credentials from the LSASS process memory."

# --- 2. SAFETY CHECK: Verify Engine ---
if 'mapper_engine' not in globals():
    print("❌ ERROR: 'mapper_engine' not found. Please run the Setup Cell first.")
else:
    # ==========================================
    # 3. EXECUTION
    # ==========================================
    print(f"🔹 Processing MITRE ATT&CK Mapping...")
    
    # Run prediction (using the engine loaded on GPU 1)
    results = mapper_engine.predict(input_text, top_k=5)

    print("\n🎯 Top 5 MITRE Techniques:")
    for tid, name, score in results:
        # Optional: Add visual indicator for confidence
        confidence = "🟢" if score > 0.6 else "🟡" if score > 0.4 else "🔴"
        print(f"{confidence} {tid} ({score:.3f}): {name}")
