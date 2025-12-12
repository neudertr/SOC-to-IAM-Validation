# ==========================================
# text2techn INFERENCE (Standalone)
# ==========================================

# 1. Dein Input Text
input_text = "The adversary dumped credentials from the LSASS process memory."

# Weitere Beispiele (einkommentieren zum Testen):
# input_text = "User clicked on a malicious link in a phishing email."
# input_text = "Adversary modified the Registry Run keys to maintain persistence."

# 2. Sicherheits-Check: Ist das Modell geladen?
if 'mapper_engine' not in globals():
    print("❌ FEHLER: Die 'mapper_engine' wurde nicht gefunden.")
    print("   -> Bitte führe zuerst das große 'Dual-Model-Loader' Script aus!")
else:
    # 3. Vorhersage (nutzt die bereits geladene Engine auf GPU 1)
    results = mapper_engine.predict(input_text, top_k=5)

    # 4. Ausgabe formatieren
    #for tid, score in results:
    #    print(f"{tid} : {score}")
    
    #print(f"\n📝 INPUT: '{input_text}'")
    #print("-" * 60)
    #print("🎯 TOP 5 ERGEBNISSE (Semantic Match):")
    
    for tid, name, score in results:
    #    # Ampel-Logik für die Konfidenz
    #    if score > 0.60: icon = "🟢"  # Starker Match
    #    elif score > 0.45: icon = "🟡"  # Mittel
    #    else: icon = "🔴"  # Schwach
        
        print(f"{tid} : {score}")
    #print("-" * 60)
