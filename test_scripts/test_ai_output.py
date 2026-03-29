import os
import sys

# Ensure we can import from hashaxe
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import torch

from hashaxe.ai.model_manager import ModelManager


def main():
    print("==================================================")
    print("🤖 HashAxe AI Password Generation Test script 🤖")
    print("==================================================")

    # Hide HuggingFace warnings for cleaner output
    os.environ["TRANSFORMERS_VERBOSITY"] = "error"

    print("[*] Initializing AI Model Manager...")
    mgr = ModelManager()

    if not torch.cuda.is_available():
        print("[!] No GPU detected or VRAM too low. Using CPU (slower).")
    else:
        print("[+] CUDA GPU available! Using hardware acceleration.")

    print("[*] Loading GPT-2 Model weights into memory...")
    success = mgr.load()
    if not success:
        print("[-] Failed to load model! Are transformers/torch installed?")
        return

    # Let's read your actual wordlist instead of hardcoding seeds
    seeds = []
    wordlist_path = "test_files/password.txt"
    try:
        with open(wordlist_path, encoding="utf-8") as wf:
            for line in wf:
                pw = line.strip()
                if pw and pw not in seeds:
                    seeds.append(pw)
                if len(seeds) >= 10:  # Grab the first 10 rules to prevent massive output
                    break
    except Exception as e:
        print(f"[-] Could not read wordlist: {e}")
        return

    output_file = "ai_generated_passwords.txt"

    print(f"\n[*] Ready! Generating 15 AI mutations for each seed...")

    total_generated = 0
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("🤖 HashAxe RAW AI Generation Dump 🤖\n")
        f.write("======================================\n\n")

        for seed in seeds:
            print(f"  -> Thinking about permutations for: '{seed}'...")

            # Ask the AI to generate 15 passwords based on the seed
            candidates = mgr.generate(
                prompt=seed,
                num_candidates=15,
                max_length=20,  # Max length of password
                temperature=1.2,  # 1.2 = High creativity/randomness
            )

            f.write(f"--- Target Seed: {seed} ---\n")
            for c in candidates:
                f.write(f"{c}\n")
                total_generated += 1
            f.write("\n")

    print(f"\n[+] Success! Generated {total_generated} highly-probable passwords.")
    print(f"[+] I've saved them all to: {output_file}")

    # Let's print out the file contents directly to the terminal
    print("\n================= PREVIEW =================")
    with open(output_file, encoding="utf-8") as f:
        print(f.read())
    print("===========================================")


if __name__ == "__main__":
    main()
