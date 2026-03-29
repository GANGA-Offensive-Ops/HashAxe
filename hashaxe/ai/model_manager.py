# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/ai/model_manager.py
#  AI model download, cache, and lifecycle manager for HuggingFace models.
#  Handles GPT-2 caching in ~/.crackedb/models/ for AI-based candidate generation.
#
# 🔗 ARCHITECTS:
#   - Bhanu Guragain (Shadow@Bh4nu) | Lead Developer  🏴 GANGA Offensive Ops 🔥
#   - Team Members:
#       • Shrijesh Pokharel
#       • Aashish Panthi
#
# ⚠️ WARNING:
#   ACCESS RESTRICTED. Authorized use only — pentesting, CTF, security research.
#   Unauthorized access to protected systems is illegal.
# ==========================================================================================
# ⚠️ Version 1.0.0 — Production Release 💀
# ==========================================================================================
"""
hashaxe.ai.model_manager — AI model download, cache, and lifecycle manager.

Manages local caching of HuggingFace models for AI-based candidate generation.
Models are stored in ``~/.crackedb/models/`` by default.

Dependencies:
  - ``transformers`` (optional) — HuggingFace model hub
  - ``torch`` (optional) — PyTorch inference backend
"""
from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_DEFAULT_MODEL_DIR = Path.home() / ".crackedb" / "models"
_DEFAULT_MODEL_NAME = "gpt2"  # 124M params, small enough for CPU inference


class ModelManager:
    """Manage AI model downloads and caching.

    Attributes:
        model_dir:  Local directory for cached models.
        model_name: HuggingFace model identifier (default: 'gpt2').
    """

    def __init__(
        self,
        model_dir: Path | None = None,
        model_name: str = _DEFAULT_MODEL_NAME,
    ):
        self.model_dir = model_dir or _DEFAULT_MODEL_DIR
        self.model_name = model_name
        self._model: Any = None
        self._tokenizer: Any = None
        self._pipeline: Any = None
        self._force_cpu: bool = False  # Set by OOM recovery to bypass GPU

    @property
    def model_path(self) -> Path:
        """Local path where the model is cached."""
        return self.model_dir / self.model_name.replace("/", "_")

    @property
    def is_downloaded(self) -> bool:
        """Check if the model is already cached locally."""
        return self.model_path.exists() and any(self.model_path.iterdir())

    @property
    def has_torch(self) -> bool:
        """Check if PyTorch is available."""
        try:
            import torch  # type: ignore
            return True
        except ImportError:
            return False

    @property
    def has_transformers(self) -> bool:
        """Check if HuggingFace transformers is available."""
        try:
            import transformers  # type: ignore
            return True
        except ImportError:
            return False

    @property
    def has_gpu(self) -> bool:
        """Check if CUDA GPU is available with sufficient VRAM for inference.

        GPT-2 (124M params) needs ~500MB for weights + ~200MB for KV cache
        during generation. On GPUs with <6GB total VRAM, other processes
        (Xorg, compositor, hashcat) typically consume 2-3GB, leaving
        insufficient headroom. Force CPU inference in that case.
        """
        try:
            import torch  # type: ignore
            if not torch.cuda.is_available():
                return False
            # Check if GPU has enough free VRAM (need ~1GB headroom minimum)
            total_vram = torch.cuda.get_device_properties(0).total_memory
            free_vram = total_vram - torch.cuda.memory_reserved(0)
            vram_gb = total_vram / (1024 ** 3)
            free_gb = free_vram / (1024 ** 3)
            if vram_gb < 6.0:
                logger.info(
                    "GPU has %.1fGB VRAM (%.1fGB free) — below 6GB threshold, "
                    "forcing CPU inference to prevent CUDA OOM",
                    vram_gb, free_gb,
                )
                return False
            return True
        except ImportError:
            return False

    @property
    def device(self) -> str:
        """Optimal device for inference."""
        return "cuda" if self.has_gpu else "cpu"

    def download(self, force: bool = False) -> bool:
        """Download and cache the model from HuggingFace.

        Returns True if successful, False otherwise.
        """
        if not self.has_transformers:
            logger.error("transformers not installed. Run: pip install transformers torch")
            return False

        if self.is_downloaded and not force:
            logger.info("Model '%s' already cached at %s", self.model_name, self.model_path)
            return True

        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer  # type: ignore

            logger.info("Downloading model '%s' → %s", self.model_name, self.model_path)
            self.model_path.mkdir(parents=True, exist_ok=True)

            tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            model = AutoModelForCausalLM.from_pretrained(self.model_name)

            tokenizer.save_pretrained(str(self.model_path))
            model.save_pretrained(str(self.model_path))

            logger.info("Model '%s' downloaded successfully (%s)",
                       self.model_name, self._format_size(self.model_path))
            return True
        except Exception as e:
            logger.error("Failed to download model '%s': %s", self.model_name, e)
            return False

    def load(self) -> bool:
        """Load the cached model into memory.

        Returns True if successful, False otherwise.
        If _force_cpu is set (e.g. by OOM recovery), always load on CPU.
        """
        if self._pipeline is not None:
            return True  # Already loaded

        if not self.has_transformers:
            logger.warning("transformers not installed — AI generation unavailable")
            return False

        model_src = str(self.model_path) if self.is_downloaded else self.model_name
        use_gpu = self.has_gpu and not self._force_cpu

        try:
            from transformers import pipeline  # type: ignore

            device_arg = 0 if use_gpu else -1
            device_label = "cuda:0" if use_gpu else "cpu"
            logger.info("Loading AI model on %s...", device_label)

            self._pipeline = pipeline(
                "text-generation",
                model=model_src,
                device=device_arg,
                truncation=True,
            )
            logger.info("AI model loaded: %s (%s)", self.model_name, device_label)
            return True
        except Exception as e:
            logger.error("Failed to load model: %s", e)
            self._pipeline = None
            # If GPU load failed, try CPU fallback automatically
            if use_gpu and not self._force_cpu:
                logger.warning("GPU load failed — retrying on CPU...")
                self._force_cpu = True
                return self.load()
            return False

    def generate(
        self,
        prompt: str = "password",
        num_candidates: int = 50,
        max_length: int = 20,
        temperature: float = 1.2,
        top_k: int = 50,
        top_p: float = 0.95,
    ) -> list[str]:
        """Generate candidate passwords using the loaded model.

        Args:
            prompt: Seed text for generation.
            num_candidates: Number of candidates to generate.
            max_length: Maximum candidate length.
            temperature: Sampling temperature (higher = more random).
            top_k: Top-k sampling parameter.
            top_p: Nucleus sampling parameter.

        Returns:
            List of generated candidate strings.
        """
        if self._pipeline is None:
            if not self.load():
                return []

        try:
            outputs = self._pipeline(
                prompt,
                max_new_tokens=max_length,
                num_return_sequences=num_candidates,
                temperature=temperature,
                top_k=top_k,
                top_p=top_p,
                do_sample=True,
                pad_token_id=self._pipeline.tokenizer.eos_token_id,
            )

            candidates = set()
            import re
            
            # 🧨 HIGHLY STRICT PENTESTER WHITELIST 🧨
            # Only allow pure alphanumeric and traditional password symbols. 
            # This instantly destroys garbage like HTML tags, JSON dumps, Python code, 
            # file routes (C:\), brackets (), quotes "", commas, etc.
            valid_pass_regex = re.compile(r"^[A-Za-z0-9!@#$%^&*_+\-=]+$")
            
            # Expanded stop words to prevent the AI from generating common linking verbs/nouns
            stop_words = {"the", "and", "is", "in", "it", "of", "to", "for", "on", "with", 
                          "as", "at", "by", "are", "has", "be", "this", "that", "from", 
                          "will", "can", "but", "not", "what", "all", "were", "when", "how"}

            def clean_token(t: str) -> str:
                return t.strip()

            for item in outputs:
                text = item.get("generated_text", "")
                if not text:
                    continue

                tokens_to_test = []

                # Strategy 1: The full contiguous block (spaces removed)
                compressed = "".join(text.split())
                tokens_to_test.append(compressed)
                
                # Strategy 2: Extract just the *first* word from the AI's sentence
                words = text.strip().split()
                if words:
                    tokens_to_test.append(words[0])

                # Strategy 3: Isolate the purely newly generated suffix
                if text.startswith(prompt):
                    suffix = text[len(prompt):].strip()
                    if suffix:
                        suffix_words = suffix.split()
                        if suffix_words:
                            tokens_to_test.append(suffix_words[0]) # First contextual word
                        tokens_to_test.append("".join(suffix_words)) # Compressed suffix

                # Filter and normalize the tokens
                for t in tokens_to_test:
                    cleaned = clean_token(t)
                    # Reject if it's too short (unless it's the exact prompt), 
                    # completely numeric, or a generic English stopword.
                    # Skip overly simple tokens if they are short (and not our prompt)
                    if len(cleaned) < 3 and cleaned != prompt:
                        continue
                    if cleaned.lower() in stop_words:
                        continue
                        
                    # 🧨 STRICT FILTER: Only allow completely valid password combinations
                    if not valid_pass_regex.match(cleaned):
                        continue
                    
                    if cleaned and len(cleaned) <= max_length:
                        candidates.add(cleaned)
                        
                        # Pentester bonus: Also yield capitalized / lowercase variations
                        # automatically, as the AI might generate lowercased names.
                        if cleaned.islower():
                            candidates.add(cleaned.capitalize())

            return sorted(candidates)
        except Exception as e:
            logger.error("AI generation failed: %s", e)
            return []

    def clear_cache(self) -> bool:
        """Remove cached model files."""
        if self.model_path.exists():
            shutil.rmtree(self.model_path)
            logger.info("Cleared model cache: %s", self.model_path)
            return True
        return False

    def info(self) -> dict[str, str]:
        """Return model status information."""
        return {
            "Model": self.model_name,
            "Cached": "Yes" if self.is_downloaded else "No",
            "Path": str(self.model_path),
            "torch": "Yes" if self.has_torch else "No (pip install torch)",
            "transformers": "Yes" if self.has_transformers else "No (pip install transformers)",
            "GPU": self.device,
        }

    @staticmethod
    def _format_size(path: Path) -> str:
        total = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
        for unit in ["B", "KB", "MB", "GB"]:
            if total < 1024:
                return f"{total:.1f} {unit}"
            total /= 1024
        return f"{total:.1f} TB"
