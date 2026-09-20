"""
Threat Analyzer Model Loader — singleton that loads embedder + classifier once.
"""

import os
import json
import joblib
from sentence_transformers import SentenceTransformer

from .config import log, CONFIG_PATH, CLF_PATH, LE_PATH


class ModelBundle:
    """Singleton model bundle: embedder + SVM classifier + label encoder."""
    _instance = None

    def __init__(self):
        self.embedder = None
        self.clf      = None
        self.le       = None
        self.config   = None
        self._loaded  = False

    @classmethod
    def get(cls):
        if cls._instance is None:
            cls._instance = cls()
        if not cls._instance._loaded:
            cls._instance._load()
        return cls._instance

    def _load(self):
        log.info("Loading Threat Analyzer models ...")
        if not os.path.exists(CLF_PATH):
            raise FileNotFoundError(
                f"Classifier not found at {CLF_PATH}.\n"
                "  → Run notebooks/stia_training.ipynb first to train and save the model."
            )
        with open(CONFIG_PATH) as f:
            self.config = json.load(f)
        self.embedder = SentenceTransformer(self.config["embedder_name"])
        self.clf      = joblib.load(CLF_PATH)
        self.le       = joblib.load(LE_PATH)
        self._loaded  = True
        log.info(
            f"Models ready | embedder={self.config['embedder_name']} "
            f"| classes={self.config['label_names']}"
        )
