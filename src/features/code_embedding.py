"""
CodeBERT 기반 코드 임베딩
패키지 install 스크립트, postinstall 등 코드를 벡터로 변환
"""

import torch
import numpy as np
from transformers import AutoTokenizer, AutoModel
from loguru import logger

MODEL_NAME = "microsoft/codebert-base"
EMBED_DIM = 768  # CodeBERT CLS 토큰 차원
MAX_LENGTH = 512


class CodeEmbedder:
    def __init__(self, device: str = None):
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        logger.info(f"CodeBERT 로드 중... (device: {self.device})")
        self.tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
        self.model = AutoModel.from_pretrained(MODEL_NAME).to(self.device)
        self.model.eval()
        logger.info("CodeBERT 로드 완료")

    def embed(self, code_snippet: str) -> np.ndarray:
        """코드 문자열 → 768차원 임베딩 벡터"""
        if not code_snippet or not code_snippet.strip():
            return np.zeros(EMBED_DIM)

        inputs = self.tokenizer(
            code_snippet,
            return_tensors="pt",
            max_length=MAX_LENGTH,
            truncation=True,
            padding="max_length",
        )
        inputs = {k: v.to(self.device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = self.model(**inputs)

        # CLS 토큰 벡터 사용
        cls_vector = outputs.last_hidden_state[:, 0, :].squeeze().cpu().numpy()
        return cls_vector

    def embed_batch(self, code_list: list[str], batch_size: int = 16) -> np.ndarray:
        """여러 코드 스니펫을 배치로 임베딩"""
        all_embeddings = []
        for i in range(0, len(code_list), batch_size):
            batch = code_list[i:i + batch_size]
            embeddings = [self.embed(code) for code in batch]
            all_embeddings.extend(embeddings)
            logger.debug(f"임베딩 진행: {min(i + batch_size, len(code_list))}/{len(code_list)}")
        return np.array(all_embeddings)
