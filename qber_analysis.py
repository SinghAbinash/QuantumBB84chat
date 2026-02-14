"""QBER analysis helpers for BB84.

Provide functions to sample revealed bits, compute mismatches and QBER.
This keeps protocol analysis separate from server orchestration.
"""
from typing import List, Dict, Any, Sequence


def compute_qber(alice_bits: Sequence[str], bob_measurements: Sequence[str], sifted_indices: Sequence[int], reveal_count: int = 10) -> Dict[str, Any]:
    """Given raw alice bits, bob measurements and indices of sifted bits,
    choose up to `reveal_count` positions at random to reveal and compute
    mismatches and QBER.

    Returns a dict with keys:
      - reveal_positions: list[int]
      - reveal_pairs: list[{'index':int,'alice':str,'bob':str}]
      - mismatches: int
      - qber: float
    """
    try:
        import random

        reveal_count = min(reveal_count, len(sifted_indices))
        reveal_positions = random.sample(sifted_indices, reveal_count) if reveal_count > 0 else []
        reveal_pairs = []
        mismatches = 0
        for pos in reveal_positions:
            a = alice_bits[pos]
            b = bob_measurements[pos]
            reveal_pairs.append({'index': pos, 'alice': a, 'bob': b})
            if a != b:
                mismatches += 1
        qber = (mismatches / reveal_count) if reveal_count > 0 else 0.0
        return {
            'reveal_positions': reveal_positions,
            'reveal_pairs': reveal_pairs,
            'mismatches': mismatches,
            'qber': qber,
        }
    except Exception:
        return {'reveal_positions': [], 'reveal_pairs': [], 'mismatches': 0, 'qber': 0.0}


def summary_preview(alice_bases: str, bob_measurements: str, sifted: str, reveal_pairs: List[Dict[str, Any]], qber: float) -> str:
    """Create a short text summary suitable for logging.
    """
    ab_preview = alice_bases[:128] + ('...' if len(alice_bases) > 128 else '')
    bm_preview = bob_measurements[:128] + ('...' if len(bob_measurements) > 128 else '')
    sift_preview = sifted[:128] + ('...' if len(sifted) > 128 else '')
    reveal_preview = ','.join(str(p['index']) for p in reveal_pairs)
    return (
        f"BB84 results: sifted_len={len(sifted)}\n"
        f"Alice bases (preview): {ab_preview}\n"
        f"Bob measurements (preview): {bm_preview}\n"
        f"Sifted bits (preview): {sift_preview}\n"
        f"Revealed indices: {reveal_preview} | QBER={qber:.3f}"
    )
