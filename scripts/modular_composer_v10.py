
import json
import hashlib
from pathlib import Path

SECTION_ORDER = [
    "bootstrap",
    "key_schedule",
    "enhancement",
    "hardening",
    "authentication",
    "transport",
    "operational_defense"
]

PIPELINE_TO_COMPOSITION = {
    "P1_PQC_MLDSA": {
        "bootstrap": "MLKEM",
        "key_schedule": "HKDF",
        "enhancement": "NONE",
        "hardening": "NONE",
        "authentication": "MLDSA",
        "transport": "AEAD_CHACHA20_POLY1305",
        "operational_defense": "REPLAY_ON"
    },
    "P2_PQC_MLDSA_LINDBLAD": {
        "bootstrap": "MLKEM",
        "key_schedule": "HKDF",
        "enhancement": "NONE",
        "hardening": "LINDBLAD",
        "authentication": "MLDSA",
        "transport": "AEAD_CHACHA20_POLY1305",
        "operational_defense": "REPLAY_ON"
    },
    "P3_HYBRID_QKD": {
        "bootstrap": "MLKEM",
        "key_schedule": "HKDF",
        "enhancement": "QKD_BB84",
        "hardening": "NONE",
        "authentication": "HMAC",
        "transport": "AEAD_CHACHA20_POLY1305",
        "operational_defense": "REPLAY_ON"
    },
    "P4_HYBRID_QKD_LINDBLAD": {
        "bootstrap": "MLKEM",
        "key_schedule": "HKDF",
        "enhancement": "QKD_BB84",
        "hardening": "LINDBLAD",
        "authentication": "HMAC",
        "transport": "AEAD_CHACHA20_POLY1305",
        "operational_defense": "REPLAY_ON"
    },
    "B1_CLASSICAL": {
        "bootstrap": "X25519_BASELINE",
        "key_schedule": "HKDF",
        "enhancement": "NONE",
        "hardening": "NONE",
        "authentication": "ED25519_BASELINE",
        "transport": "AEAD_CHACHA20_POLY1305",
        "operational_defense": "REPLAY_ON"
    },
    "B2_MINIMAL_PQC": {
        "bootstrap": "MLKEM",
        "key_schedule": "HKDF",
        "enhancement": "NONE",
        "hardening": "NONE",
        "authentication": "HMAC",
        "transport": "AEAD_CHACHA20_POLY1305",
        "operational_defense": "REPLAY_ON"
    },
    "A0_MINIMAL_PQC": {
        "bootstrap": "MLKEM",
        "key_schedule": "HKDF",
        "enhancement": "NONE",
        "hardening": "NONE",
        "authentication": "HMAC",
        "transport": "AEAD_CHACHA20_POLY1305",
        "operational_defense": "REPLAY_ON"
    },
    "A1_PQC_AUTH": {
        "bootstrap": "MLKEM",
        "key_schedule": "HKDF",
        "enhancement": "NONE",
        "hardening": "NONE",
        "authentication": "MLDSA",
        "transport": "AEAD_CHACHA20_POLY1305",
        "operational_defense": "REPLAY_ON"
    },
    "A2_PQC_LINDBLAD": {
        "bootstrap": "MLKEM",
        "key_schedule": "HKDF",
        "enhancement": "NONE",
        "hardening": "LINDBLAD",
        "authentication": "HMAC",
        "transport": "AEAD_CHACHA20_POLY1305",
        "operational_defense": "REPLAY_ON"
    },
    "A3_HYBRID_QKD": {
        "bootstrap": "MLKEM",
        "key_schedule": "HKDF",
        "enhancement": "QKD_BB84",
        "hardening": "NONE",
        "authentication": "HMAC",
        "transport": "AEAD_CHACHA20_POLY1305",
        "operational_defense": "REPLAY_ON"
    },
    "A4_HYBRID_QKD_AUTH": {
        "bootstrap": "MLKEM",
        "key_schedule": "HKDF",
        "enhancement": "QKD_BB84",
        "hardening": "NONE",
        "authentication": "MLDSA",
        "transport": "AEAD_CHACHA20_POLY1305",
        "operational_defense": "REPLAY_ON"
    },
    "A5_HYBRID_QKD_LINDBLAD": {
        "bootstrap": "MLKEM",
        "key_schedule": "HKDF",
        "enhancement": "QKD_BB84",
        "hardening": "LINDBLAD",
        "authentication": "HMAC",
        "transport": "AEAD_CHACHA20_POLY1305",
        "operational_defense": "REPLAY_ON"
    },
    "A6_FULL_HARDENED": {
        "bootstrap": "MLKEM",
        "key_schedule": "HKDF",
        "enhancement": "QKD_BB84",
        "hardening": "LINDBLAD",
        "authentication": "MLDSA",
        "transport": "AEAD_CHACHA20_POLY1305",
        "operational_defense": "REPLAY_ON"
    },
    "A7_PQC_AUTH_NO_REPLAY": {
        "bootstrap": "MLKEM",
        "key_schedule": "HKDF",
        "enhancement": "NONE",
        "hardening": "NONE",
        "authentication": "MLDSA",
        "transport": "AEAD_CHACHA20_POLY1305",
        "operational_defense": "REPLAY_OFF"
    },
    "A8_HYBRID_QKD_LINDBLAD_NO_REPLAY": {
        "bootstrap": "MLKEM",
        "key_schedule": "HKDF",
        "enhancement": "QKD_BB84",
        "hardening": "LINDBLAD",
        "authentication": "HMAC",
        "transport": "AEAD_CHACHA20_POLY1305",
        "operational_defense": "REPLAY_OFF"
    }
}

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_module_grammar(project_root: str):
    path = Path(project_root) / "configs" / "module_grammar_v10.json"
    return load_json(path)

def canonicalize_composition(comp: dict):
    out = {}
    for sec in SECTION_ORDER:
        out[sec] = comp[sec]
    return out

def composition_key(comp: dict):
    comp = canonicalize_composition(comp)
    return "|".join([comp[s] for s in SECTION_ORDER])

def composition_id_from_key(key: str):
    return "COMP_" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]

def pipeline_to_composition(pipeline_id: str):
    if pipeline_id not in PIPELINE_TO_COMPOSITION:
        raise KeyError(f"Unknown pipeline_id for modular mapping: {pipeline_id}")
    return canonicalize_composition(dict(PIPELINE_TO_COMPOSITION[pipeline_id]))

def valid_actions_for_section(grammar: dict, section_name: str, partial_comp: dict):
    choices = grammar["sections"][section_name]["choices"]
    # constrained but simple action mask:
    # only actions in the current section are allowed
    return list(choices)

def is_complete_composition(comp: dict):
    return all(sec in comp for sec in SECTION_ORDER)

def bucketize_context(row: dict):
    msg_len = int(row["msg_len_bytes"])
    delay = float(row["network_delay_ms"])
    loss = float(row["packet_loss_pct"])
    cpu = int(row["cpu_stress_level"])
    p_noise = float(row["P_NOISE"])
    n_raw = int(row["N_RAW"])
    lind_steps = int(row["LINDBLAD_STEPS"])

    msg_bin = "small" if msg_len <= 256 else ("medium" if msg_len <= 2048 else "large")
    delay_bin = "low" if delay <= 10 else ("medium" if delay <= 40 else "high")
    loss_bin = "none" if loss == 0 else ("low" if loss <= 1.0 else "high")
    noise_bin = "none" if p_noise == 0 else ("low" if p_noise <= 0.02 else "high")
    raw_bin = "small" if n_raw <= 1024 else ("medium" if n_raw <= 4096 else "large")
    lind_bin = "off" if lind_steps == 0 else ("low" if lind_steps <= 4 else "high")

    return (msg_bin, delay_bin, loss_bin, str(cpu), noise_bin, raw_bin, lind_bin)
