
import json
from pathlib import Path

from protocol_common_v2 import *  # reuse all stable primitives from v2

def _bool_flag(flags: dict, name: str, default: bool = False) -> bool:
    return bool(flags.get(name, default))

def _convert_registry_item_to_runtime_spec(item: dict) -> dict:
    """
    Convert a registry item into an executable runtime spec.
    We keep the runtime operationally comparable by ensuring every executable
    variant has some transcript-auth path:
      - mldsa when requested explicitly
      - ed25519 for classical baseline
      - hmac otherwise
    """
    item_id = item.get("pipeline_id") or item.get("ablation_id")
    flags = dict(item.get("flags", {}))

    # External baselines
    if item_id == "B1_CLASSICAL":
        return {
            "pipeline_id": item_id,
            "description": item.get("description", "Classical baseline"),
            "kem_scheme": "x25519",
            "auth_scheme": "ed25519",
            "use_qkd": False,
            "use_lindblad": False,
            "use_replay_protection": True,
            "source_group": item.get("source_group", "external_baseline"),
            "flags": {
                "use_pqc": False,
                "use_qkd": False,
                "use_lindblad": False,
                "use_mldsa_auth": False,
                "use_replay_protection": True
            }
        }

    if item_id == "B2_MINIMAL_PQC":
        return {
            "pipeline_id": item_id,
            "description": item.get("description", "Minimal PQC operational baseline"),
            "kem_scheme": "mlkem",
            "auth_scheme": item.get("auth_scheme", "hmac"),
            "use_qkd": False,
            "use_lindblad": False,
            "use_replay_protection": True,
            "source_group": item.get("source_group", "external_baseline"),
            "flags": {
                "use_pqc": True,
                "use_qkd": False,
                "use_lindblad": False,
                "use_mldsa_auth": False,
                "use_replay_protection": True
            }
        }

    # Main pipelines / ablations
    use_pqc = _bool_flag(flags, "use_pqc", True)
    use_qkd = _bool_flag(flags, "use_qkd", False)
    use_lindblad = _bool_flag(flags, "use_lindblad", False)
    use_mldsa_auth = _bool_flag(flags, "use_mldsa_auth", False)
    use_replay_protection = _bool_flag(flags, "use_replay_protection", True)

    kem_scheme = "mlkem" if use_pqc else "x25519"
    auth_scheme = "mldsa" if use_mldsa_auth else item.get("auth_scheme", "hmac")

    return {
        "pipeline_id": item_id,
        "description": item.get("description", item_id),
        "kem_scheme": kem_scheme,
        "auth_scheme": auth_scheme,
        "use_qkd": use_qkd,
        "use_lindblad": use_lindblad,
        "use_replay_protection": use_replay_protection,
        "source_group": item.get("source_group", "registry_item"),
        "flags": {
            "use_pqc": use_pqc,
            "use_qkd": use_qkd,
            "use_lindblad": use_lindblad,
            "use_mldsa_auth": use_mldsa_auth,
            "use_replay_protection": use_replay_protection
        }
    }

def load_runtime_pipeline_specs(project_root: str = None) -> dict:
    """
    Priority:
      1) runtime_pipeline_specs_v3.json if present
      2) pipeline_registry_v2.json converted into runtime specs
      3) fallback to built-in v2 static specs
    """
    # Fallback to v2 built-ins
    fallback_specs = {}
    try:
        for k, v in PIPELINE_SPECS.items():
            vv = dict(v)
            vv["pipeline_id"] = k
            vv["description"] = k
            vv["source_group"] = "fallback_v2_builtin"
            fallback_specs[k] = vv
    except Exception:
        pass

    if project_root is None:
        return fallback_specs

    project_root = str(project_root)
    runtime_path = Path(project_root) / "configs" / "runtime_pipeline_specs_v3.json"
    if runtime_path.exists():
        raw = load_json(runtime_path, default={}) or {}
        specs = {}
        for item in raw.get("runtime_specs", []):
            specs[item["pipeline_id"]] = dict(item)
        if specs:
            return specs

    registry_path = Path(project_root) / "configs" / "pipeline_registry_v2.json"
    if registry_path.exists():
        reg = load_json(registry_path, default={}) or {}
        items = []
        for x in reg.get("main_pipelines", []):
            xx = dict(x)
            xx["source_group"] = "main_pipeline"
            items.append(xx)
        for x in reg.get("external_baselines", []):
            xx = dict(x)
            xx["source_group"] = "external_baseline"
            items.append(xx)
        for x in reg.get("ablation_templates", []):
            xx = dict(x)
            xx["source_group"] = "ablation_template"
            items.append(xx)

        specs = {}
        for item in items:
            rt = _convert_registry_item_to_runtime_spec(item)
            specs[rt["pipeline_id"]] = rt
        if specs:
            return specs

    return fallback_specs

def resolve_pipeline_spec(pipeline_id: str, project_root: str = None) -> dict:
    specs = load_runtime_pipeline_specs(project_root=project_root)
    if pipeline_id not in specs:
        raise KeyError(f"Unknown pipeline_id: {pipeline_id}. Available: {sorted(specs.keys())}")
    return dict(specs[pipeline_id])
