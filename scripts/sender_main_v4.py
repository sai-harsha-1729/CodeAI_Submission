
import os
import sys
import json
import time
import argparse
import socket
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from protocol_common_v3 import (
    load_master_config, resolve_pipeline_spec, get_kem_adapter, get_auth_adapter,
    canonical_json_bytes, b64e, b64d, timed_call, send_json_frame, recv_json_frame,
    hkdf_combine, derive_session_subkeys, aead_encrypt, aead_decrypt, transcript_digest,
    build_aad, hmac_tag, lindblad_harden_key, sha256, hash_expand, get_cpu_snapshot, utc_now_iso
)

def build_plaintext(msg_len: int, session_id: str, pipeline_id: str) -> bytes:
    seed = (session_id + "|" + pipeline_id + "|" + str(msg_len)).encode("utf-8")
    return hash_expand(seed, msg_len, label=b"sender-payload")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--project_root", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--pipeline_id", required=True)
    parser.add_argument("--session_id", required=True)
    parser.add_argument("--msg_len", type=int, default=128)
    parser.add_argument("--trial_idx", type=int, default=0)
    parser.add_argument("--sweep_id", default="default")
    parser.add_argument("--log_path", required=True)
    parser.add_argument("--socket_timeout_sec", type=float, default=20.0)

    # per-run overrides for sweeps
    parser.add_argument("--n_raw", type=int, default=None)
    parser.add_argument("--p_noise", type=float, default=None)
    parser.add_argument("--qber_max", type=float, default=None)
    parser.add_argument("--sample_frac", type=float, default=None)
    parser.add_argument("--lindblad_steps", type=int, default=None)
    parser.add_argument("--lindblad_tau", type=float, default=None)
    parser.add_argument("--lindblad_gamma", type=float, default=None)

    args = parser.parse_args()

    t_total_0 = time.perf_counter_ns()

    cfg = load_master_config(args.project_root)
    spec = resolve_pipeline_spec(args.pipeline_id, project_root=args.project_root)

    lind_cfg = cfg["lindblad_defaults"]
    qkd_cfg = cfg["qkd_defaults"]
    seed_base = int(cfg["execution_policy"]["random_seed_base"])

    # resolved per-run settings
    n_raw = int(args.n_raw if args.n_raw is not None else qkd_cfg["N_RAW"])
    p_noise = float(args.p_noise if args.p_noise is not None else qkd_cfg["P_NOISE"])
    qber_max = float(args.qber_max if args.qber_max is not None else qkd_cfg["QBER_MAX"])
    sample_frac = float(args.sample_frac if args.sample_frac is not None else qkd_cfg["SAMPLE_FRAC"])

    lindblad_steps = int(args.lindblad_steps if args.lindblad_steps is not None else lind_cfg["steps"])
    lindblad_tau = float(args.lindblad_tau if args.lindblad_tau is not None else lind_cfg["tau"])
    lindblad_gamma = float(args.lindblad_gamma if args.lindblad_gamma is not None else lind_cfg["gamma"])

    telemetry = {
        "role": "sender",
        "pipeline_id": args.pipeline_id,
        "success": False,
        "abort": False,
        "abort_reason": None,
        "timings_ns": {},
        "metrics": {},
        "cpu_snapshot_start": get_cpu_snapshot(),
        "started_utc": utc_now_iso(),
        "session_id": args.session_id,
        "resolved_overrides": {
            "N_RAW": n_raw,
            "P_NOISE": p_noise,
            "QBER_MAX": qber_max,
            "SAMPLE_FRAC": sample_frac,
            "LINDBLAD_STEPS": lindblad_steps,
            "LINDBLAD_TAU": lindblad_tau,
            "LINDBLAD_GAMMA": lindblad_gamma
        }
    }

    hello = {
        "type": "client_hello",
        "session_id": args.session_id,
        "pipeline_id": args.pipeline_id,
        "msg_len": int(args.msg_len),
        "trial_idx": int(args.trial_idx),
        "sweep_id": args.sweep_id,
        "N_RAW": n_raw,
        "P_NOISE": p_noise,
        "QBER_MAX": qber_max,
        "SAMPLE_FRAC": sample_frac,
        "LINDBLAD_STEPS": lindblad_steps,
        "LINDBLAD_TAU": lindblad_tau,
        "LINDBLAD_GAMMA": lindblad_gamma
    }

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(float(args.socket_timeout_sec))
    client.connect((args.host, args.port))

    try:
        send_json_frame(client, hello)

        server_hello = recv_json_frame(client)
        kem_public_key = b64d(server_hello["kem_public_key_b64"])

        kem_adapter = get_kem_adapter(spec["kem_scheme"])
        auth_adapter = get_auth_adapter(spec["auth_scheme"])

        sender_auth_public_key_b64 = None
        sender_auth_secret_key = None

        if spec["auth_scheme"] in ("mldsa", "ed25519"):
            (auth_kp, t_auth_keygen_ns) = timed_call(auth_adapter.generate_keypair)
            auth_pk, auth_sk = auth_kp
            sender_auth_public_key_b64 = b64e(auth_pk)
            sender_auth_secret_key = auth_sk
            telemetry["timings_ns"]["auth_keygen_ns"] = t_auth_keygen_ns

        (kem_out, t_encap_ns) = timed_call(kem_adapter.encapsulate, kem_public_key)
        kem_ct, shared_secret = kem_out
        telemetry["timings_ns"]["kem_encap_ns"] = t_encap_ns

        client_kem = {
            "type": "client_kem",
            "kem_ciphertext_b64": b64e(kem_ct),
            "sender_auth_public_key_b64": sender_auth_public_key_b64
        }
        send_json_frame(client, client_kem)

        bootstrap_master = hkdf_combine([shared_secret], length=32, info=b"bootstrap-master")
        bootstrap_keys = derive_session_subkeys(bootstrap_master, context=f"{args.pipeline_id}|bootstrap".encode())

        qkd_response = recv_json_frame(client)

        if qkd_response.get("abort", False):
            telemetry["abort"] = True
            telemetry["abort_reason"] = qkd_response.get("abort_reason", "QKD_ABORT")
            telemetry["metrics"]["qber"] = qkd_response.get("qber", None)
            return _finalize(telemetry, args.log_path, t_total_0)

        session_master = hkdf_combine([shared_secret], length=32, info=b"session-master|base")

        if spec["use_qkd"]:
            qkd_aad = canonical_json_bytes({
                "type": "qkd_transport",
                "session_id": args.session_id,
                "pipeline_id": args.pipeline_id
            })
            qkd_nonce = b64d(qkd_response["key_nonce_b64"])
            qkd_ct = b64d(qkd_response["key_ciphertext_b64"])

            (qkd_final_key, t_qkd_transport_decrypt_ns) = timed_call(
                aead_decrypt, bootstrap_keys["transport"], qkd_nonce, qkd_ct, qkd_aad
            )
            telemetry["timings_ns"]["qkd_transport_decrypt_ns"] = t_qkd_transport_decrypt_ns
            telemetry["metrics"]["qber"] = qkd_response.get("qber", None)

            session_master = hkdf_combine([shared_secret, qkd_final_key], length=32, info=b"session-master|qkd")

        lind_meta = None
        if spec["use_lindblad"]:
            (lind_out, t_lind_ns) = timed_call(
                lindblad_harden_key,
                session_master,
                pipeline_id=args.pipeline_id,
                trial_idx=args.trial_idx,
                sweep_id=args.sweep_id,
                mode=str(lind_cfg["enabled_mode"]),
                steps=lindblad_steps,
                tau=lindblad_tau,
                gamma=lindblad_gamma,
                base_seed=seed_base
            )
            session_master, lind_meta = lind_out
            telemetry["timings_ns"]["lindblad_ns"] = t_lind_ns
            telemetry["lindblad_meta"] = lind_meta

        session_keys = derive_session_subkeys(session_master, context=f"{args.pipeline_id}|session".encode())

        transcript = transcript_digest(
            canonical_json_bytes(hello),
            canonical_json_bytes(server_hello),
            canonical_json_bytes(client_kem),
            canonical_json_bytes(qkd_response)
        )

        if spec["auth_scheme"] in ("mldsa", "ed25519"):
            (signature, t_auth_sign_ns) = timed_call(auth_adapter.sign, sender_auth_secret_key, transcript)
            telemetry["timings_ns"]["auth_sign_ns"] = t_auth_sign_ns
            auth_frame = {
                "type": "auth_frame",
                "scheme": spec["auth_scheme"],
                "signature_b64": b64e(signature)
            }
        else:
            (tag, t_auth_sign_ns) = timed_call(hmac_tag, session_keys["auth"], transcript)
            telemetry["timings_ns"]["auth_sign_ns"] = t_auth_sign_ns
            auth_frame = {
                "type": "auth_frame",
                "scheme": "hmac",
                "hmac_tag_b64": b64e(tag)
            }

        send_json_frame(client, auth_frame)

        plaintext = build_plaintext(args.msg_len, args.session_id, args.pipeline_id)
        aad = build_aad(args.session_id, args.pipeline_id, 1, {"msg_len": int(args.msg_len)})

        (enc_out, t_encrypt_ns) = timed_call(aead_encrypt, session_keys["aead"], plaintext, aad)
        nonce, ciphertext = enc_out
        telemetry["timings_ns"]["encrypt_ns"] = t_encrypt_ns

        secure_frame = {
            "type": "secure_frame",
            "msg_counter": 1,
            "aad_b64": b64e(aad),
            "nonce_b64": b64e(nonce),
            "ciphertext_b64": b64e(ciphertext)
        }
        send_json_frame(client, secure_frame)

        ack = recv_json_frame(client)
        if not ack.get("ok", False):
            telemetry["abort"] = True
            telemetry["abort_reason"] = ack.get("error", "RECEIVER_REJECTED")
            return _finalize(telemetry, args.log_path, t_total_0)

        telemetry["success"] = True
        telemetry["metrics"]["plaintext_sha256"] = sha256(plaintext).hex()
        telemetry["metrics"]["plaintext_len"] = len(plaintext)
        telemetry["metrics"]["ack_replay_token"] = ack.get("replay_token")
        telemetry["cpu_snapshot_end"] = get_cpu_snapshot()
        return _finalize(telemetry, args.log_path, t_total_0)

    except Exception as e:
        telemetry["abort"] = True
        telemetry["abort_reason"] = f"EXCEPTION: {type(e).__name__}: {e}"
        telemetry["cpu_snapshot_end"] = get_cpu_snapshot()
        return _finalize(telemetry, args.log_path, t_total_0)
    finally:
        try:
            client.close()
        except Exception:
            pass

def _finalize(telemetry, log_path, t_total_0):
    telemetry["timings_ns"]["total_ns"] = time.perf_counter_ns() - t_total_0
    telemetry["ended_utc"] = utc_now_iso()
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(telemetry, f, indent=2)
    print(json.dumps({
        "role": telemetry["role"],
        "pipeline_id": telemetry["pipeline_id"],
        "success": telemetry["success"],
        "abort": telemetry["abort"],
        "abort_reason": telemetry["abort_reason"],
        "log_path": str(log_path)
    }))
    return 0

if __name__ == "__main__":
    main()
