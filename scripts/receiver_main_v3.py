
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
    build_aad, hmac_verify, lindblad_harden_key, bb84_run_full_session,
    FileReplayCache, make_replay_token, sha256, get_cpu_snapshot, utc_now_iso
)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--project_root", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--pipeline_id", required=True)
    parser.add_argument("--log_path", required=True)
    args = parser.parse_args()

    t_total_0 = time.perf_counter_ns()

    cfg = load_master_config(args.project_root)
    spec = resolve_pipeline_spec(args.pipeline_id, project_root=args.project_root)

    replay_cfg = cfg["replay_defaults"]
    lind_cfg = cfg["lindblad_defaults"]
    qkd_cfg = cfg["qkd_defaults"]
    seed_base = int(cfg["execution_policy"]["random_seed_base"])

    telemetry = {
        "role": "receiver",
        "pipeline_id": args.pipeline_id,
        "success": False,
        "abort": False,
        "abort_reason": None,
        "timings_ns": {},
        "metrics": {},
        "cpu_snapshot_start": get_cpu_snapshot(),
        "started_utc": utc_now_iso()
    }

    replay_cache = FileReplayCache(
        cache_path=str(Path(args.project_root) / "state" / "replay_cache_v2.txt"),
        max_entries=int(replay_cfg["max_entries"])
    )

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(1)

    conn, addr = server.accept()
    try:
        hello = recv_json_frame(conn)
        session_id = hello["session_id"]
        trial_idx = int(hello.get("trial_idx", 0))
        sweep_id = hello.get("sweep_id", "default")
        msg_len = int(hello.get("msg_len", 128))

        telemetry["session_id"] = session_id
        telemetry["client_addr"] = str(addr)
        telemetry["hello"] = hello

        kem_adapter = get_kem_adapter(spec["kem_scheme"])
        auth_adapter = get_auth_adapter(spec["auth_scheme"])

        (keypair, t_keypair_ns) = timed_call(kem_adapter.generate_keypair)
        pk, sk = keypair
        telemetry["timings_ns"]["kem_keypair_ns"] = t_keypair_ns

        server_hello = {
            "type": "server_hello",
            "pipeline_id": args.pipeline_id,
            "kem_scheme": spec["kem_scheme"],
            "kem_public_key_b64": b64e(pk)
        }
        send_json_frame(conn, server_hello)

        client_kem = recv_json_frame(conn)
        kem_ct = b64d(client_kem["kem_ciphertext_b64"])

        (shared_secret, t_decap_ns) = timed_call(kem_adapter.decapsulate, sk, kem_ct)
        telemetry["timings_ns"]["kem_decap_ns"] = t_decap_ns

        bootstrap_master = hkdf_combine([shared_secret], length=32, info=b"bootstrap-master")
        bootstrap_keys = derive_session_subkeys(bootstrap_master, context=f"{args.pipeline_id}|bootstrap".encode())

        qkd_response = {
            "type": "qkd_status",
            "abort": False,
            "abort_reason": None,
            "qber": None,
            "key_nonce_b64": None,
            "key_ciphertext_b64": None
        }

        session_master = hkdf_combine([shared_secret], length=32, info=b"session-master|base")

        if spec["use_qkd"]:
            qkd_seed = int(sha256(f"{session_id}|{args.pipeline_id}|{trial_idx}|{sweep_id}".encode()).hex()[:8], 16)
            (qkd_result, t_qkd_ns) = timed_call(
                bb84_run_full_session,
                int(hello.get("N_RAW", qkd_cfg["N_RAW"])),
                float(hello.get("P_NOISE", qkd_cfg["P_NOISE"])),
                float(hello.get("QBER_MAX", qkd_cfg["QBER_MAX"])),
                float(hello.get("SAMPLE_FRAC", qkd_cfg["SAMPLE_FRAC"])),
                32,
                qkd_seed
            )
            telemetry["timings_ns"]["qkd_ns"] = t_qkd_ns
            telemetry["metrics"]["qber"] = qkd_result["qber"]
            telemetry["metrics"]["qkd_abort"] = qkd_result["abort"]

            if qkd_result["abort"]:
                qkd_response["abort"] = True
                qkd_response["abort_reason"] = qkd_result["abort_reason"]
                qkd_response["qber"] = qkd_result["qber"]
                send_json_frame(conn, qkd_response)

                telemetry["abort"] = True
                telemetry["abort_reason"] = qkd_result["abort_reason"]
                telemetry["success"] = False
                return _finalize(telemetry, args.log_path, t_total_0)

            qkd_final_key = qkd_result["alice_final_key"]
            qkd_aad = canonical_json_bytes({
                "type": "qkd_transport",
                "session_id": session_id,
                "pipeline_id": args.pipeline_id
            })
            (enc_out, t_qkd_transport_ns) = timed_call(
                aead_encrypt, bootstrap_keys["transport"], qkd_final_key, qkd_aad
            )
            qkd_nonce, qkd_ct = enc_out
            telemetry["timings_ns"]["qkd_transport_encrypt_ns"] = t_qkd_transport_ns

            qkd_response["qber"] = qkd_result["qber"]
            qkd_response["key_nonce_b64"] = b64e(qkd_nonce)
            qkd_response["key_ciphertext_b64"] = b64e(qkd_ct)

            send_json_frame(conn, qkd_response)
            session_master = hkdf_combine([shared_secret, qkd_final_key], length=32, info=b"session-master|qkd")
        else:
            send_json_frame(conn, qkd_response)

        lind_meta = None
        if spec["use_lindblad"]:
            (lind_out, t_lind_ns) = timed_call(
                lindblad_harden_key,
                session_master,
                pipeline_id=args.pipeline_id,
                trial_idx=trial_idx,
                sweep_id=sweep_id,
                mode=str(lind_cfg["enabled_mode"]),
                steps=int(hello.get("LINDBLAD_STEPS", lind_cfg["steps"])),
                tau=float(hello.get("LINDBLAD_TAU", lind_cfg["tau"])),
                gamma=float(hello.get("LINDBLAD_GAMMA", lind_cfg["gamma"])),
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

        auth_frame = recv_json_frame(conn)
        auth_ok = False

        auth_scheme = spec["auth_scheme"]
        if auth_scheme in ("mldsa", "ed25519"):
            sender_auth_public_key = b64d(client_kem["sender_auth_public_key_b64"])
            signature = b64d(auth_frame["signature_b64"])
            (auth_ok, t_auth_verify_ns) = timed_call(auth_adapter.verify, sender_auth_public_key, transcript, signature)
            telemetry["timings_ns"]["auth_verify_ns"] = t_auth_verify_ns
        elif auth_scheme == "hmac":
            tag = b64d(auth_frame["hmac_tag_b64"])
            (auth_ok, t_auth_verify_ns) = timed_call(hmac_verify, session_keys["auth"], transcript, tag)
            telemetry["timings_ns"]["auth_verify_ns"] = t_auth_verify_ns

        if not auth_ok:
            send_json_frame(conn, {"ok": False, "error": "AUTH_FAILED"})
            telemetry["abort"] = True
            telemetry["abort_reason"] = "AUTH_FAILED"
            return _finalize(telemetry, args.log_path, t_total_0)

        secure_frame = recv_json_frame(conn)
        aad = b64d(secure_frame["aad_b64"])
        nonce = b64d(secure_frame["nonce_b64"])
        ciphertext = b64d(secure_frame["ciphertext_b64"])
        msg_counter = int(secure_frame["msg_counter"])

        replay_token = make_replay_token(session_id, msg_counter, nonce, aad, ciphertext)
        replay_hit = False
        if spec["use_replay_protection"]:
            replay_hit = replay_cache.seen(replay_token)
            if replay_hit:
                send_json_frame(conn, {"ok": False, "error": "REPLAY_REJECTED"})
                telemetry["abort"] = True
                telemetry["abort_reason"] = "REPLAY_REJECTED"
                telemetry["metrics"]["replay_hit"] = True
                return _finalize(telemetry, args.log_path, t_total_0)

        (plaintext, t_decrypt_ns) = timed_call(aead_decrypt, session_keys["aead"], nonce, ciphertext, aad)
        telemetry["timings_ns"]["decrypt_ns"] = t_decrypt_ns

        if spec["use_replay_protection"]:
            replay_cache.add(replay_token)

        send_json_frame(conn, {
            "ok": True,
            "plaintext_sha256": sha256(plaintext).hex(),
            "plaintext_len": len(plaintext),
            "replay_token": replay_token
        })

        telemetry["success"] = True
        telemetry["metrics"]["plaintext_sha256"] = sha256(plaintext).hex()
        telemetry["metrics"]["plaintext_len"] = len(plaintext)
        telemetry["metrics"]["replay_hit"] = replay_hit
        telemetry["cpu_snapshot_end"] = get_cpu_snapshot()
        return _finalize(telemetry, args.log_path, t_total_0)

    finally:
        try:
            conn.close()
        except Exception:
            pass
        try:
            server.close()
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
