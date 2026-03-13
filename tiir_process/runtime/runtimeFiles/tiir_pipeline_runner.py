import os
import pandas as pd

_REQUIRED_HELPERS = [
    ("tiir_process_log_utils.py", "tiir_logger"),
    ("tiir_input_router.py", "tiir_route_input"),
    ("text2CPE_inference.py", "tiir_run_text2cpe_inference"),
    ("orchestrator_stix.py", "tiir_build_cti_object"),
    ("Loader.py", "startLoader"),
]

for _path, _symbol in _REQUIRED_HELPERS:
    if _symbol not in globals():
        with open(_path, "r", encoding="utf-8") as _f:
            exec(_f.read(), globals())


def _print_input_block(route_context):
    print("TIIR PIPELINE REVIEW SUMMARY")
    print("=" * 72)
    print("A. INPUT")
    print(f"   Input kind: {route_context.get('input_kind')}")
    print(f"   Source: {route_context.get('source_name')}")
    preview = route_context.get("input_preview", "")
    if preview:
        print(f"   Preview: {preview}")
    if route_context.get("input_kind") == "json_file":
        summary = route_context.get("json_summary", {})
        print(f"   JSON root type: {summary.get('root_type')}")
        print(f"   JSON prebuilt CPEs: {summary.get('prebuilt_cpe_count')}")
        print(f"   Extracted text chars: {summary.get('description_chars')}")


def _print_resolution_block(route_context, inference_result=None):
    print("\nB. CPE RESOLUTION")
    print(f"   Route: {route_context.get('route')}")
    print(f"   Reason: {route_context.get('route_reason')}")

    if route_context.get("route") == "direct_cpe_path":
        prebuilt = route_context.get("prebuilt_cpes", [])
        print(f"   Inference skipped. Direct CPE evidence found: {len(prebuilt)}")
        for idx, comp in enumerate(prebuilt, start=1):
            print(f"   [{idx}] {comp.get('cpe23')} | {comp.get('grounding_status')} | source={comp.get('evidence_source')}")
    elif inference_result is not None:
        summary = inference_result["pipeline_summary"]
        print(
            f"   Components: {summary['components_total']} | grounded: {summary['grounded']} | "
            f"rejected: {summary['rejected']}"
        )
        print(f"   Generation time: {summary['generation_time_s']} s")
        for idx, comp in enumerate(inference_result["final_cpe_results"], start=1):
            print(
                f"   [{idx}] {comp.get('vendor')}/{comp.get('product')} -> {comp.get('cpe23')} | "
                f"score={comp.get('match_score')} | {comp.get('grounding_status')}"
            )
    else:
        print("   No resolvable text available. Pipeline cannot continue.")


def _print_orchestrator_block(stix_output, route_context):
    print("\nC. ORCHESTRATOR / CTI OBJECT")
    print(f"   CTI object written: Test_STIX.json")
    print(f"   Route mode: {route_context.get('route')}")
    print(f"   Primary CPE: {stix_output.get('cpe')}")
    print(f"   Detected CPE entries: {len(stix_output.get('x_detected_cpes', []))}")


def _print_permissions_block(loader_result):
    print("\nD. IMPACTED PERMISSIONS")
    perm_df = pd.DataFrame(loader_result["permission_hits"])
    if perm_df.empty:
        print("   No permission hits")
    else:
        columns = ["PermissionID", "LinkID", "Entitlement", "Criticality_before", "Criticality_after", "MatchLogic"]
        print(perm_df[columns].to_string(index=False))


def _print_accounts_block(loader_result):
    print("\nE. IMPACTED IDENTITIES")
    acc_df = pd.DataFrame(loader_result["account_hits"])
    if acc_df.empty:
        print("   No linked identities")
    else:
        columns = ["AccountID", "LinkID", "givenName", "lastName", "Team", "Function", "Action"]
        print(acc_df[columns].to_string(index=False))


def _print_outputs_block(loader_result):
    print("\nOUTPUT FILES")
    print(f"   STIX object: {os.path.basename(loader_result['files']['stix_object'])}")
    print(f"   Permission updates: {os.path.basename(loader_result['files']['permissions_modified'])}")
    print(f"   Account updates: {os.path.basename(loader_result['files']['accounts_modified'])}")
    print(f"   Modification report: {os.path.basename(loader_result['files']['report'])}")
    print(f"   Deterministic process log: {os.path.basename(loader_result['files']['tiir_process_log'])}")


def tiir_run_pipeline(input_payload=None, *, verbose=False, show_audit_json=False):
    if input_payload is None:
        input_payload = globals().get("input_payload", globals().get("input_text"))

    if input_payload is None:
        raise ValueError("No input_payload or input_text defined.")

    tiir_logger.reset({
        "component": "tiir_pipeline_runner",
        "input_payload_type": type(input_payload).__name__,
        "input_preview": str(input_payload)[:200],
    })

    route_context = tiir_route_input(input_payload)
    _print_input_block(route_context)

    if route_context["route"] == "error_no_text":
        _print_resolution_block(route_context, inference_result=None)
        tiir_logger.log("pipeline", "aborted_no_text", route_context, status="ERROR")
        return {"route_context": route_context, "status": "aborted_no_text"}

    inference_result = None
    final_cpe_results = route_context.get("prebuilt_cpes", [])

    if route_context["route"] == "inference_path":
        inference_result = tiir_run_text2cpe_inference(
            route_context["normalized_description"],
            verbose=verbose,
            show_audit_json=show_audit_json,
        )
        final_cpe_results = inference_result["final_cpe_results"]

    _print_resolution_block(route_context, inference_result=inference_result)

    stix_output = tiir_build_cti_object(
        description=route_context.get("normalized_description", ""),
        detected_cpes=final_cpe_results,
        route_context=route_context,
        output_stix_file="Test_STIX.json",
    )
    _print_orchestrator_block(stix_output, route_context)

    loader_result = startLoader(return_results=True, quiet=True)
    _print_permissions_block(loader_result)
    _print_accounts_block(loader_result)
    _print_outputs_block(loader_result)

    result = {
        "status": "completed",
        "route_context": route_context,
        "inference_result": inference_result,
        "stix_output": stix_output,
        "loader_result": loader_result,
    }
    tiir_logger.log("pipeline", "completed", {
        "status": result["status"],
        "route": route_context.get("route"),
        "permission_hits": loader_result["counts"]["permission_hits"],
        "account_hits": loader_result["counts"]["account_hits"],
    })
    return result


if globals().get("AUTO_RUN_TIIR_PIPELINE", True):
    _tiir_result = tiir_run_pipeline(
        input_payload=globals().get("input_payload", globals().get("input_text")),
        verbose=bool(globals().get("PIPELINE_VERBOSE", False)),
        show_audit_json=bool(globals().get("SHOW_AUDIT_JSON", False)),
    )
