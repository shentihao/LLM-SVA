def calculate_confidence(item, llm_result):
    # Prototype weights from the paper methodology.
    w_llm, w_static, w_flow, w_path = 0.35, 0.20, 0.30, 0.15

    c_llm = float(llm_result.get("confidence", 0.0))
    c_static = 1.0 if item["verification"]["source_valid"] and item["verification"]["sink_valid"] else 0.0
    c_flow = 1.0 if item["verification"]["path_valid"] else 0.0
    c_path = 1.0 if item["verification"]["sanitization_absent"] else 0.0

    confidence = (
        w_llm * c_llm
        + w_static * c_static
        + w_flow * c_flow
        + w_path * c_path
    )

    if confidence >= 0.85:
        status = "CONFIRMED"
    elif confidence >= 0.60:
        status = "REVIEW"
    else:
        status = "LOW_CONFIDENCE"

    return {
        "confidence": round(confidence, 4),
        "status": status,
        "components": {
            "llm": round(c_llm, 4),
            "static": c_static,
            "flow": c_flow,
            "path": c_path
        }
    }
