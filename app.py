from flask import Flask, jsonify, render_template

from config import load_config
from detector import PresenceDetector


config = load_config()
detector = PresenceDetector(config)
app = Flask(__name__)


@app.route("/")
def index():
    frontend_config = {
        "pollingIntervalSeconds": config.polling_interval_seconds,
        "statusEndpoint": "/api/status",
        "debugEndpoint": "/api/devices/debug",
    }
    return render_template(
        "index.html",
        frontend_config=frontend_config,
        target_summary=config.target_summary,
    )


@app.route("/api/status")
def api_status():
    try:
        return jsonify(detector.get_status())
    except Exception as exc:  # pragma: no cover - defensive fallback
        return (
            jsonify(
                {
                    "present": False,
                    "status_text": "Status check failed",
                    "error": "unexpected_error",
                    "message": str(exc),
                }
            ),
            500,
        )


@app.route("/api/devices/debug")
def api_devices_debug():
    try:
        return jsonify(detector.inspect_devices())
    except Exception as exc:  # pragma: no cover - defensive fallback
        return jsonify({"error": "unexpected_error", "message": str(exc)}), 500


if __name__ == "__main__":
    app.run(host=config.bind_host, port=config.bind_port, debug=False)
