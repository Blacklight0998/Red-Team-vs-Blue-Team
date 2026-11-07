# Red Team contribution represented in this group repository: Andy Vega Araya.
# Executable logic preserved from the supplied Red Team module.
import json
from datetime import datetime
from pathlib import Path


def save_report(tool_name, target, data):
    reports_dir = Path(__file__).parent.parent / "reports"
    reports_dir.mkdir(exist_ok=True)

    report = {
        "tool": tool_name,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "target": target,
    }
    report.update(data)

    safe_target = target.replace("/", "_").replace("\\", "_").replace(":", "_")
    output = reports_dir / f"{tool_name}_{safe_target}_report.json"

    with output.open("w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=2)

    return output
