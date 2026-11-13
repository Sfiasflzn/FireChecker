
from flask import Flask, render_template, request, session
from werkzeug.utils import secure_filename
import os

# FireChecker modules
from config_reader import read_config, parse_acl_rules
from rule_checker import check_acl_rules
from risk_analyzer import calculate_risk
from report_generator import generate_report


app = Flask(__name__)
app.secret_key = "firechecker_secret_key"

UPLOAD_FOLDER = "uploads"
OUTPUT_FOLDER = "output"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)


@app.route("/")
def home():

    result = session.get("analysis_result", {})

    return render_template(
        "index.html",
        total_rules=result.get("total_rules"),
        total_findings=result.get("total_findings"),
        risk_level=result.get("risk_level")
    )


@app.route("/upload", methods=["POST"])
def upload_file():

    if "config_file" not in request.files:
        return "No file selected"

    file = request.files["config_file"]

    if file.filename == "":
        return "No file selected"

    allowed_extensions = (".txt", ".cfg")

    if not file.filename.lower().endswith(allowed_extensions):
        return "Invalid file format. Please upload .txt or .cfg"

    filename = secure_filename(file.filename)

    if not filename:
        return "Invalid filename"

    filepath = os.path.join(
        app.config["UPLOAD_FOLDER"],
        filename
    )

    file.save(filepath)

    try:
        # Step 1: Read configuration
        config_lines = read_config(filepath)

        # Step 2: Parse ACL rules
        rules = parse_acl_rules(config_lines)

        # Step 3: Check security rules
        findings = check_acl_rules(rules)

        # Step 4: Calculate risk
        summary = calculate_risk(findings)

        # Save latest analysis results
        session["analysis_result"] = {
            "total_rules": len(rules),
            "total_findings": len(findings),
            "risk_level": summary.get("risk_level")
        }

        # Step 5: Generate JSON report
        report_path = os.path.join(
            OUTPUT_FOLDER,
            "firechecker_report.json"
        )

        generate_report(
            findings,
            summary,
            report_path
        )

        # Display analysis results
        return render_template(
            "results.html",
            filename=filename,
            total_rules=len(rules),
            findings=findings,
            summary=summary
        )

    except Exception as error:
        app.logger.exception("FireChecker analysis failed")
        return f"Analysis failed: {error}", 500


if __name__ == "__main__":
    app.run(debug=True)
