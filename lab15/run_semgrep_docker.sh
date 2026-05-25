#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Запуск Semgrep ===${NC}"

BASE_DIR="$(pwd)"
REPORT_DIR="${BASE_DIR}/reports"
RULES_DIR="${BASE_DIR}/semgrep-rules-develop"

mkdir -p "$REPORT_DIR"

REPORT_TXT="${REPORT_DIR}/semgrep-report.txt"
REPORT_JSON="${REPORT_DIR}/semgrep-owasp.json"
REPORT_HTML="${REPORT_DIR}/semgrep-owasp.html"
PYTHON_SCRIPT="${REPORT_DIR}/convert_to_html.py"

rm -f "$REPORT_TXT" "$REPORT_JSON" "$REPORT_HTML" "$PYTHON_SCRIPT"

SEMGREP_IMAGE="9349edbadf90"
PYTHON_IMAGE="a7185a8e40af"

BASE_CONFIG_ARGS="--config /rules/python --config /rules/javascript --config /rules/generic"
OWASP_CONFIG_ARGS="--config /rules/python --config /rules/javascript --config /rules/generic --config /rules/problem-based-packs"

run_scan() {
    local config_args=$1
    local output_file=$2
    local is_json=$3
    local json_flag=""
    local quiet_flag=""

    if [ "$is_json" == "true" ]; then
        json_flag="--json"
        quiet_flag="--quiet"
    fi

    docker run --rm \
        -v "${BASE_DIR}:/src" \
        -v "${RULES_DIR}:/rules:ro" \
        -e SEMGREP_SEND_METRICS=off \
        -e SEMGREP_APP_TOKEN= \
        -e SEMGREP_VERSION_CHECK=off \
        "${SEMGREP_IMAGE}" \
        semgrep ${config_args} ./backend ./frontend ${json_flag} ${quiet_flag} --no-rewrite-rule-ids > "${output_file}" 2>&1
    return $?
}

# 1. Базовый анализ
echo -e "${GREEN}[1/4] Базовый анализ...${NC}"
run_scan "${BASE_CONFIG_ARGS}" "${REPORT_TXT}" "false"
if [ -s "${REPORT_TXT}" ]; then
    echo "   Отчет сохранен: ${REPORT_TXT}"
else
    echo "   Warning: Отчет пуст"
fi

# 2. OWASP анализ
echo -e "${GREEN}[2/4] OWASP анализ...${NC}"
run_scan "${OWASP_CONFIG_ARGS}" "${REPORT_JSON}" "true"
if [ -s "${REPORT_JSON}" ] && head -c 1 "${REPORT_JSON}" | grep -q "{"; then
    COUNT=$(grep -o '"check_id"' "${REPORT_JSON}" | wc -l)
    echo "   Отчет сохранен: ${REPORT_JSON} (Найдено: ${COUNT})"
else
    echo "   Warning: JSON некорректен"
    echo '{"results": [], "errors": [{"message": "Scan failed"}]}' > "${REPORT_JSON}"
fi

# 3. Генерация HTML
echo -e "${GREEN}[3/4] Генерация HTML...${NC}"
cat > "${PYTHON_SCRIPT}" << 'PYEOF'
import json
import sys
import os
input_file = sys.argv[1]
output_file = sys.argv[2]
SRC_ROOT = "/src"
def get_code_snippet(path, start_line, context=2):
    full_path = os.path.join(SRC_ROOT, path)
    if not os.path.exists(full_path):
        return None
    try:
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        start_idx = max(0, start_line - 1 - context)
        end_idx = min(len(lines), start_line + context)
        snippet_lines = lines[start_idx:end_idx]
        formatted = []
        for i, line in enumerate(snippet_lines):
            line_num = start_idx + i + 1
            marker = ">>>" if line_num == start_line else "   "
            formatted.append(f"{marker} {line_num}: {l.rstrip()}")
        return "\n".join(formatted)
    except Exception:
        return None
def get_severity_sort_key(severity):
    order = {"HIGH": 0, "WARNING": 1, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    return order.get(severity.upper(), 4)
data = {"results": [], "errors": []}
try:
    if os.path.exists(input_file):
        with open(input_file, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if content:
                data = json.loads(content)
except Exception as e:
    data["errors"].append({"message": str(e)})
results = data.get("results", [])
errors = data.get("errors", [])
results.sort(key=lambda x: get_severity_sort_key(x.get("severity", "INFO")))
html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Semgrep Security Report (OWASP)</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f4f6f8; color: #333; line-height: 1.6; margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 15px; margin-bottom: 30px; }}
        h2 {{ font-size: 1.2em; color: #2c3e50; margin-top: 0; }}
        .stats {{ display: flex; gap: 20px; margin-bottom: 30px; flex-wrap: wrap; }}
        .stat-card {{ background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); flex: 1; min-width: 200px; text-align: center; border-top: 4px solid #3498db; }}
        .stat-val {{ font-size: 2.5em; font-weight: bold; display: block; }}
        .val-high {{ color: #e74c3c; }} .val-med {{ color: #f39c12; }} .val-low {{ color: #3498db; }}
        .issue-card {{ background: #fff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); margin-bottom: 25px; overflow: hidden; border-left: 6px solid #ccc; }}
        .issue-card.HIGH {{ border-left-color: #e74c3c; }}
        .issue-card.MEDIUM {{ border-left-color: #f39c12; }}
        .issue-card.LOW {{ border-left-color: #3498db; }}
        .issue-card.INFO {{ border-left-color: #95a5a6; }}
        .card-header {{ padding: 15px 20px; background: #f8f9fa; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; }}
        .rule-id {{ font-family: monospace; font-size: 1.1em; font-weight: bold; color: #2c3e50; }}
        .badge {{ padding: 4px 10px; border-radius: 20px; font-size: 0.85em; font-weight: bold; text-transform: uppercase; color: #fff; }}
        .bg-HIGH {{ background: #e74c3c; }} .bg-MEDIUM {{ background: #f39c12; color: #333; }} .bg-LOW {{ background: #3498db; }} .bg-INFO {{ background: #95a5a6; }}
        .card-body {{ padding: 20px; }}
        .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-bottom: 20px; background: #f8f9fa; padding: 15px; border-radius: 6px; }}
        .meta-item {{ font-size: 0.9em; }}
        .meta-label {{ font-weight: bold; color: #7f8c8d; display: block; margin-bottom: 3px; }}
        .meta-value {{ color: #2c3e50; word-break: break-word; }}
        .tag {{ display: inline-block; background: #e9ecef; padding: 2px 8px; border-radius: 4px; margin-right: 5px; margin-bottom: 5px; font-size: 0.85em; color: #495057; }}
        .tag-owasp {{ background: #e8f4fd; color: #0d6efd; border: 1px solid #b6d4fe; }}
        .tag-cwe {{ background: #f8d7da; color: #842029; border: 1px solid #f1aeb5; }}
        .message-box {{ margin: 15px 0; padding: 15px; background: #fff3cd; border: 1px solid #ffecb5; border-radius: 6px; color: #664d03; }}
        .code-block {{ background: #282c34; color: #abb2bf; padding: 15px; border-radius: 6px; overflow-x: auto; font-family: "Consolas", "Monaco", monospace; font-size: 0.9em; border: 1px solid #444; white-space: pre; }}
        .refs {{ margin-top: 15px; font-size: 0.9em; }}
        .refs a {{ color: #3498db; text-decoration: none; margin-right: 15px; }}
        .refs a:hover {{ text-decoration: underline; }}
        .location {{ font-family: monospace; color: #666; background: #eee; padding: 2px 6px; border-radius: 4px; }}
    </style>
</head>
<body>
<div class="container">
    <h1>🛡️ Отчет Semgrep: OWASP Top 10 & Security</h1>
    <div class="stats">
        <div class="stat-card" style="border-top-color: #e74c3c;">
            <span class="stat-val val-high">{len([r for r in results if r.get('severity','').upper() == 'HIGH'])}</span>
            <span>High Severity</span>
        </div>
        <div class="stat-card" style="border-top-color: #f39c12;">
            <span class="stat-val val-med">{len([r for r in results if r.get('severity','').upper() in ['MEDIUM', 'WARNING']])}</span>
            <span>Medium Severity</span>
        </div>
        <div class="stat-card" style="border-top-color: #3498db;">
            <span class="stat-val val-low">{len([r for r in results if r.get('severity','').upper() in ['LOW', 'INFO']])}</span>
            <span>Low Severity</span>
        </div>
        <div class="stat-card">
            <span class="stat-val" style="color:#7f8c8d">{len(results)}</span>
            <span>Всего найдено</span>
        </div>
    </div>
"""
if errors:
    html += "<div style='background:#fadbd8;color:#922b21;padding:15px;border-radius:6px;margin-bottom:20px;'><strong>⚠️ Ошибки сканирования:</strong><br>"
    for e in errors: html += f"- {e.get('message', '')}<br>"
    html += "</div>"
if not results:
    html += "<div style='text-align:center;padding:40px;background:#fff;border-radius:8px;'><h2>✅ Уязвимостей не найдено</h2></div>"
else:
    for r in results:
        sev = r.get("severity", "INFO").upper()
        check_id = r.get("check_id", "Unknown")
        path = r.get("path", "unknown")
        line = r.get("start", {}).get("line", "?")
        col = r.get("start", {}).get("col", "?")
        extra = r.get("extra", {})
        message = extra.get("message", "No description")
        metadata = extra.get("metadata", {})
        owasp_tags = metadata.get("owasp", [])
        cwe_tags = metadata.get("cwe", [])
        refs = metadata.get("references", [])
        impact = metadata.get("impact", "")
        likelihood = metadata.get("likelihood", "")
        confidence = metadata.get("confidence", "")
        category = metadata.get("category", "")
        snippet = get_code_snippet(path, line)
        if not snippet:
            snippet = f"# Code unavailable for {path}:{line}"
        snippet_escaped = snippet.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        owasp_html = "".join([f'<span class="tag tag-owasp">{tag}</span>' for tag in owasp_tags])
        if not owasp_html: owasp_html = "<span style='color:#999'>No OWASP mapping</span>"
        cwe_html = "".join([f'<span class="tag tag-cwe">{tag}</span>' for tag in cwe_tags])
        if not cwe_html: cwe_html = "<span style='color:#999'>No CWE mapping</span>"
        refs_html = ""
        if refs:
            refs_html = "<div class='refs'><strong>📚 Ресурсы:</strong><br>"
            for ref in refs:
                refs_html += f'<a href="{ref}" target="_blank">🔗 {ref[:60]}...</a>'
            refs_html += "</div>"
        risk_info = ""
        if impact or likelihood or confidence:
            risk_info = f"""
            <div class="meta-item"><span class="meta-label">Impact:</span> <span class="meta-value">{impact or '-'}</span></div>
            <div class="meta-item"><span class="meta-label">Likelihood:</span> <span class="meta-value">{likelihood or '-'}</span></div>
            <div class="meta-item"><span class="meta-label">Confidence:</span> <span class="meta-value">{confidence or '-'}</span></div>
            """
        html += f"""
        <div class="issue-card {sev}">
            <div class="card-header">
                <div>
                    <div class="rule-id">{check_id}</div>
                    <div style="font-size:0.9em; color:#666; margin-top:4px;">
                        📍 <span class="location">{path}</span> : строка {line}, колонка {col}
                    </div>
                </div>
                <span class="badge bg-{sev}">{sev}</span>
            </div>
            <div class="card-body">
                <div class="message-box">{message}</div>
                <div class="meta-grid">
                    <div class="meta-item" style="grid-column: 1 / -1;">
                        <span class="meta-label">OWASP Categories:</span>
                        <div style="margin-top:5px;">{owasp_html}</div>
                    </div>
                    <div class="meta-item" style="grid-column: 1 / -1;">
                        <span class="meta-label">CWE:</span>
                        <div style="margin-top:5px;">{cwe_html}</div>
                    </div>
                    {risk_info}
                    <div class="meta-item"><span class="meta-label">Category:</span> <span class="meta-value">{category or 'security'}</span></div>
                </div>
                <div style="margin-top:20px;"><strong>💻 Уязвимый код:</strong></div>
                <div class="code-block">{snippet_escaped}</div>
                {refs_html}
            </div>
        </div>
        """
html += """
</div>
<footer style="text-align:center;margin-top:50px;color:#999;font-size:0.8em;">
    Generated by Semgrep Docker Wrapper • Local Offline Mode
</footer>
</body>
</html>
"""
with open(output_file, "w", encoding="utf-8") as f:
    f.write(html)
print(f"HTML saved: {output_file}")
PYEOF

CONTAINER_INPUT="/src/reports/semgrep-owasp.json"
CONTAINER_OUTPUT="/src/reports/semgrep-owasp.html"
CONTAINER_SCRIPT="/src/reports/convert_to_html.py"

docker run --rm \
    -v "${BASE_DIR}:/src" \
    "${PYTHON_IMAGE}" \
    python3 "${CONTAINER_SCRIPT}" "${CONTAINER_INPUT}" "${CONTAINER_OUTPUT}"

if [ -f "$REPORT_HTML" ]; then
    sudo chown -R "$(whoami)":"$(whoami)" "$REPORT_DIR" 2>/dev/null || true
    echo -e "${GREEN}✅ ГОТОВО!${NC}"
    ls -lh "$REPORT_DIR"
    echo -e "🌐 Отчет: ${REPORT_HTML}"
else
    echo -e "${RED}Ошибка создания HTML.${NC}"
    exit 1
fi
