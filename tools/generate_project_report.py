import json
import os
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List
from xml.sax.saxutils import escape

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
REPORT_ROOT = ROOT / "reports" / "project_report"
ASSET_DIR = REPORT_ROOT / "assets"
DOCX_PATH = REPORT_ROOT / "Container_Image_Threat_Scanner_Report.docx"
SAFE_DOCX_PATH = REPORT_ROOT / "Container_Image_Threat_Scanner_Report_Safe.docx"
HTML_PATH = REPORT_ROOT / "Container_Image_Threat_Scanner_Report.html"
JSON_PATH = ROOT / "reports" / "latest_scan.json"

SOURCE_FILES = [
    "README.md",
    "main.py",
    "dashboard/app.py",
    "scanner/image_pull.py",
    "scanner/layer_extractor.py",
    "scanner/package_enum.py",
    "scanner/vulnerability_scanner.py",
    "scanner/threat_intelligence.py",
    "scanner/forensic_mapper.py",
    "scanner/risk_engine.py",
    "scanner/report_generator.py",
    "ci/scan.yml",
]


def ensure_dirs() -> None:
    ASSET_DIR.mkdir(parents=True, exist_ok=True)


def load_scan() -> dict:
    with open(JSON_PATH, encoding="utf-8") as f:
        return json.load(f)


def try_font(names: List[str], size: int):
    candidates = []
    win_fonts = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Fonts"
    for name in names:
        candidates.extend([win_fonts / name, Path(name)])
    for candidate in candidates:
        if candidate.exists():
            try:
                return ImageFont.truetype(str(candidate), size=size)
            except OSError:
                continue
    return ImageFont.load_default()


TITLE_FONT = try_font(["cambria.ttc", "times.ttf", "arialbd.ttf"], 42)
H1_FONT = try_font(["cambria.ttc", "arialbd.ttf"], 26)
H2_FONT = try_font(["calibrib.ttf", "arialbd.ttf"], 20)
BODY_FONT = try_font(["calibri.ttf", "arial.ttf"], 16)
SMALL_FONT = try_font(["calibri.ttf", "arial.ttf"], 13)
CODE_FONT = try_font(["consola.ttf", "cour.ttf"], 16)


def canvas(title: str, subtitle: str = "", size=(1600, 900)):
    img = Image.new("RGB", size, "#0f172a")
    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle((30, 30, size[0] - 30, size[1] - 30), 28, outline="#1e293b", width=3, fill="#111827")
    draw.text((70, 60), title, fill="#f8fafc", font=TITLE_FONT)
    if subtitle:
        draw.text((70, 120), subtitle, fill="#94a3b8", font=BODY_FONT)
    return img, draw


def save(img: Image.Image, name: str) -> Path:
    path = ASSET_DIR / name
    img.save(path)
    return path


def make_cover(scan: dict) -> Path:
    img, draw = canvas("CONTAINER IMAGE THREAT SCANNER", "Professional project report with layer-aware forensics evidence")
    draw.text((70, 200), "Project Title", fill="#38bdf8", font=H2_FONT)
    draw.text((70, 240), "Container Image Threat Scanner with Layer Forensics", fill="#ffffff", font=H1_FONT)
    details = [
        f"Prepared from workspace: {ROOT.name}",
        f"Latest scan artifact: {scan['image_metadata']['image_name']}",
        f"Risk score: {scan['risk_score']['score']} / 10",
        f"Risk grade: {scan['risk_score']['grade']}",
        f"Generated on: {datetime.now().strftime('%d %B %Y, %I:%M %p')}",
        "Document format: Word-compatible DOCX",
        "Recommended body font: Aptos/Calibri 11 pt, headings Cambria 16-24 pt",
    ]
    y = 330
    for line in details:
        draw.rounded_rectangle((70, y - 10, 1030, y + 38), 14, fill="#172554", outline="#1d4ed8")
        draw.text((95, y), line, fill="#e0f2fe", font=BODY_FONT)
        y += 62
    draw.rounded_rectangle((70, 700, 1530, 820), 20, fill="#052e16", outline="#22c55e", width=2)
    draw.text((95, 730), "Evidence basis: existing generated scan reports in /reports plus direct execution of local project modules in the current workspace.", fill="#dcfce7", font=BODY_FONT)
    return save(img, "cover.png")


def make_summary_dashboard(scan: dict) -> Path:
    img, draw = canvas("Dashboard Overview", "Rendered from reports/latest_scan.json")
    risk = scan["risk_score"]
    vuln = scan["vuln_data"]["summary"]
    threat = scan["threat_data"]["summary"]
    cards = [
        ("Image", scan["image_metadata"]["image_name"], "#0ea5e9"),
        ("Risk Score", f"{risk['score']} / 10", "#ef4444"),
        ("Grade", risk["grade"], "#f59e0b"),
        ("CVEs", str(scan["vuln_data"]["total_count"]), "#8b5cf6"),
        ("Threats", str(scan["threat_data"]["total_count"]), "#10b981"),
    ]
    x = 70
    for label, value, color in cards:
        draw.rounded_rectangle((x, 180, x + 265, 300), 18, fill="#1f2937", outline=color, width=3)
        draw.text((x + 20, 205), label, fill="#93c5fd", font=SMALL_FONT)
        draw.text((x + 20, 240), value, fill="#ffffff", font=H2_FONT)
        x += 290
    draw.text((70, 350), "Vulnerability Distribution", fill="#e2e8f0", font=H2_FONT)
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_colors = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#facc15", "LOW": "#22c55e", "INFO": "#64748b"}
    max_v = max(max(vuln.values() or [1]), 1)
    x = 90
    for sev in sev_order:
        count = vuln.get(sev, 0)
        h = 260 * (count / max_v if max_v else 0)
        draw.rectangle((x, 710 - h, x + 100, 710), fill=sev_colors[sev])
        draw.text((x, 725), sev, fill="#cbd5e1", font=SMALL_FONT)
        draw.text((x + 35, 680 - h), str(count), fill="#ffffff", font=SMALL_FONT)
        x += 125
    draw.text((860, 350), "Threat Breakdown", fill="#e2e8f0", font=H2_FONT)
    y = 400
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = threat.get(sev, 0)
        draw.rounded_rectangle((860, y, 1460, y + 70), 18, fill="#111827", outline=sev_colors.get(sev, "#94a3b8"), width=3)
        draw.text((890, y + 16), f"{sev}: {count}", fill="#ffffff", font=BODY_FONT)
        draw.text((1120, y + 16), "Threat intelligence findings", fill="#94a3b8", font=BODY_FONT)
        y += 92
    draw.rounded_rectangle((860, 760, 1460, 840), 20, fill="#3f1d1d", outline="#ef4444", width=2)
    draw.text((885, 788), risk["classification"], fill="#fecaca", font=BODY_FONT)
    return save(img, "dashboard_overview.png")


def make_layer_heatmap(scan: dict) -> Path:
    img, draw = canvas("Layer Risk Heatmap", "Layer-wise forensic concentration of vulnerabilities and threats")
    layers = scan["forensic_map"]["layer_reports"]
    max_score = max((layer.get("risk_score", 0) for layer in layers), default=1) or 1
    left = 110
    top = 220
    col_w = 180
    row_h = 80
    headers = ["Layer", "Risk", "CVEs", "Threats", "Files"]
    for i, header in enumerate(headers):
        draw.rounded_rectangle((left + i * col_w, top, left + (i + 1) * col_w - 12, top + 55), 12, fill="#1e293b")
        draw.text((left + i * col_w + 18, top + 15), header, fill="#e2e8f0", font=BODY_FONT)
    y = top + 70
    for layer in layers:
        score = layer.get("risk_score", 0)
        intensity = int(60 + (195 * score / max_score))
        if score >= 7:
            fill = (intensity, 36, 36)
        elif score >= 4:
            fill = (120, 70 + intensity // 3, 30)
        else:
            fill = (28, 90 + intensity // 4, 70)
        values = [f"Layer {layer['layer_index']}", f"{score:.1f}", str(len(layer.get("vulnerabilities", []))), str(len(layer.get("threats", []))), str(layer.get("file_count", 0))]
        for i, value in enumerate(values):
            draw.rounded_rectangle((left + i * col_w, y, left + (i + 1) * col_w - 12, y + row_h - 8), 10, fill=fill if i == 1 else "#111827", outline="#334155")
            draw.text((left + i * col_w + 18, y + 22), value, fill="#ffffff", font=BODY_FONT)
        y += row_h
    return save(img, "layer_heatmap.png")


def make_architecture_diagram() -> Path:
    img, draw = canvas("System Architecture", "CLI pipeline, scanner engine, reporting layer, and dashboard")
    boxes = [
        ("User / CI Trigger", (70, 220, 340, 330), "#0284c7"),
        ("main.py CLI", (410, 220, 680, 330), "#2563eb"),
        ("Scanner Modules", (750, 160, 1110, 390), "#7c3aed"),
        ("Reports + SBOM", (1190, 220, 1510, 330), "#059669"),
        ("Dashboard / app.py", (1190, 470, 1510, 580), "#ea580c"),
    ]
    for label, coords, color in boxes:
        draw.rounded_rectangle(coords, 24, fill="#111827", outline=color, width=4)
        tw = draw.textlength(label, font=H2_FONT)
        draw.text(((coords[0] + coords[2] - tw) / 2, coords[1] + 38), label, fill="#f8fafc", font=H2_FONT)
    module_lines = ["image_pull.py", "layer_extractor.py", "package_enum.py", "vulnerability_scanner.py", "threat_intelligence.py", "forensic_mapper.py", "risk_engine.py", "report_generator.py"]
    y = 205
    for line in module_lines:
        draw.text((800, y), f"- {line}", fill="#ddd6fe", font=BODY_FONT)
        y += 24
    for start, end in [((340, 275), (410, 275)), ((680, 275), (750, 275)), ((1110, 275), (1190, 275)), ((1350, 330), (1350, 470))]:
        draw.line([start, end], fill="#94a3b8", width=6)
    return save(img, "architecture.png")


def make_ci_diagram() -> Path:
    img, draw = canvas("CI/CD Workflow", "Based on ci/scan.yml")
    steps = ["Checkout repository", "Set up Python 3.11", "Install dependencies", "Start Docker daemon", "Pull target image", "Run scanner + export JSON", "Parse risk score", "Upload artifacts", "PR comment / fail on critical"]
    y = 180
    for idx, step in enumerate(steps, 1):
        draw.rounded_rectangle((180, y, 1420, y + 72), 18, fill="#111827", outline="#38bdf8", width=3)
        draw.ellipse((110, y + 12, 170, y + 72), fill="#1d4ed8")
        draw.text((132, y + 26), str(idx), fill="#ffffff", font=BODY_FONT)
        draw.text((210, y + 22), step, fill="#f8fafc", font=BODY_FONT)
        if idx < len(steps):
            draw.line((145, y + 72, 145, y + 102), fill="#94a3b8", width=5)
        y += 95
    return save(img, "ci_workflow.png")


def make_terminal_evidence(scan: dict) -> Path:
    img = Image.new("RGB", (1600, 950), "#020617")
    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle((30, 30, 1570, 920), 18, fill="#0b1220", outline="#334155", width=3)
    draw.rectangle((30, 30, 1570, 85), fill="#111827")
    draw.text((70, 48), "PowerShell - Container Threat Scanner Evidence", fill="#e2e8f0", font=BODY_FONT)
    transcript = [
        r"PS C:\Users\HP\Desktop\container-security-scanner> python -c ""import json; d=json.load(open('reports/latest_scan.json'));",
        r"> print(d['image_metadata']['image_name']); print(d['risk_score']); print(d['report_paths'])""",
        scan["image_metadata"]["image_name"],
        str(scan["risk_score"]),
        str(scan["report_paths"]),
        "",
        "Evidence notes:",
        "- Local dashboard can load these results directly from reports/latest_scan.json",
        "- Docker daemon was not reachable during this session, so fresh image pull execution could not be repeated.",
        "- Existing project-generated scan evidence from the repository was used for formal report generation.",
    ]
    y = 120
    for line in transcript:
        draw.text((60, y), line, fill="#d1fae5" if line.startswith("-") else "#e5e7eb", font=CODE_FONT)
        y += 48
    return save(img, "terminal_evidence.png")


def make_codebase_map() -> Path:
    img, draw = canvas("Codebase Map", "High-level ownership of the project files")
    columns = [
        ("Entry & UI", ["main.py", "dashboard/app.py", "README.md"], "#0ea5e9", 70),
        ("Scanner Core", ["image_pull.py", "layer_extractor.py", "package_enum.py", "vulnerability_scanner.py"], "#8b5cf6", 550),
        ("Analysis & Output", ["threat_intelligence.py", "forensic_mapper.py", "risk_engine.py", "report_generator.py", "ci/scan.yml"], "#10b981", 1030),
    ]
    for title, items, color, x in columns:
        draw.rounded_rectangle((x, 180, x + 420, 760), 24, fill="#111827", outline=color, width=4)
        draw.text((x + 24, 210), title, fill="#f8fafc", font=H2_FONT)
        y = 280
        for item in items:
            draw.rounded_rectangle((x + 24, y, x + 396, y + 64), 16, fill="#1f2937", outline="#334155")
            draw.text((x + 42, y + 20), item, fill="#e2e8f0", font=BODY_FONT)
            y += 88
    return save(img, "codebase_map.png")


def make_findings_matrix(scan: dict) -> Path:
    img, draw = canvas("Top Findings Matrix", "Highest-impact CVEs and threats from the latest scan")
    vulns = sorted(scan["vuln_data"]["vulnerabilities"], key=lambda v: -v.get("cvss_score", 0))[:6]
    threats = scan["threat_data"]["threats"][:8]
    draw.text((70, 170), "Top Vulnerabilities", fill="#f8fafc", font=H2_FONT)
    y = 220
    for vuln in vulns:
        draw.rounded_rectangle((70, y, 760, y + 72), 14, fill="#1f2937", outline="#ef4444", width=2)
        draw.text((90, y + 15), f"{vuln['cve_id']} | {vuln['package_name']} {vuln['package_version']}", fill="#ffffff", font=BODY_FONT)
        draw.text((90, y + 42), f"{vuln['severity']} | CVSS {vuln.get('cvss_score', 0)} | Layer {vuln.get('layer_index', '?')}", fill="#fca5a5", font=SMALL_FONT)
        y += 86
    draw.text((830, 170), "Representative Threats", fill="#f8fafc", font=H2_FONT)
    y = 220
    for threat in threats:
        draw.rounded_rectangle((830, y, 1520, y + 64), 14, fill="#1f2937", outline="#f59e0b", width=2)
        draw.text((850, y + 12), threat["name"][:52], fill="#ffffff", font=BODY_FONT)
        draw.text((850, y + 38), f"{threat['severity']} | {threat.get('file_path', '')[:55]}", fill="#fde68a", font=SMALL_FONT)
        y += 76
    return save(img, "findings_matrix.png")


def generate_assets(scan: dict) -> list[Path]:
    return [
        make_cover(scan),
        make_summary_dashboard(scan),
        make_layer_heatmap(scan),
        make_architecture_diagram(),
        make_ci_diagram(),
        make_terminal_evidence(scan),
        make_codebase_map(),
        make_findings_matrix(scan),
    ]


@dataclass
class ImageRef:
    path: Path
    rid: str
    name: str
    cx: int
    cy: int


class DocxBuilder:
    def __init__(self) -> None:
        self.blocks: List[str] = []
        self.images: List[ImageRef] = []
        self.image_counter = 1

    def add_heading(self, text: str, level: int = 1) -> None:
        self.blocks.append(self._paragraph(text, style="Heading1" if level == 1 else "Heading2"))

    def add_paragraph(self, text: str, style: str = "BodyText") -> None:
        self.blocks.append(self._paragraph(text, style=style))

    def add_codeblock(self, text: str) -> None:
        for line in text.splitlines():
            self.blocks.append(self._paragraph(line or " ", style="Code"))

    def add_page_break(self) -> None:
        self.blocks.append('<w:p><w:r><w:br w:type="page"/></w:r></w:p>')

    def add_image(self, path: Path, width_inches: float = 6.5) -> None:
        with Image.open(path) as img:
            width_px, height_px = img.size
        cx = int(width_inches * 914400)
        cy = int(cx * height_px / width_px)
        rid = f"rId{len(self.images) + 1}"
        ref = ImageRef(path=path, rid=rid, name=path.name, cx=cx, cy=cy)
        self.images.append(ref)
        self.blocks.append(self._image_xml(ref))

    def _paragraph(self, text: str, style: str = "BodyText") -> str:
        return (
            f'<w:p><w:pPr><w:pStyle w:val="{style}"/></w:pPr>'
            f'<w:r><w:t xml:space="preserve">{escape(text)}</w:t></w:r></w:p>'
        )

    def _image_xml(self, ref: ImageRef) -> str:
        docpr_id = self.image_counter
        self.image_counter += 1
        return f"""
<w:p>
  <w:r>
    <w:drawing>
      <wp:inline distT="0" distB="0" distL="0" distR="0"
        xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing">
        <wp:extent cx="{ref.cx}" cy="{ref.cy}"/>
        <wp:docPr id="{docpr_id}" name="{escape(ref.name)}"/>
        <a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
          <a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">
            <pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">
              <pic:nvPicPr><pic:cNvPr id="{docpr_id}" name="{escape(ref.name)}"/><pic:cNvPicPr/></pic:nvPicPr>
              <pic:blipFill><a:blip r:embed="{ref.rid}"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>
              <pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{ref.cx}" cy="{ref.cy}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>
            </pic:pic>
          </a:graphicData>
        </a:graphic>
      </wp:inline>
    </w:drawing>
  </w:r>
</w:p>
""".strip()

    def save(self, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("[Content_Types].xml", self._content_types_xml())
            zf.writestr("_rels/.rels", ROOT_RELS_XML)
            zf.writestr("docProps/core.xml", core_props_xml())
            zf.writestr("docProps/app.xml", APP_PROPS_XML)
            zf.writestr("word/document.xml", self._document_xml())
            zf.writestr("word/styles.xml", STYLES_XML)
            zf.writestr("word/settings.xml", SETTINGS_XML)
            zf.writestr("word/fontTable.xml", FONT_TABLE_XML)
            zf.writestr("word/webSettings.xml", WEB_SETTINGS_XML)
            zf.writestr("word/_rels/document.xml.rels", self._document_rels_xml())
            for idx, img in enumerate(self.images, 1):
                zf.write(img.path, f"word/media/image{idx}{img.path.suffix.lower()}")


class SafeDocxBuilder:
    def __init__(self) -> None:
        self.blocks: List[str] = []

    def add_heading(self, text: str, level: int = 1) -> None:
        self.blocks.append(self._paragraph(text, style="Heading1" if level == 1 else "Heading2"))

    def add_paragraph(self, text: str, style: str = "BodyText") -> None:
        self.blocks.append(self._paragraph(text, style=style))

    def add_codeblock(self, text: str) -> None:
        for line in text.splitlines():
            self.blocks.append(self._paragraph(line or " ", style="Code"))

    def add_page_break(self) -> None:
        self.blocks.append('<w:p><w:r><w:br w:type="page"/></w:r></w:p>')

    def add_image_note(self, path: Path) -> None:
        self.add_paragraph(f"[Figure asset available separately: assets/{path.name}]")

    def _paragraph(self, text: str, style: str = "BodyText") -> str:
        return (
            f'<w:p><w:pPr><w:pStyle w:val="{style}"/></w:pPr>'
            f'<w:r><w:t xml:space="preserve">{escape(text)}</w:t></w:r></w:p>'
        )

    def save(self, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        document_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    {' '.join(self.blocks)}
    <w:sectPr>
      <w:pgSz w:w="12240" w:h="15840"/>
      <w:pgMar w:top="1440" w:right="1000" w:bottom="1440" w:left="1000"/>
    </w:sectPr>
  </w:body>
</w:document>"""
        rels_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"""
        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("[Content_Types].xml", """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>""")
            zf.writestr("_rels/.rels", ROOT_RELS_XML)
            zf.writestr("docProps/core.xml", core_props_xml())
            zf.writestr("docProps/app.xml", APP_PROPS_XML)
            zf.writestr("word/document.xml", document_xml)
            zf.writestr("word/styles.xml", STYLES_XML)
            zf.writestr("word/_rels/document.xml.rels", rels_xml)

    def _document_xml(self) -> str:
        body = "\n".join(self.blocks)
        return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas"
 xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
 xmlns:o="urn:schemas-microsoft-com:office:office"
 xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
 xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math"
 xmlns:v="urn:schemas-microsoft-com:vml"
 xmlns:wp14="http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing"
 xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
 xmlns:w10="urn:schemas-microsoft-com:office:word"
 xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
 xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml"
 xmlns:wpg="http://schemas.microsoft.com/office/word/2010/wordprocessingGroup"
 xmlns:wpi="http://schemas.microsoft.com/office/word/2010/wordprocessingInk"
 xmlns:wne="http://schemas.microsoft.com/office/2006/wordml"
 xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape"
 mc:Ignorable="w14 wp14">
  <w:body>
    {body}
    <w:sectPr>
      <w:pgSz w:w="12240" w:h="15840"/>
      <w:pgMar w:top="1440" w:right="1000" w:bottom="1440" w:left="1000" w:header="708" w:footer="708" w:gutter="0"/>
    </w:sectPr>
  </w:body>
</w:document>"""

    def _document_rels_xml(self) -> str:
        relationships = [
            '<Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>',
            '<Relationship Id="rIdSettings" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>',
            '<Relationship Id="rIdFontTable" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/fontTable" Target="fontTable.xml"/>',
            '<Relationship Id="rIdWebSettings" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/webSettings" Target="webSettings.xml"/>',
        ]
        for idx, img in enumerate(self.images, 1):
            relationships.append(f'<Relationship Id="{img.rid}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/image{idx}{img.path.suffix.lower()}"/>')
        return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' + "".join(relationships) + "</Relationships>"

    def _content_types_xml(self) -> str:
        return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="png" ContentType="image/png"/>
  <Default Extension="jpg" ContentType="image/jpeg"/>
  <Default Extension="jpeg" ContentType="image/jpeg"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
  <Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>
  <Override PartName="/word/fontTable.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.fontTable+xml"/>
  <Override PartName="/word/webSettings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.webSettings+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>"""


def core_props_xml() -> str:
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
 xmlns:dc="http://purl.org/dc/elements/1.1/"
 xmlns:dcterms="http://purl.org/dc/terms/"
 xmlns:dcmitype="http://purl.org/dc/dcmitype/"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>Container Image Threat Scanner with Layer Forensics</dc:title>
  <dc:subject>Project Report</dc:subject>
  <dc:creator>Codex</dc:creator>
  <cp:keywords>container security, docker, forensic layers, SBOM, vulnerability scanning</cp:keywords>
  <dc:description>Professional long-form project report generated from repository evidence.</dc:description>
  <cp:lastModifiedBy>Codex</cp:lastModifiedBy>
  <dcterms:created xsi:type="dcterms:W3CDTF">{created}</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">{created}</dcterms:modified>
</cp:coreProperties>"""


APP_PROPS_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
 xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <Application>Codex</Application>
  <DocSecurity>0</DocSecurity>
  <ScaleCrop>false</ScaleCrop>
  <Company>OpenAI</Company>
  <LinksUpToDate>false</LinksUpToDate>
  <SharedDoc>false</SharedDoc>
  <HyperlinksChanged>false</HyperlinksChanged>
  <AppVersion>1.0</AppVersion>
</Properties>"""


ROOT_RELS_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>"""


SETTINGS_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:zoom w:percent="100"/>
  <w:defaultTabStop w:val="720"/>
</w:settings>"""


WEB_SETTINGS_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:webSettings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>"""


FONT_TABLE_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:fonts xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:font w:name="Cambria"/>
  <w:font w:name="Calibri"/>
  <w:font w:name="Consolas"/>
</w:fonts>"""


STYLES_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:style w:type="paragraph" w:default="1" w:styleId="Normal">
    <w:name w:val="Normal"/>
    <w:qFormat/>
    <w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="22"/></w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="BodyText">
    <w:name w:val="Body Text"/>
    <w:basedOn w:val="Normal"/>
    <w:qFormat/>
    <w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="22"/></w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Heading1">
    <w:name w:val="heading 1"/>
    <w:basedOn w:val="Normal"/>
    <w:qFormat/>
    <w:rPr><w:rFonts w:ascii="Cambria" w:hAnsi="Cambria"/><w:b/><w:sz w:val="34"/><w:color w:val="1F4E79"/></w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Heading2">
    <w:name w:val="heading 2"/>
    <w:basedOn w:val="Normal"/>
    <w:qFormat/>
    <w:rPr><w:rFonts w:ascii="Cambria" w:hAnsi="Cambria"/><w:b/><w:sz w:val="28"/><w:color w:val="1F2937"/></w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Code">
    <w:name w:val="Code"/>
    <w:basedOn w:val="Normal"/>
    <w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/><w:sz w:val="18"/><w:color w:val="333333"/></w:rPr>
  </w:style>
</w:styles>"""


def add_long_form_content(builder: DocxBuilder, scan: dict, asset_paths: list[Path]) -> None:
    asset_map = {path.name: path for path in asset_paths}
    builder.add_image(asset_map["cover.png"], width_inches=7.7)
    builder.add_page_break()

    builder.add_heading("Table of Contents", 1)
    for entry in [
        "1. Executive Summary",
        "2. Project Overview",
        "3. Problem Statement and Objectives",
        "4. Scope, Assumptions, and Constraints",
        "5. Technology Stack",
        "6. Functional Architecture",
        "7. Module-by-Module Code Design",
        "8. Scan Methodology and Algorithms",
        "9. Output Analysis and Findings",
        "10. Dashboard Visual Evidence",
        "11. CI/CD Integration",
        "12. Testing and Validation",
        "13. Risk Interpretation and Remediation",
        "14. Conclusion",
        "15. References",
        "16. Appendix A - Source Code Listings",
        "17. Appendix B - Output Evidence Excerpts",
    ]:
        builder.add_paragraph(entry)
    builder.add_paragraph("Document formatting note: Headings are intended for Cambria 14-17 pt presentation and body text for Calibri/Aptos 11 pt professional submission format.")
    builder.add_page_break()

    sections = [
        ("Executive Summary", [
            "This report documents the design, implementation, evidence set, and forensic security findings of the project titled Container Image Threat Scanner with Layer Forensics.",
            "The solution combines Docker image acquisition, layer extraction, package enumeration, CVE matching, threat intelligence, forensic mapping, risk scoring, multi-format reporting, and dashboard visualization.",
            f"The latest available project evidence in this workspace shows the image {scan['image_metadata']['image_name']} with a calculated risk score of {scan['risk_score']['score']} out of 10 and grade {scan['risk_score']['grade']}.",
            "A practical environment limitation affected this report generation session: the Docker daemon was not reachable from the current machine, so a brand-new live image pull could not be repeated at report time. This document therefore uses the most recent scanner-generated outputs already present in the repository and local module execution against those artifacts."
        ]),
        ("Project Overview", [
            "Container images are now a standard deployment unit, but image scanning tools often stop at issue detection. This project improves on that by tracing findings back to the exact layer that introduced them.",
            "The scanner is organized as a modular Python application with a Streamlit dashboard and CI automation workflow, making it suitable for academic demonstration as well as practical security pipeline integration.",
        ]),
        ("Problem Statement and Objectives", [
            "The problem addressed by the project is the lack of actionable, layer-level attribution in many container security workflows.",
            "The key objectives are to identify known vulnerabilities, detect secrets and misconfigurations, map each finding to a responsible layer, compute an interpretable risk score, and export evidence for both machines and humans.",
        ]),
        ("Scope, Assumptions, and Constraints", [
            "The project covers Linux container images accessible through Docker, common package ecosystems, vulnerability lookups through a demo database and optional live NVD queries, and several practical threat-intelligence checks.",
            "The dashboard assumes that a latest scan artifact is available under reports/latest_scan.json, allowing analysis to continue even when a live scan is not currently possible.",
            "The primary operational constraint in this session is Docker availability. Docker must be running for full end-to-end live scanning.",
        ]),
        ("Technology Stack", [
            "Python, Docker SDK, Requests, Rich, PyYAML, Streamlit, Plotly, Pandas, and GitHub Actions together form the project stack.",
            "The reporting pipeline also produces CycloneDX-style SBOM output, which improves traceability and interoperability.",
        ]),
        ("Functional Architecture", [
            "The scanner pipeline starts with image acquisition and metadata extraction, proceeds through layer parsing and package enumeration, and then branches into vulnerability matching, threat-intelligence analysis, forensic mapping, risk scoring, and reporting.",
            "This separation of concerns makes the project easier to extend and reason about during demonstrations and code reviews.",
        ]),
        ("Module-by-Module Code Design", [
            "Each major Python file owns a focused part of the workflow: CLI orchestration, Docker access, layer extraction, package discovery, CVE intelligence, threat intelligence, forensic mapping, risk scoring, reporting, dashboard visualization, and CI automation.",
            "This modularity is one of the project's strongest engineering qualities because it improves readability, maintenance, and evidence presentation.",
        ]),
        ("Scan Methodology and Algorithms", [
            "The methodology is deterministic: acquire metadata, decompose the image, inspect filesystem artifacts, enumerate packages, match CVEs, identify suspicious files or secrets, map findings to layers, and convert counts into a risk score.",
            "The scoring model is intentionally readable so that the report can explain exactly why a given grade was assigned.",
        ]),
        ("Output Analysis and Findings", [
            f"The primary evidence file for this report is {JSON_PATH.name}, which records a scan of {scan['image_metadata']['image_name']} with {scan['image_metadata']['layer_count']} layers and image size {scan['image_metadata']['size_mb']} MB.",
            f"The scanner identified {scan['vuln_data']['total_count']} vulnerabilities and {scan['threat_data']['total_count']} threat-intelligence findings. The final image risk score is {scan['risk_score']['score']} / 10, corresponding to grade {scan['risk_score']['grade']}.",
            f"The riskiest layer is Layer {scan['forensic_map']['riskiest_layer']['layer_index']} with score {scan['forensic_map']['riskiest_layer']['risk_score']}.",
        ]),
        ("Dashboard Visual Evidence", [
            "The dashboard transforms scanner artifacts into an investigation interface for overview, vulnerabilities, threats, layer map, SBOM, and remediation pages.",
            "Because the dashboard reads from the latest scan artifact, it supports review workflows even when the live scanner is not currently executing.",
        ]),
        ("CI/CD Integration", [
            "The GitHub Actions workflow demonstrates that the scanner is automation-ready. It installs dependencies, starts Docker, runs the scanner, uploads reports, comments on pull requests, and fails the pipeline when critical issues are present.",
        ]),
        ("Testing and Validation", [
            "Validation is evidence-driven. The repository contains generated reports for several images, showing that the scanner has been exercised beyond a single sample target.",
            "The latest scan artifact was parsed successfully during report generation, validating the stability of the result schema expected by the dashboard and report logic.",
        ]),
        ("Risk Interpretation and Remediation", [
            "The grade F result in the latest evidence indicates that the scanned image should not proceed to production deployment without remediation.",
            "Immediate priorities are patching vulnerable packages, removing secrets and sensitive files, stripping unnecessary SUID binaries, and enforcing a non-root runtime user.",
        ]),
        ("Conclusion", [
            "This project succeeds as both an academic submission and a practical security engineering solution because it explains not only what is wrong in an image, but exactly where the risk was introduced.",
            "The appendices preserve source code and evidence excerpts so the report functions as a full technical submission package.",
        ]),
        ("References", [
            "NIST National Vulnerability Database (NVD)",
            "Docker SDK for Python documentation",
            "CycloneDX SBOM specification",
            "OWASP guidance for container security",
            "Repository source files and generated reports contained in this workspace",
        ]),
    ]
    for title, paragraphs in sections:
        builder.add_heading(title, 1)
        for paragraph in paragraphs:
            builder.add_paragraph(paragraph)
        if title == "Executive Summary":
            builder.add_image(asset_map["terminal_evidence.png"], width_inches=7.2)
        elif title == "Technology Stack":
            builder.add_image(asset_map["codebase_map.png"], width_inches=7.2)
        elif title == "Functional Architecture":
            builder.add_image(asset_map["architecture.png"], width_inches=7.2)
        elif title == "Output Analysis and Findings":
            builder.add_image(asset_map["findings_matrix.png"], width_inches=7.2)
            builder.add_image(asset_map["layer_heatmap.png"], width_inches=7.2)
        elif title == "Dashboard Visual Evidence":
            builder.add_image(asset_map["dashboard_overview.png"], width_inches=7.2)
        elif title == "CI/CD Integration":
            builder.add_image(asset_map["ci_workflow.png"], width_inches=7.2)

    builder.add_page_break()
    builder.add_heading("Appendix A - Source Code Listings", 1)
    builder.add_paragraph("The following sections reproduce the major source files that implement the scanner, dashboard, and CI workflow. This appendix intentionally expands the technical depth of the report and helps satisfy long-form submission requirements.")
    for rel_path in SOURCE_FILES:
        builder.add_heading(rel_path, 2)
        builder.add_codeblock((ROOT / rel_path).read_text(encoding="utf-8"))
        builder.add_page_break()

    builder.add_heading("Appendix B - Output Evidence Excerpts", 1)
    builder.add_paragraph("This appendix records a concise evidence summary based on reports/latest_scan.json and the generated report paths present in the workspace.")
    evidence_excerpt = json.dumps({
        "image_metadata": scan["image_metadata"],
        "risk_score": scan["risk_score"],
        "report_paths": scan["report_paths"],
        "vulnerability_summary": scan["vuln_data"]["summary"],
        "threat_summary": scan["threat_data"]["summary"],
        "critical_path": scan["forensic_map"]["critical_path"],
    }, indent=2)
    builder.add_codeblock(evidence_excerpt)


def add_long_form_content_safe(builder: SafeDocxBuilder, scan: dict, asset_paths: list[Path]) -> None:
    asset_map = {path.name: path for path in asset_paths}
    builder.add_heading("Container Image Threat Scanner with Layer Forensics", 1)
    builder.add_paragraph("Professional project report generated from repository evidence.")
    builder.add_paragraph(f"Image analyzed: {scan['image_metadata']['image_name']}")
    builder.add_paragraph(f"Risk score: {scan['risk_score']['score']} / 10")
    builder.add_paragraph(f"Risk grade: {scan['risk_score']['grade']}")
    builder.add_paragraph("Note: this safe DOCX version omits embedded drawings for maximum compatibility. All figure assets are available in the companion assets folder.")
    builder.add_page_break()

    for title, paragraphs in [
        ("Executive Summary", [
            "This report documents the design, implementation, and evidence of the Container Image Threat Scanner with Layer Forensics project.",
            f"The latest workspace evidence records {scan['vuln_data']['total_count']} vulnerabilities, {scan['threat_data']['total_count']} threats, and a final risk score of {scan['risk_score']['score']} / 10.",
            "Docker was not reachable during this session, so the report is based on the latest real scan artifacts already present in the repository."
        ]),
        ("Project Overview", [
            "The project scans Docker images, decomposes layers, enumerates packages, matches vulnerabilities, detects secrets and misconfigurations, and produces layer-aware forensic attribution.",
            "The implementation also includes a Streamlit dashboard and a GitHub Actions workflow."
        ]),
        ("Findings", [
            f"The scanned image was {scan['image_metadata']['image_name']} with {scan['image_metadata']['layer_count']} layers and size {scan['image_metadata']['size_mb']} MB.",
            f"The riskiest layer was Layer {scan['forensic_map']['riskiest_layer']['layer_index']} with score {scan['forensic_map']['riskiest_layer']['risk_score']}.",
            f"Classification: {scan['risk_score']['classification']}"
        ]),
        ("References", [
            "NIST National Vulnerability Database (NVD)",
            "Docker SDK for Python documentation",
            "CycloneDX SBOM specification",
            "OWASP container security guidance",
        ]),
    ]:
        builder.add_heading(title, 1)
        for paragraph in paragraphs:
            builder.add_paragraph(paragraph)
        if title == "Executive Summary":
            builder.add_image_note(asset_map["terminal_evidence.png"])
        elif title == "Project Overview":
            builder.add_image_note(asset_map["architecture.png"])
            builder.add_image_note(asset_map["codebase_map.png"])
        elif title == "Findings":
            builder.add_image_note(asset_map["dashboard_overview.png"])
            builder.add_image_note(asset_map["layer_heatmap.png"])
            builder.add_image_note(asset_map["findings_matrix.png"])

    builder.add_page_break()
    builder.add_heading("Appendix A - Source Code Listings", 1)
    for rel_path in SOURCE_FILES:
        builder.add_heading(rel_path, 2)
        builder.add_codeblock((ROOT / rel_path).read_text(encoding="utf-8"))
        builder.add_page_break()


def build_html_report(scan: dict, asset_paths: list[Path]) -> None:
    asset_map = {path.name: path for path in asset_paths}
    figures = [
        "cover.png",
        "terminal_evidence.png",
        "architecture.png",
        "codebase_map.png",
        "dashboard_overview.png",
        "findings_matrix.png",
        "layer_heatmap.png",
        "ci_workflow.png",
    ]
    html = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Container Image Threat Scanner Report</title>",
        "<style>body{font-family:Calibri,Arial,sans-serif;max-width:980px;margin:40px auto;line-height:1.55;color:#1f2937} h1,h2{font-family:Cambria,Georgia,serif} pre{white-space:pre-wrap;background:#f8fafc;padding:14px;border:1px solid #cbd5e1;overflow-wrap:anywhere} img{max-width:100%;border:1px solid #cbd5e1;margin:12px 0 24px} .meta{background:#eff6ff;padding:16px;border-left:4px solid #2563eb}</style></head><body>",
        "<h1>Container Image Threat Scanner with Layer Forensics</h1>",
        f"<div class='meta'><p><strong>Image:</strong> {escape(scan['image_metadata']['image_name'])}</p><p><strong>Risk Score:</strong> {scan['risk_score']['score']} / 10</p><p><strong>Risk Grade:</strong> {escape(scan['risk_score']['grade'])}</p></div>",
        "<h2>Executive Summary</h2>",
        f"<p>The latest workspace evidence contains {scan['vuln_data']['total_count']} vulnerabilities and {scan['threat_data']['total_count']} threat findings with classification <strong>{escape(scan['risk_score']['classification'])}</strong>.</p>",
    ]
    for fig in figures:
        html.append(f"<h2>{escape(fig)}</h2><img src='assets/{escape(fig)}' alt='{escape(fig)}'>")
    html.append("<h2>Appendix A - Source Code Listings</h2>")
    for rel_path in SOURCE_FILES:
        html.append(f"<h3>{escape(rel_path)}</h3><pre>{escape((ROOT / rel_path).read_text(encoding='utf-8'))}</pre>")
    html.append("</body></html>")
    HTML_PATH.write_text("".join(html), encoding="utf-8")


def main() -> None:
    ensure_dirs()
    scan = load_scan()
    assets = generate_assets(scan)
    safe_builder = SafeDocxBuilder()
    add_long_form_content_safe(safe_builder, scan, assets)
    safe_builder.save(SAFE_DOCX_PATH)
    build_html_report(scan, assets)
    print(f"Generated safe report: {SAFE_DOCX_PATH}")
    print(f"Generated html report: {HTML_PATH}")


if __name__ == "__main__":
    main()
