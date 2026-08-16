from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Check:
    key: str
    title: str
    passed: bool
    points: int
    recommendation: str


@dataclass(frozen=True)
class Report:
    path: str
    score: int
    grade: str
    checks: list[Check]

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "score": self.score,
            "grade": self.grade,
            "checks": [asdict(check) for check in self.checks],
        }


def _exists(root: Path, *parts: str) -> bool:
    return (root.joinpath(*parts)).exists()


def audit(path: str | Path = ".") -> Report:
    root = Path(path).resolve()
    checks = [
        Check("readme", "README explica el proyecto", _exists(root, "README.md"), 15, "Añade un README con propuesta, instalación y ejemplos."),
        Check("license", "Licencia open source presente", any(_exists(root, name) for name in ("LICENSE", "LICENSE.md", "LICENSE.txt")), 10, "Incluye una licencia OSI compatible."),
        Check("contributing", "Guía de contribución", _exists(root, "CONTRIBUTING.md"), 10, "Documenta cómo preparar el entorno y enviar un pull request."),
        Check("code_of_conduct", "Código de conducta", _exists(root, "CODE_OF_CONDUCT.md"), 5, "Añade reglas de convivencia para una comunidad acogedora."),
        Check("ci", "Integración continua", _exists(root, ".github", "workflows"), 15, "Configura una comprobación automática en cada cambio."),
        Check("tests", "Pruebas automatizadas", _exists(root, "tests") or _exists(root, "test"), 15, "Crea pruebas que protejan el comportamiento público."),
        Check("security", "Política de seguridad", _exists(root, "SECURITY.md"), 10, "Explica cómo reportar vulnerabilidades de forma responsable."),
        Check("dependabot", "Actualizaciones de dependencias", _exists(root, ".github", "dependabot.yml"), 5, "Activa actualizaciones periódicas de dependencias."),
        Check("changelog", "Historial de cambios", _exists(root, "CHANGELOG.md"), 5, "Mantén un changelog para que los usuarios entiendan cada versión."),
        Check("issue_templates", "Plantillas de incidencias", _exists(root, ".github", "ISSUE_TEMPLATE"), 5, "Guía los reportes con plantillas claras."),
    ]
    total = sum(check.points for check in checks)
    earned = sum(check.points for check in checks if check.passed)
    score = round(earned / total * 100) if total else 0
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 55 else "D" if score >= 35 else "F"
    return Report(str(root), score, grade, checks)


def render_text(report: Report) -> str:
    lines = [f"OSS Compass · {report.score}/100 · Grade {report.grade}", "=" * 42, ""]
    for check in report.checks:
        icon = "✓" if check.passed else "✗"
        lines.append(f"{icon} {check.title} ({check.points} pts)")
        if not check.passed:
            lines.append(f"  → {check.recommendation}")
    return "\n".join(lines)


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
