from __future__ import annotations

import json
import re
import tarfile
import zipfile
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from uuid import uuid4

import httpx
from packaging.requirements import Requirement


@dataclass(frozen=True)
class Finding:
    id: str
    rule_id: str
    category: str
    severity: str
    confidence: float
    file_path: str
    line_range: Optional[str]
    snippet_redacted: Optional[str]
    evidence: Dict[str, Any]
    recommendation: str


SKILL_LAYOUT_INVALID_MISSING_SKILL_MD = "skill_layout_invalid_missing_skill_md"
SKILL_LAYOUT_INVALID_SKILL_MD_DEPTH = "skill_layout_invalid_skill_md_depth"
SKILL_LAYOUT_INVALID_SKILL_MD_EMPTY = "skill_layout_invalid_skill_md_empty"
SKILL_LAYOUT_INVALID_SKILL_MD_NOT_UTF8 = "skill_layout_invalid_skill_md_not_utf8"
SKILL_LAYOUT_INVALID_PACKAGE_STRUCTURE = "skill_layout_invalid_package_structure"
SKILL_LAYOUT_ERROR_CODES = {
    SKILL_LAYOUT_INVALID_MISSING_SKILL_MD,
    SKILL_LAYOUT_INVALID_SKILL_MD_DEPTH,
    SKILL_LAYOUT_INVALID_SKILL_MD_EMPTY,
    SKILL_LAYOUT_INVALID_SKILL_MD_NOT_UTF8,
    SKILL_LAYOUT_INVALID_PACKAGE_STRUCTURE,
}


def _relpath(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except Exception:
        return str(path)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except Exception:
        return False


def safe_extract_archive(
    *,
    archive_path: Path,
    dest_dir: Path,
    max_unpacked_bytes: int,
    max_file_count: int,
    max_dir_depth: int,
) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    if archive_path.name.lower().endswith(".zip"):
        _extract_zip(
            archive_path=archive_path,
            dest_dir=dest_dir,
            max_unpacked_bytes=max_unpacked_bytes,
            max_file_count=max_file_count,
            max_dir_depth=max_dir_depth,
        )
        return
    if archive_path.name.lower().endswith(".tar.gz") or archive_path.name.lower().endswith(".tgz"):
        _extract_targz(
            archive_path=archive_path,
            dest_dir=dest_dir,
            max_unpacked_bytes=max_unpacked_bytes,
            max_file_count=max_file_count,
            max_dir_depth=max_dir_depth,
        )
        return
    raise ValueError("unsupported_archive_format")


def _split_member_path(member_name: str) -> List[str]:
    if not member_name:
        raise ValueError("invalid_member_path")
    normalized = member_name.replace("\\", "/")
    if normalized.startswith("/"):
        raise ValueError("absolute_path_not_allowed")
    if re.match(r"^[A-Za-z]:", normalized):
        raise ValueError("drive_path_not_allowed")
    parts = [p for p in normalized.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise ValueError("path_traversal_not_allowed")
    if not parts:
        raise ValueError("invalid_member_path")
    return parts


def _depth_of(member_name: str) -> int:
    return len(_split_member_path(member_name))


def _safe_target_path(dest_dir: Path, member_name: str) -> Path:
    parts = _split_member_path(member_name)
    target = dest_dir.joinpath(*parts)
    if not _is_within(target, dest_dir):
        raise ValueError("path_traversal_not_allowed")
    return target


def _extract_zip(
    *,
    archive_path: Path,
    dest_dir: Path,
    max_unpacked_bytes: int,
    max_file_count: int,
    max_dir_depth: int,
) -> None:
    total_declared = 0
    count = 0
    with zipfile.ZipFile(str(archive_path)) as zf:
        planned_files: List[zipfile.ZipInfo] = []
        planned_dirs: List[str] = []
        for zi in zf.infolist():
            name = zi.filename
            if _depth_of(name) > max_dir_depth:
                raise ValueError("dir_depth_limit_exceeded")
            is_symlink = (zi.external_attr >> 16) & 0o170000 == 0o120000
            if is_symlink:
                raise ValueError("symlink_not_allowed")
            if zi.is_dir():
                planned_dirs.append(name)
                continue
            count += 1
            if count > max_file_count:
                raise ValueError("file_count_limit_exceeded")
            total_declared += zi.file_size
            if total_declared > max_unpacked_bytes:
                raise ValueError("unpacked_size_limit_exceeded")
            planned_files.append(zi)

        for d in planned_dirs:
            target_dir = _safe_target_path(dest_dir, d)
            target_dir.mkdir(parents=True, exist_ok=True)

        total_written = 0
        for zi in planned_files:
            target_path = _safe_target_path(dest_dir, zi.filename)
            target_path.parent.mkdir(parents=True, exist_ok=True)

            with zf.open(zi, "r") as src, target_path.open("wb") as dst:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    total_written += len(chunk)
                    if total_written > max_unpacked_bytes:
                        raise ValueError("unpacked_size_limit_exceeded")
                    dst.write(chunk)


def _extract_targz(
    *,
    archive_path: Path,
    dest_dir: Path,
    max_unpacked_bytes: int,
    max_file_count: int,
    max_dir_depth: int,
) -> None:
    total = 0
    count = 0
    with tarfile.open(str(archive_path), mode="r:gz") as tf:
        members = tf.getmembers()
        planned_files: List[tarfile.TarInfo] = []
        planned_dirs: List[str] = []
        for m in members:
            if _depth_of(m.name) > max_dir_depth:
                raise ValueError("dir_depth_limit_exceeded")
            if m.issym() or m.islnk():
                raise ValueError("symlink_not_allowed")
            if m.ischr() or m.isblk() or m.isfifo() or (hasattr(m, "isdev") and m.isdev()):
                raise ValueError("special_file_not_allowed")
            if m.isdir():
                planned_dirs.append(m.name)
            if m.isfile():
                count += 1
                if count > max_file_count:
                    raise ValueError("file_count_limit_exceeded")
                total += m.size
                if total > max_unpacked_bytes:
                    raise ValueError("unpacked_size_limit_exceeded")
                planned_files.append(m)

        for d in planned_dirs:
            target_dir = _safe_target_path(dest_dir, d)
            target_dir.mkdir(parents=True, exist_ok=True)

        total_written = 0
        for m in planned_files:
            target_path = _safe_target_path(dest_dir, m.name)
            target_path.parent.mkdir(parents=True, exist_ok=True)

            src = tf.extractfile(m)
            if src is None:
                raise ValueError("extract_failed")
            with src, target_path.open("wb") as dst:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    total_written += len(chunk)
                    if total_written > max_unpacked_bytes:
                        raise ValueError("unpacked_size_limit_exceeded")
                    dst.write(chunk)


def validate_skill_layout(root_dir: Path) -> None:
    """强门禁前置校验：不通过则抛 ValueError(稳定错误码)。"""
    candidates = sorted(
        [p for p in root_dir.rglob("*") if p.is_file() and p.name.lower() == "skill.md"],
        key=lambda p: str(p),
    )
    if not candidates:
        raise ValueError(SKILL_LAYOUT_INVALID_MISSING_SKILL_MD)

    # 限制仅允许根目录或一级子目录，避免深层伪装绕过。
    allowed = []
    for p in candidates:
        rel = p.relative_to(root_dir)
        if len(rel.parts) <= 2:
            allowed.append(p)
    if not allowed:
        raise ValueError(SKILL_LAYOUT_INVALID_SKILL_MD_DEPTH)

    def _is_ignored_top_level(part: str) -> bool:
        return part.startswith(".") or part == "__MACOSX"

    package_roots: Set[str] = set()
    for p in allowed:
        rel = p.relative_to(root_dir)
        package_roots.add("" if len(rel.parts) == 1 else rel.parts[0])

    # 根目录与子目录混用，或多个候选根目录，容易被伪装文件绕过。
    if len(package_roots) != 1:
        raise ValueError(SKILL_LAYOUT_INVALID_PACKAGE_STRUCTURE)

    package_root = next(iter(package_roots))
    if package_root:
        for top in root_dir.iterdir():
            if _is_ignored_top_level(top.name):
                continue
            if top.name != package_root:
                raise ValueError(SKILL_LAYOUT_INVALID_PACKAGE_STRUCTURE)

    # 至少有一个可读且非空 UTF-8 文本的 SKILL.md。
    for p in allowed:
        data = p.read_bytes()
        if not data.strip():
            continue
        try:
            data.decode("utf-8")
            return
        except UnicodeDecodeError:
            continue

    any_non_empty = any(p.read_bytes().strip() for p in allowed)
    if not any_non_empty:
        raise ValueError(SKILL_LAYOUT_INVALID_SKILL_MD_EMPTY)
    raise ValueError(SKILL_LAYOUT_INVALID_SKILL_MD_NOT_UTF8)


def scan_directory(root_dir: Path) -> List[Finding]:
    findings: List[Finding] = []
    files = _collect_files(root_dir)

    secrets_findings = _scan_secrets(root_dir, files)
    sast_findings = _scan_dangerous_calls(root_dir, files)
    config_findings = _scan_config_risks(root_dir, files)
    prompt_findings = _scan_prompt_injection_patterns(root_dir, files)
    chain_findings = _scan_decode_execute_chains(root_dir, files)
    exfil_findings = _scan_exfiltration_patterns(root_dir, files)
    malicious_findings = _scan_malicious_heuristics(root_dir, files)
    dep_findings = _scan_dependencies(root_dir, files)
    correlated_prompt_findings = _scan_prompt_correlated_chains(
        root_dir=root_dir,
        files=files,
        prompt_findings=prompt_findings,
        chain_findings=chain_findings,
        exfil_findings=exfil_findings,
    )

    findings.extend(secrets_findings)
    findings.extend(sast_findings)
    findings.extend(config_findings)
    findings.extend(prompt_findings)
    findings.extend(chain_findings)
    findings.extend(exfil_findings)
    findings.extend(malicious_findings)
    findings.extend(dep_findings)
    findings.extend(correlated_prompt_findings)

    return findings


def _collect_files(root_dir: Path) -> List[Path]:
    files: List[Path] = []
    for p in root_dir.rglob("*"):
        if p.is_file():
            files.append(p)
    return files


def _looks_binary(data: bytes) -> bool:
    if not data:
        return False
    head = data[:4096]
    if b"\x00" in head:
        return True
    # Heuristic: lots of non-text control bytes usually indicates binary.
    # Keep it conservative to avoid skipping legitimate UTF-8 text.
    control = 0
    for b in head:
        if b in (9, 10, 13):  # \t \n \r
            continue
        if b < 32 or b == 127:
            control += 1
    return (control / max(1, len(head))) > 0.12


def _read_text_lines(path: Path, max_bytes: int = 1024 * 1024) -> Optional[List[str]]:
    try:
        if path.stat().st_size > max_bytes:
            return None
        data = path.read_bytes()
        if _looks_binary(data):
            return None
        return data.decode("utf-8", errors="ignore").splitlines()
    except Exception:
        return None


def _new_finding(
    *,
    rule_id: str,
    category: str,
    severity: str,
    confidence: float,
    file_path: str,
    line_range: Optional[str],
    snippet_redacted: Optional[str],
    evidence: Dict[str, Any],
    recommendation: str,
) -> Finding:
    return Finding(
        id=uuid4().hex,
        rule_id=rule_id,
        category=category,
        severity=severity,
        confidence=confidence,
        file_path=file_path,
        line_range=line_range,
        snippet_redacted=snippet_redacted,
        evidence=evidence,
        recommendation=recommendation,
    )


def _scan_secrets(root_dir: Path, files: List[Path]) -> List[Finding]:
    patterns: List[Tuple[str, re.Pattern[str], str]] = [
        ("SEC-PRIVATE-KEY", re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"), "检测到私钥内容，建议移除并轮换密钥"),
        ("SEC-AWS-ACCESS-KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "检测到疑似访问密钥，建议移除并轮换"),
        ("SEC-GENERIC-TOKEN", re.compile(r"(?i)\b(token|apikey|api_key|secret|password)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]"), "检测到疑似敏感配置，建议改为安全注入"),
    ]
    findings: List[Finding] = []
    for p in files:
        lines = _read_text_lines(p)
        if lines is None:
            continue
        for idx, line in enumerate(lines, start=1):
            for rule_id, rx, rec in patterns:
                if rx.search(line):
                    findings.append(
                        _new_finding(
                            rule_id=rule_id,
                            category="secrets",
                            severity="High" if rule_id != "SEC-GENERIC-TOKEN" else "Medium",
                            confidence=0.8,
                            file_path=_relpath(p, root_dir),
                            line_range=str(idx),
                            snippet_redacted=None,
                            evidence={"match": rx.pattern},
                            recommendation=rec,
                        )
                    )
    return findings


def _scan_dangerous_calls(root_dir: Path, files: List[Path]) -> List[Finding]:
    rules: List[Tuple[str, re.Pattern[str], str]] = [
        ("SAST-EVAL", re.compile(r"\beval\s*\("), "避免使用 eval，改为安全解析或白名单执行"),
        ("SAST-EXEC", re.compile(r"\bexec\s*\("), "避免使用 exec，改为安全解析或白名单执行"),
        ("SAST-OS-SYSTEM", re.compile(r"\bos\.system\s*\("), "避免 os.system，改用参数化安全调用或移除命令执行"),
        ("SAST-SUBPROCESS", re.compile(r"\bsubprocess\.(Popen|call|run)\s*\("), "检查 subprocess 调用参数是否可控，避免命令注入"),
        ("SAST-PICKLE", re.compile(r"\bpickle\.(loads|load)\s*\("), "避免反序列化不可信数据，使用安全格式或加签校验"),
        ("SAST-YAML-LOAD", re.compile(r"\byaml\.load\s*\("), "使用 yaml.safe_load 代替 yaml.load"),
    ]
    findings: List[Finding] = []
    for p in files:
        if p.suffix.lower() not in {".py", ".js", ".ts", ".sh", ".ps1"}:
            continue
        lines = _read_text_lines(p)
        if lines is None:
            continue
        for idx, line in enumerate(lines, start=1):
            for rule_id, rx, rec in rules:
                if rx.search(line):
                    findings.append(
                        _new_finding(
                            rule_id=rule_id,
                            category="sast",
                            severity="High" if rule_id in {"SAST-OS-SYSTEM", "SAST-SUBPROCESS"} else "Medium",
                            confidence=0.7,
                            file_path=_relpath(p, root_dir),
                            line_range=str(idx),
                            snippet_redacted=None,
                            evidence={"match": rx.pattern},
                            recommendation=rec,
                        )
                    )
    return findings


def _scan_config_risks(root_dir: Path, files: List[Path]) -> List[Finding]:
    findings: List[Finding] = []
    for p in files:
        name = p.name.lower()
        if name not in {".env", "config.yaml", "config.yml", "settings.py", "config.json"} and not name.endswith(".env"):
            continue
        lines = _read_text_lines(p)
        if lines is None:
            continue
        for idx, line in enumerate(lines, start=1):
            if re.search(r"(?i)\bdebug\b\s*[:=]\s*(true|1)\b", line):
                findings.append(
                    _new_finding(
                        rule_id="CFG-DEBUG-ON",
                        category="config",
                        severity="Low",
                        confidence=0.7,
                        file_path=_relpath(p, root_dir),
                        line_range=str(idx),
                        snippet_redacted=None,
                        evidence={"key": "debug"},
                        recommendation="生产环境关闭调试开关",
                    )
                )
            if re.search(r"(?i)\bcors\b.*\*", line) or re.search(r"(?i)\ballow_origin\b.*\*", line):
                findings.append(
                    _new_finding(
                        rule_id="CFG-CORS-ANY",
                        category="config",
                        severity="Medium",
                        confidence=0.6,
                        file_path=_relpath(p, root_dir),
                        line_range=str(idx),
                        snippet_redacted=None,
                        evidence={"match": "*"},
                        recommendation="限制允许的来源域名，避免使用 *",
                    )
                )
            if re.search(r"(?i)\bverify\b\s*[:=]\s*false\b", line) or re.search(r"(?i)\btls_verify\b\s*[:=]\s*false\b", line):
                findings.append(
                    _new_finding(
                        rule_id="CFG-TLS-VERIFY-OFF",
                        category="config",
                        severity="Medium",
                        confidence=0.7,
                        file_path=_relpath(p, root_dir),
                        line_range=str(idx),
                        snippet_redacted=None,
                        evidence={"key": "verify"},
                        recommendation="开启证书校验，避免中间人攻击风险",
                    )
                )
    return findings


def _scan_malicious_heuristics(root_dir: Path, files: List[Path]) -> List[Finding]:
    rules: List[Tuple[str, re.Pattern[str], str, str]] = [
        ("MAL-DOWNLOADER", re.compile(r"(?i)\b(curl|wget)\b.+\b(sh|bash)\b"), "High", "检查是否存在远程下载并执行行为，必要时移除"),
        ("MAL-POWERSHELL-ENC", re.compile(r"(?i)powershell.+-enc"), "High", "检查 PowerShell 编码执行内容是否可疑"),
        ("MAL-MINER-KEYWORD", re.compile(r"(?i)\b(xmrig|minerd|minergate|stratum\+tcp)\b"), "High", "检测到疑似挖矿相关特征，建议立即隔离并复核"),
        ("MAL-BASE64-LONG", re.compile(r"[A-Za-z0-9+/]{200,}={0,2}"), "Low", "检测到长 base64 字符串，建议确认是否为嵌入式可执行/配置"),
    ]
    findings: List[Finding] = []
    for p in files:
        lines = _read_text_lines(p, max_bytes=2 * 1024 * 1024)
        if lines is None:
            continue
        for idx, line in enumerate(lines, start=1):
            for rule_id, rx, sev, rec in rules:
                m = rx.search(line)
                if m:
                    matched = m.group(0)
                    matched_len = len(matched)
                    sample_prefix = (matched[:24] + "…") if matched_len > 24 else matched
                    sample_sha256 = hashlib.sha256(matched.encode("utf-8", errors="ignore")).hexdigest()
                    findings.append(
                        _new_finding(
                            rule_id=rule_id,
                            category="malicious",
                            severity=sev,
                            confidence=0.55 if rule_id == "MAL-BASE64-LONG" else 0.7,
                            file_path=_relpath(p, root_dir),
                            line_range=str(idx),
                            snippet_redacted=None,
                            evidence={
                                "match": rx.pattern,
                                "matched_len": matched_len,
                                "sample_prefix": sample_prefix,
                                "sample_sha256": sample_sha256,
                            },
                            recommendation=rec,
                        )
                    )
    return findings


def _is_text_candidate_file(path: Path) -> bool:
    name = path.name.lower()
    suffix = path.suffix.lower()
    if name in {"dockerfile", "makefile"}:
        return True
    if suffix in {
        ".py",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".cmd",
        ".md",
        ".txt",
        ".yaml",
        ".yml",
        ".json",
    }:
        return True
    return False


def _path_has_any(path: str, keywords: Iterable[str]) -> bool:
    p = path.lower()
    return any(k in p for k in keywords)


def _apply_evidence_weighting(*, raw_score: int, file_path: str, line_text: str) -> int:
    score = raw_score
    lowered = line_text.lower()
    if file_path.startswith(("tests/", "test/", "fixtures/", "examples/")):
        score = max(0, score - 2)
    if lowered.lstrip().startswith(("#", "//", "*", "/*", "--")):
        score = max(0, score - 1)
    if "example" in lowered or "demo" in lowered:
        score = max(0, score - 1)
    return score


def _severity_from_weighted_score(score: int) -> str:
    if score >= 8:
        return "Critical"
    if score >= 6:
        return "High"
    if score >= 3:
        return "Medium"
    return "Low"


def _extract_assigned_name(line: str) -> Optional[str]:
    m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
    return m.group(1) if m else None


def _extract_exec_arg_name(line: str) -> Optional[str]:
    patterns = [
        re.compile(r"(?i)\b(?:eval|exec)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\b"),
        re.compile(r"(?i)\bsubprocess\.(?:run|call|popen)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\b"),
        re.compile(r"(?i)\bos\.system\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\b"),
    ]
    for rx in patterns:
        m = rx.search(line)
        if m:
            return m.group(1)
    return None


def _scan_prompt_injection_patterns(root_dir: Path, files: List[Path]) -> List[Finding]:
    rules: List[Tuple[str, str, re.Pattern[str], int, str]] = [
        (
            "PROMPT-INJ-IGNORE-SYSTEM",
            "policy_override",
            re.compile(r"(?i)\b(ignore|bypass|override)\b.{0,40}\b(system|developer)\s+(prompt|instruction)s?\b"),
            4,
            "检测到疑似提示词注入中的系统指令绕过语句，建议增加策略拦截和人工复核。",
        ),
        (
            "PROMPT-INJ-TOOL-ABUSE",
            "tool_abuse",
            re.compile(r"(?i)\b(use|call|invoke)\b.{0,30}\b(shell|terminal|filesystem|browser|tool)s?\b.{0,40}\b(exfiltrate|steal|dump|send)\b"),
            5,
            "检测到疑似诱导工具越权调用语句，建议限制高风险工具权限并增加审批门槛。",
        ),
        (
            "PROMPT-INJ-DISABLE-SAFETY",
            "safety_bypass",
            re.compile(r"(?i)\b(disable|turn off|skip)\b.{0,30}\b(safety|guardrail|policy|audit|logging)\b"),
            4,
            "检测到疑似关闭安全策略指令，建议按高风险注入处置。",
        ),
        (
            "PROMPT-INJ-ROLE-HIJACK",
            "role_hijack",
            re.compile(r"(?i)\b(you are now|act as|assume role of)\b.{0,30}\b(system|developer|admin|root)\b"),
            5,
            "检测到疑似角色劫持语句，建议忽略该类角色重定义并记录审计。",
        ),
        (
            "PROMPT-INJ-SECRET-EXFIL-INTENT",
            "secret_exfiltration",
            re.compile(r"(?i)\b(system prompt|hidden prompt|api[_ -]?key|token|credential|secret)\b.{0,40}\b(print|output|reveal|dump|send|leak)\b|\b(print|output|reveal|dump|send|leak)\b.{0,40}\b(system prompt|hidden prompt|api[_ -]?key|token|credential|secret)\b"),
            7,
            "检测到疑似机密窃取意图，建议直接按高风险策略拦截并进入人工复核。",
        ),
        (
            "PROMPT-INJ-OBFUSCATED-BYPASS",
            "obfuscation",
            re.compile(r"(?i)\b(base64|hex|decode|decrypt)\b.{0,40}\b(ignore|bypass|override|disable)\b|\b(ignore|bypass|override|disable)\b.{0,40}\b(base64|hex|decode|decrypt)\b"),
            6,
            "检测到疑似混淆绕过语句，建议执行解码内容隔离与策略复检。",
        ),
    ]
    findings: List[Finding] = []
    for p in files:
        if not _is_text_candidate_file(p):
            continue
        lines = _read_text_lines(p, max_bytes=2 * 1024 * 1024)
        if lines is None:
            continue
        rel = _relpath(p, root_dir)
        for idx, line in enumerate(lines, start=1):
            for rule_id, attack_type, rx, base_score, rec in rules:
                if not rx.search(line):
                    continue
                score = _apply_evidence_weighting(raw_score=base_score, file_path=rel, line_text=line)
                severity = _severity_from_weighted_score(score)
                chain_evidence: List[str] = ["prompt_injection_phrase"]
                if attack_type in {"secret_exfiltration", "obfuscation", "tool_abuse"}:
                    chain_evidence.append(attack_type)
                findings.append(
                    _new_finding(
                        rule_id=rule_id,
                        category="prompt_injection",
                        severity=severity,
                        confidence=min(0.95, 0.45 + score * 0.08),
                        file_path=rel,
                        line_range=str(idx),
                        snippet_redacted=None,
                        evidence={
                            "chain_evidence": chain_evidence,
                            "weighted_score": score,
                            "base_score": base_score,
                            "match": rx.pattern,
                            "attack_type": attack_type,
                        },
                        recommendation=rec,
                    )
                )
    return findings


def _scan_prompt_correlated_chains(
    *,
    root_dir: Path,
    files: List[Path],
    prompt_findings: List[Finding],
    chain_findings: List[Finding],
    exfil_findings: List[Finding],
) -> List[Finding]:
    if not prompt_findings:
        return []
    prompt_hit_files = {f.file_path for f in prompt_findings}
    chain_hit_files = {f.file_path for f in chain_findings}
    exfil_hit_files = {f.file_path for f in exfil_findings}
    findings: List[Finding] = []

    for p in files:
        rel = _relpath(p, root_dir)
        if rel not in prompt_hit_files:
            continue
        extra_evidence: List[str] = []
        if rel in exfil_hit_files:
            extra_evidence.append("network_egress")
        if rel in chain_hit_files:
            extra_evidence.append("dynamic_exec")
        if not extra_evidence:
            continue
        lines = _read_text_lines(p, max_bytes=2 * 1024 * 1024) or []
        line_no = 1
        for idx, line in enumerate(lines, start=1):
            if re.search(r"(?i)\b(ignore|bypass|override|disable)\b", line):
                line_no = idx
                break
        raw_score = 8 if "network_egress" in extra_evidence else 7
        weighted = _apply_evidence_weighting(raw_score=raw_score, file_path=rel, line_text=lines[line_no - 1] if lines else "")
        findings.append(
            _new_finding(
                rule_id="PROMPT-INJ-CORRELATED-CHAIN",
                category="prompt_injection",
                severity=_severity_from_weighted_score(weighted),
                confidence=min(0.95, 0.45 + weighted * 0.07),
                file_path=rel,
                line_range=str(line_no),
                snippet_redacted=None,
                evidence={
                    "chain_evidence": ["prompt_injection_phrase", *extra_evidence],
                    "weighted_score": weighted,
                    "attack_type": "correlated_attack_chain",
                },
                recommendation="检测到提示词注入与执行/外传行为同文件关联，建议立即阻断并升级人工处置。",
            )
        )
    return findings


def _scan_decode_execute_chains(root_dir: Path, files: List[Path]) -> List[Finding]:
    decode_rx = re.compile(r"(?i)\b(base64|b64decode|fromhex|binascii|gzip\.decompress|zlib\.decompress|decode)\b")
    exec_rx = re.compile(r"(?i)\b(eval|exec|subprocess\.(?:run|call|popen)|os\.system|powershell\s+-enc|node\s+-e)\b")
    input_rx = re.compile(r"(?i)\b(input|argv|sys\.argv|request\.(?:args|json|form)|os\.environ|getenv)\b")
    findings: List[Finding] = []
    decode_points: List[Dict[str, Any]] = []
    exec_points: List[Dict[str, Any]] = []
    for p in files:
        if p.suffix.lower() not in {".py", ".js", ".ts", ".sh", ".ps1", ".zsh", ".bash", ".cmd"}:
            continue
        lines = _read_text_lines(p, max_bytes=2 * 1024 * 1024)
        if lines is None:
            continue
        rel = _relpath(p, root_dir)
        window_radius = 4
        for idx, line in enumerate(lines, start=1):
            has_decode = bool(decode_rx.search(line))
            has_exec = bool(exec_rx.search(line))
            if has_decode:
                decode_points.append(
                    {
                        "file_path": rel,
                        "line_no": idx,
                        "line_text": line,
                        "token": _extract_assigned_name(line),
                        "has_input": bool(input_rx.search(line)),
                    }
                )
            if has_exec:
                exec_points.append(
                    {
                        "file_path": rel,
                        "line_no": idx,
                        "line_text": line,
                        "token": _extract_exec_arg_name(line),
                    }
                )
            if not (has_decode or has_exec):
                continue
            window = "\n".join(lines[max(0, idx - (window_radius + 1)): min(len(lines), idx + window_radius)])
            has_window_decode = has_decode or bool(decode_rx.search(window))
            has_window_exec = has_exec or bool(exec_rx.search(window))
            if not (has_window_decode and has_window_exec):
                continue
            has_input = bool(input_rx.search(window))
            chain_evidence: List[str] = ["decode_call", "dynamic_exec"]
            raw_score = 6
            if has_input:
                chain_evidence.insert(0, "user_or_env_input")
                raw_score += 2
            weighted = _apply_evidence_weighting(raw_score=raw_score, file_path=rel, line_text=line)
            findings.append(
                _new_finding(
                    rule_id="CHAIN-DECODE-EXEC",
                    category="attack_chain",
                    severity=_severity_from_weighted_score(weighted),
                    confidence=min(0.95, 0.45 + weighted * 0.07),
                    file_path=rel,
                    line_range=str(idx),
                    snippet_redacted=None,
                    evidence={
                        "chain_evidence": chain_evidence,
                        "weighted_score": weighted,
                        "window_radius": window_radius,
                    },
                    recommendation="检测到疑似解码后执行链路，建议移除动态执行并使用白名单解析。",
                )
            )

    # Weak cross-file correlation: decode and execute happen in different files
    # but are linked via the same variable token name.
    emitted_cross_keys = set()
    for d in decode_points:
        token = d.get("token")
        if not token:
            continue
        for e in exec_points:
            if e.get("token") != token:
                continue
            if e["file_path"] == d["file_path"]:
                continue
            key = (d["file_path"], d["line_no"], e["file_path"], e["line_no"], token)
            if key in emitted_cross_keys:
                continue
            emitted_cross_keys.add(key)
            raw_score = 7 + (1 if d.get("has_input") else 0)
            weighted = _apply_evidence_weighting(
                raw_score=raw_score,
                file_path=e["file_path"],
                line_text=e["line_text"],
            )
            findings.append(
                _new_finding(
                    rule_id="CHAIN-DECODE-EXEC-CROSSFILE",
                    category="attack_chain",
                    severity=_severity_from_weighted_score(weighted),
                    confidence=min(0.95, 0.45 + weighted * 0.07),
                    file_path=e["file_path"],
                    line_range=str(e["line_no"]),
                    snippet_redacted=None,
                    evidence={
                        "chain_evidence": ["cross_file_link", "decode_call", "dynamic_exec"],
                        "weighted_score": weighted,
                        "token": token,
                        "source_file": d["file_path"],
                        "source_line": d["line_no"],
                        "sink_file": e["file_path"],
                        "sink_line": e["line_no"],
                    },
                    recommendation="检测到跨文件解码后执行链路，建议打散动态执行链并对中间变量进行可信约束。",
                )
            )
    return findings


def _scan_exfiltration_patterns(root_dir: Path, files: List[Path]) -> List[Finding]:
    secret_read_rx = re.compile(
        r"(?i)(\.env|id_rsa|credentials|token|secret|passwd|shadow|aws_access_key|openai[_-]?api[_-]?key)"
    )
    send_rx = re.compile(
        r"(?i)\b(requests\.(?:post|get)|httpx\.(?:post|get)|curl\b|wget\b|Invoke-WebRequest\b|fetch\s*\(|axios\.)"
    )
    findings: List[Finding] = []
    for p in files:
        if not _is_text_candidate_file(p):
            continue
        lines = _read_text_lines(p, max_bytes=2 * 1024 * 1024)
        if lines is None:
            continue
        rel = _relpath(p, root_dir)
        for idx, line in enumerate(lines, start=1):
            if not (secret_read_rx.search(line) or send_rx.search(line)):
                continue
            window = "\n".join(lines[max(0, idx - 4): min(len(lines), idx + 3)])
            has_secret = bool(secret_read_rx.search(window))
            has_send = bool(send_rx.search(window))
            if not (has_secret and has_send):
                continue
            chain_evidence = ["secret_read", "network_egress"]
            raw_score = 7
            if _path_has_any(rel, ["skill.md", "prompt", "instruction"]):
                raw_score += 1
                chain_evidence.append("skill_instruction_surface")
            weighted = _apply_evidence_weighting(raw_score=raw_score, file_path=rel, line_text=line)
            findings.append(
                _new_finding(
                    rule_id="CHAIN-SECRET-EXFIL",
                    category="exfiltration",
                    severity=_severity_from_weighted_score(weighted),
                    confidence=min(0.95, 0.45 + weighted * 0.07),
                    file_path=rel,
                    line_range=str(idx),
                    snippet_redacted=None,
                    evidence={
                        "chain_evidence": chain_evidence,
                        "weighted_score": weighted,
                        "window_radius": 3,
                    },
                    recommendation="检测到疑似敏感信息外传行为，建议移除外发逻辑并隔离凭据读取权限。",
                )
            )
    return findings


def _scan_dependencies(root_dir: Path, files: List[Path]) -> List[Finding]:
    findings: List[Finding] = []
    dep_files = [
        p
        for p in files
        if p.name
        in {
            "requirements.txt",
            "poetry.lock",
            "Pipfile.lock",
            "package-lock.json",
            "package.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "pyproject.toml",
            "setup.py",
        }
    ]
    if not dep_files:
        return findings

    for p in dep_files:
        findings.append(
            _new_finding(
                rule_id="DEP-MANIFEST",
                category="dependency",
                severity="Info",
                confidence=0.6,
                file_path=_relpath(p, root_dir),
                line_range=None,
                snippet_redacted=None,
                evidence={"file": p.name},
                recommendation="检查依赖来源与版本锁定策略",
            )
        )

    req = next((p for p in dep_files if p.name == "requirements.txt"), None)
    if req:
        findings.extend(_osv_check_requirements(root_dir, req))

    findings.extend(_scan_supply_chain_script_risks(root_dir, dep_files))

    return findings


def _osv_check_requirements(root_dir: Path, requirements_path: Path) -> List[Finding]:
    lines = _read_text_lines(requirements_path, max_bytes=512 * 1024)
    if lines is None:
        return []
    packages: List[Tuple[str, str]] = []
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("-"):
            continue
        try:
            r = Requirement(s)
        except Exception:
            continue
        name = r.name
        ver = None
        for spec in r.specifier:
            if spec.operator == "==":
                ver = spec.version
                break
        if name and ver:
            packages.append((name, ver))

    if not packages:
        return []

    findings: List[Finding] = []
    client = httpx.Client(timeout=5.0)
    try:
        for name, ver in packages[:80]:
            payload = {"package": {"name": name, "ecosystem": "PyPI"}, "version": ver}
            try:
                r = client.post("https://api.osv.dev/v1/query", json=payload)
                if r.status_code != 200:
                    continue
                data = r.json()
            except Exception:
                continue
            vulns = data.get("vulns") if isinstance(data, dict) else None
            if not vulns:
                continue
            for v in vulns[:20]:
                vid = v.get("id") if isinstance(v, dict) else None
                summary = v.get("summary") if isinstance(v, dict) else None
                severity = "High"
                findings.append(
                    _new_finding(
                        rule_id="DEP-OSV-VULN",
                        category="dependency",
                        severity=severity,
                        confidence=0.7,
                        file_path=_relpath(requirements_path, root_dir),
                        line_range=None,
                        snippet_redacted=None,
                        evidence={"package": name, "version": ver, "vuln_id": vid, "summary": summary},
                        recommendation="升级到安全版本或替换依赖",
                    )
                )
    finally:
        client.close()

    return findings


def _scan_supply_chain_script_risks(root_dir: Path, dep_files: List[Path]) -> List[Finding]:
    findings: List[Finding] = []
    suspicious_cmd_rx = re.compile(
        r"(?i)(curl|wget|powershell|invoke-webrequest).{0,80}(\||bash|sh\b|iex\b)|\bnode\s+-e\b|\bpython\s+-c\b"
    )
    dynamic_exec_rx = re.compile(r"(?i)\b(eval|exec|subprocess\.(?:run|call|popen)|os\.system)\b")
    for p in dep_files:
        name = p.name.lower()
        rel = _relpath(p, root_dir)
        if name == "package.json":
            try:
                obj = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            scripts = obj.get("scripts")
            if not isinstance(scripts, dict):
                continue
            for key, value in scripts.items():
                if not isinstance(value, str):
                    continue
                if key not in {"preinstall", "install", "postinstall", "prepare"}:
                    continue
                if not suspicious_cmd_rx.search(value):
                    continue
                findings.append(
                    _new_finding(
                        rule_id="SUPPLYCHAIN-NPM-INSTALL-SCRIPT",
                        category="supplychain",
                        severity="High",
                        confidence=0.82,
                        file_path=rel,
                        line_range=None,
                        snippet_redacted=None,
                        evidence={
                            "script_hook": key,
                            "chain_evidence": ["install_hook", "remote_or_dynamic_command"],
                            "sample_prefix": value[:120],
                        },
                        recommendation="检测到 npm 安装脚本中的可疑命令，建议移除远程下载执行与动态代码执行。",
                    )
                )
            continue

        if name in {"setup.py", "pyproject.toml"}:
            lines = _read_text_lines(p, max_bytes=1024 * 1024)
            if lines is None:
                continue
            for idx, line in enumerate(lines, start=1):
                if suspicious_cmd_rx.search(line) or dynamic_exec_rx.search(line):
                    findings.append(
                        _new_finding(
                            rule_id="SUPPLYCHAIN-PY-BUILD-SCRIPT",
                            category="supplychain",
                            severity="High",
                            confidence=0.78,
                            file_path=rel,
                            line_range=str(idx),
                            snippet_redacted=None,
                            evidence={
                                "chain_evidence": ["build_or_packaging_script", "dynamic_or_remote_execution"],
                            },
                            recommendation="检测到构建脚本中的可疑执行逻辑，建议改为静态构建步骤并审计来源。",
                        )
                    )
    return findings


# 与 scan_directory 中各类扫描一一对应
STANDARD_SCAN_CHECKS: List[Dict[str, str]] = [
    {
        "id": "skill_layout",
        "title": "Skill 包结构（前置）",
        "description": "校验是否符合 Agent Skill 约定：解压后至少包含一处 SKILL.md；非标准结构将记为命中并判定不通过。",
    },
    {
        "id": "secrets",
        "title": "敏感信息泄露",
        "description": "基于正则匹配检测私钥、云访问密钥、令牌等敏感内容。",
    },
    {
        "id": "sast",
        "title": "危险调用与代码模式（SAST）",
        "description": "对源码脚本扫描 eval/exec、子进程、反序列化、非安全 YAML 等风险模式。",
    },
    {
        "id": "config",
        "title": "配置与权限风险",
        "description": "检查 .env、yaml/json 等常见配置中的调试开关、CORS 过宽、TLS 校验关闭等。",
    },
    {
        "id": "malicious",
        "title": "恶意特征与可疑行为",
        "description": "启发式检测下载并执行、可疑 PowerShell、挖矿关键字、异常长 Base64 等。",
    },
    {
        "id": "dependency",
        "title": "依赖与供应链",
        "description": "识别依赖清单（requirements.txt、package.json 等）；对 Python 固定版本依赖查询 OSV 公开漏洞库。",
    },
    {
        "id": "prompt_injection",
        "title": "Prompt 注入与越权指令",
        "description": "检测忽略系统指令、工具越权调用、关闭安全策略等可疑提示词注入语句。",
    },
    {
        "id": "attack_chain",
        "title": "混淆与执行链路",
        "description": "检测解码后执行、输入到动态执行等组合攻击链路并进行证据加权。",
    },
    {
        "id": "exfiltration",
        "title": "敏感信息外传行为",
        "description": "检测敏感读取与网络外发组合行为，识别疑似数据泄露链路。",
    },
    {
        "id": "supplychain",
        "title": "供应链脚本攻击",
        "description": "检测 npm 安装钩子和 Python 构建脚本中的远程下载执行与动态命令。",
    },
]


def is_skill_layout_error(error_code: str) -> bool:
    return error_code in SKILL_LAYOUT_ERROR_CODES


def build_skill_layout_failure_summary(error_code: str) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []
    for c in STANDARD_SCAN_CHECKS:
        if c["id"] == "skill_layout":
            checks.append(
                {
                    **c,
                    "findings_count": 1,
                    "status": "fail",
                }
            )
            continue
        checks.append(
            {
                **c,
                "findings_count": 0,
                "status": "not_checked",
            }
        )

    return {
        "score": 0.0,
        "score_raw": 0,
        "level": "High",
        "conclusion": "FAIL",
        "counts_by_severity": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
        "counts_by_category": {"skill_layout": 1},
        "counts_by_attack_type": {},
        "checks": checks,
        "reason": error_code,
    }


def aggregate(
    findings: Iterable[Finding],
    *,
    fail_on_critical: bool,
    high_count_threshold: int,
    score_threshold: int,
) -> Dict[str, Any]:
    sev_weights = {"Critical": 25, "High": 10, "Medium": 5, "Low": 2, "Info": 0}
    counts_by_severity: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    counts_by_category: Dict[str, int] = {}
    counts_by_attack_type: Dict[str, int] = {}

    raw_score = 0
    for f in findings:
        counts_by_severity[f.severity] = counts_by_severity.get(f.severity, 0) + 1
        counts_by_category[f.category] = counts_by_category.get(f.category, 0) + 1
        attack_type = f.evidence.get("attack_type") if isinstance(f.evidence, dict) else None
        if isinstance(attack_type, str) and attack_type.strip():
            k = attack_type.strip()
            counts_by_attack_type[k] = counts_by_attack_type.get(k, 0) + 1
        raw_score += sev_weights.get(f.severity, 0)
    raw_score = min(100, raw_score)
    # 对外展示使用正向 10 分制（分数越高越安全），与内部风控分离：
    # display_score = (100 - raw_score) / 10
    score = round((100 - raw_score) / 10.0, 2)

    fail = False
    if fail_on_critical and counts_by_severity["Critical"] > 0:
        fail = True
    if counts_by_severity["High"] >= high_count_threshold:
        fail = True
    if raw_score >= score_threshold:
        fail = True

    # 项目化风险等级（区别于规则严重级别）：
    # Blocker: 出现 Critical 命中（需立即阻断）
    # High: 已触发 FAIL 结论（但未到 Blocker）
    # Medium: 未触发 FAIL，但存在较明显风险暴露
    # Low: 仅存在轻微风险信号
    # Baseline: 未发现风险信号
    if counts_by_severity["Critical"] > 0:
        level = "Blocker"
    elif fail:
        level = "High"
    elif counts_by_severity["High"] > 0 or raw_score >= 25 or counts_by_severity["Medium"] >= 3:
        level = "Medium"
    elif raw_score > 0:
        level = "Low"
    else:
        level = "Baseline"

    checks: List[Dict[str, Any]] = []
    for c in STANDARD_SCAN_CHECKS:
        cid = c["id"]
        n = counts_by_category.get(cid, 0)
        checks.append(
            {
                **c,
                "findings_count": n,
                "status": "fail" if n > 0 else "pass",
            }
        )

    return {
        "score": score,
        "score_raw": raw_score,
        "level": level,
        "conclusion": "FAIL" if fail else "PASS",
        "counts_by_severity": counts_by_severity,
        "counts_by_category": counts_by_category,
        "counts_by_attack_type": counts_by_attack_type,
        "checks": checks,
    }


def build_report(
    *,
    task_id: str,
    artifact_sha256: str,
    created_at: str,
    engine_version: str,
    ruleset_version: str,
    summary: Dict[str, Any],
    findings: List[Finding],
) -> Dict[str, Any]:
    return {
        "meta": {
            "task_id": task_id,
            "artifact_sha256": artifact_sha256,
            "created_at": created_at,
            "engine_version": engine_version,
            "ruleset_version": ruleset_version,
        },
        "conclusion": summary.get("conclusion"),
        "summary": summary,
        "findings": [
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "category": f.category,
                "severity": f.severity,
                "confidence": f.confidence,
                "file_path": f.file_path,
                "line_range": f.line_range,
                "snippet_redacted": f.snippet_redacted,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
            }
            for f in findings
        ],
    }


def write_report(report_path: Path, report: Dict[str, Any]) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


_CATEGORY_ZH: Dict[str, str] = {
    "secrets": "敏感信息",
    "sast": "危险调用 / SAST",
    "config": "配置风险",
    "malicious": "恶意特征",
    "dependency": "依赖与供应链",
    "prompt_injection": "Prompt 注入",
    "attack_chain": "攻击链路",
    "exfiltration": "数据外传",
    "supplychain": "供应链脚本风险",
}

_SEVERITY_ZH: Dict[str, str] = {
    "Critical": "严重",
    "High": "高",
    "Medium": "中",
    "Low": "低",
    "Info": "信息",
}

_ATTACK_TYPE_ZH: Dict[str, str] = {
    "policy_override": "策略覆盖",
    "tool_abuse": "工具滥用",
    "safety_bypass": "绕过安全",
    "role_hijack": "角色劫持",
    "secret_exfiltration": "机密窃取",
    "obfuscation": "混淆绕过",
    "correlated_attack_chain": "关联攻击链",
}


def _md_cell(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).replace("\r\n", "\n").replace("\r", "\n")
    text = text.replace("|", "\\|")
    return " ".join(text.split())


def _zh_conclusion(c: Any) -> str:
    if c is None:
        return "—"
    u = str(c).strip().upper()
    if u == "PASS":
        return "通过"
    if u == "FAIL":
        return "未通过"
    return str(c)


def _zh_level(lv: Any) -> str:
    if lv is None:
        return "—"
    m = {
        "Blocker": "严重",
        "High": "高",
        "Medium": "中",
        "Low": "低",
        "Baseline": "无风险",
    }
    return m.get(str(lv), str(lv))


def _extract_attack_type(finding: Dict[str, Any]) -> Optional[str]:
    evidence = finding.get("evidence")
    if not isinstance(evidence, dict):
        return None
    raw = evidence.get("attack_type")
    if not isinstance(raw, str):
        return None
    s = raw.strip()
    return s or None


def render_report_markdown(report: Dict[str, Any]) -> str:
    """将 build_report 产出的 JSON 结构渲染为 Markdown（供下载）。"""
    meta = report.get("meta") or {}
    summary = report.get("summary") or {}
    findings = report.get("findings") or []
    conclusion = report.get("conclusion")
    lines: List[str] = []

    lines.append("# Skill 安全扫描报告")
    lines.append("")
    lines.append("## 元信息")
    lines.append("")
    lines.append(f"| 字段 | 值 |")
    lines.append(f"| --- | --- |")
    lines.append(f"| 任务 ID | `{_md_cell(meta.get('task_id'))}` |")
    lines.append(f"| 制品 SHA256 | `{_md_cell(meta.get('artifact_sha256'))}` |")
    lines.append(f"| 创建时间 | {_md_cell(meta.get('created_at'))} |")
    lines.append(f"| 引擎版本 | {_md_cell(meta.get('engine_version'))} |")
    lines.append(f"| 规则集版本 | {_md_cell(meta.get('ruleset_version'))} |")
    lines.append("")

    lines.append("## 摘要")
    lines.append("")
    lines.append(f"- **结论**：{_zh_conclusion(conclusion)}")
    lines.append(f"- **综合评分**：{_md_cell(summary.get('score'))}/10")
    lines.append(f"- **风险等级**：{_zh_level(summary.get('level'))}")
    lines.append("")

    counts_sev = summary.get("counts_by_severity") if isinstance(summary.get("counts_by_severity"), dict) else {}
    lines.append("### 严重级别分布")
    lines.append("")
    for key in ("Critical", "High", "Medium", "Low", "Info"):
        label = _SEVERITY_ZH.get(key, key)
        n = int(counts_sev.get(key, 0) or 0)
        lines.append(f"- {label}：{n}")
    lines.append("")

    checks = summary.get("checks")
    lines.append("## 检测范围与结果")
    lines.append("")
    if isinstance(checks, list) and checks:
        lines.append("| 检测项 | 检查说明 | 本类结果 |")
        lines.append("| --- | --- | --- |")
        for c in checks:
            if not isinstance(c, dict):
                continue
            title = _md_cell(c.get("title", ""))
            desc = _md_cell(c.get("description", ""))
            n = int(c.get("findings_count", 0) or 0)
            st = str(c.get("status", "")).strip().lower()
            if st == "fail":
                status_text = "不通过"
            elif st == "not_checked":
                status_text = "未检查"
            else:
                status_text = "通过"
            if st == "fail" and n > 0:
                status_text = f"{status_text}（检出 {n} 条）"
            lines.append(f"| {_md_cell(title)} | {desc} | {status_text} |")
    else:
        lines.append("*（无分项检测元数据，以下为按类别聚合命中数）*")
        lines.append("")
        cat_counts = summary.get("counts_by_category") if isinstance(summary.get("counts_by_category"), dict) else {}
        lines.append("| 类别 | 命中数 |")
        lines.append("| --- | --- |")
        for cat, n in sorted(cat_counts.items(), key=lambda x: (-int(x[1] or 0), str(x[0]))):
            zh = _CATEGORY_ZH.get(str(cat).lower(), str(cat))
            lines.append(f"| {_md_cell(zh)} | {int(n or 0)} |")
    lines.append("")

    attack_type_counts: Dict[str, int] = {}
    attack_type_recommendations: Dict[str, str] = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        attack_type = _extract_attack_type(f)
        if not attack_type:
            continue
        attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1
        rec = f.get("recommendation")
        if isinstance(rec, str) and rec.strip() and attack_type not in attack_type_recommendations:
            attack_type_recommendations[attack_type] = rec.strip()

    if attack_type_counts:
        lines.append("## 攻击类型分布")
        lines.append("")
        lines.append("| 攻击类型 | 命中数 |")
        lines.append("| --- | --- |")
        for attack_type, n in sorted(attack_type_counts.items(), key=lambda x: (-int(x[1]), str(x[0]))):
            zh = _ATTACK_TYPE_ZH.get(attack_type, attack_type)
            lines.append(f"| {_md_cell(zh)} | {int(n)} |")
        lines.append("")

        lines.append("## 分组处置建议")
        lines.append("")
        for attack_type, _ in sorted(attack_type_counts.items(), key=lambda x: (-int(x[1]), str(x[0]))):
            zh = _ATTACK_TYPE_ZH.get(attack_type, attack_type)
            rec = attack_type_recommendations.get(attack_type)
            if rec:
                lines.append(f"- **{_md_cell(zh)}**：{_md_cell(rec)}")
            else:
                lines.append(f"- **{_md_cell(zh)}**：建议按高风险提示词攻击流程进行人工复核。")
        lines.append("")

    lines.append("## 命中明细")
    lines.append("")
    if not findings:
        lines.append("*暂无命中。*")
    else:
        lines.append(
            "| 严重级别 | 类别 | 规则 | 文件 | 行号 | 置信度 | 建议 |"
        )
        lines.append("| --- | --- | --- | --- | --- | --- | --- |")
        for f in findings:
            if not isinstance(f, dict):
                continue
            sev = str(f.get("severity", ""))
            sev_zh = _SEVERITY_ZH.get(sev, sev)
            cat = str(f.get("category", ""))
            cat_zh = _CATEGORY_ZH.get(cat.lower(), cat)
            lines.append(
                "| "
                + " | ".join(
                    [
                        _md_cell(sev_zh),
                        _md_cell(cat_zh),
                        _md_cell(f.get("rule_id")),
                        _md_cell(f.get("file_path")),
                        _md_cell(f.get("line_range")),
                        _md_cell(f.get("confidence")),
                        _md_cell(f.get("recommendation")),
                    ]
                )
                + " |"
            )
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("*由 Skill 安全检测平台自动生成。*")
    lines.append("")
    return "\n".join(lines)
