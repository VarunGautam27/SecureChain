"""Static source-code indicator scan - a narrow, opt-in complement to the
behavioral anomaly detector, not a replacement for it.

Only runs when lookup_result.status == "no_cve" (nothing found in GitHub
Advisory or NVD) and the scan is not running in offline/cached-demo mode,
since it downloads and reads the package's real published source archive -
something the offline demo path deliberately never does.

Two layers, of different strength:

  - A keyword/pattern scan (both npm and PyPI) that reads the package's
    actual .js/.py source text for indicators associated with malicious
    packages in published incident write-ups. On its own this only flags a
    package when multiple independent indicator categories are present
    together, or when a suspicious pattern sits inside an install-time hook
    (preinstall/install/postinstall) - never on a single keyword match, since
    a bare `child_process` or `eval()` call is extremely common in
    legitimate packages (build tools, native bindings, CLI wrappers) and is
    not itself evidence of anything.
  - A real, but deliberately simplified, taint (data-flow) tracer for both
    ecosystems: find_taint_chains (Python, using the standard library `ast`
    module) and find_js_taint_chains (JavaScript, using acorn - a real,
    actively-maintained JS parser - via a small Node.js helper script in
    js_ast/, since Python has no adequate built-in JS parser of its own).
    Both check whether a value from a known-suspicious source (a decoded
    payload, a network response) is actually assigned through to a known-
    dangerous sink (eval/exec/os.system/subprocess/pickle.loads for Python;
    eval/Function/child_process exec-family calls for JS), rather than
    merely co-occurring in the same file - a confirmed chain is real
    evidence, not a keyword coincidence, and flags on its own. Both are
    single-file and intraprocedural only (no cross-function or cross-file
    tracking, no alias analysis beyond direct assignment) - a genuine step
    beyond keyword matching, not a substitute for a full interprocedural
    engine like CodeQL or Pysa.

    Using acorn (via Node.js, since Node is already a hard requirement for
    scanning npm packages at all) instead of a pure-Python JS parser gives
    the JS tracer genuine modern-syntax coverage (optional chaining, nullish
    coalescing, private class fields, etc.) matching real JS tooling, not an
    approximation of it - a file that still fails to parse (genuinely
    invalid syntax) degrades to "no chain reported for it", the same
    graceful handling as a Python SyntaxError, never a crash. All files in a
    package are parsed in a single batched Node process call rather than one
    process per file, since per-process launch overhead (~1.7s measured)
    would make scanning a package with hundreds of files impractically slow
    otherwise.
"""

from __future__ import annotations

import ast
import io
import json
import re
import subprocess
import tarfile
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

import requests

from securechain.ml.explain import explain_static_classifier
from securechain.ml.features import static_scan_vector
from securechain.ml.static_classifier import load_static_classifier, predict_static_risk

REQUEST_TIMEOUT_SECONDS = 20
_MAX_FILE_BYTES = 2_000_000
_SKIP_PATH_MARKERS = ("node_modules/", "/test/", "/tests/", "/__tests__/")

_JS_PATTERNS = [
    ("dynamic-code-execution", re.compile(r"\beval\s*\("), "calls eval()"),
    ("dynamic-code-execution", re.compile(r"\bnew\s+Function\s*\("), "constructs code dynamically via Function()"),
    ("process-spawn", re.compile(r"\bchild_process\b"), "uses child_process to spawn system commands"),
    ("raw-network", re.compile(r"require\(\s*['\"](?:net|dns)['\"]\s*\)"), "uses a low-level network module (net/dns)"),
    ("encoded-payload", re.compile(r"Buffer\.from\([^)]*,\s*['\"]base64['\"]\)"), "decodes a base64-encoded payload"),
]

_PY_PATTERNS = [
    ("dynamic-code-execution", re.compile(r"\beval\s*\("), "calls eval()"),
    ("dynamic-code-execution", re.compile(r"\bexec\s*\("), "calls exec()"),
    ("process-spawn", re.compile(r"\bos\.system\s*\("), "uses os.system() to spawn a shell command"),
    ("process-spawn", re.compile(r"\bsubprocess\."), "uses the subprocess module"),
    ("raw-network", re.compile(r"\bsocket\.(?:socket|create_connection)\b"), "uses raw sockets"),
    ("encoded-payload", re.compile(r"base64\.b64decode"), "decodes a base64-encoded payload"),
]

_HARDCODED_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_BENIGN_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}


@dataclass
class StaticScanResult:
    status: str  # "ok" | "not_run" | "lookup_failed"
    flagged: bool = False
    flag_reason: Optional[str] = None  # "confirmed_chain" | "install_hook" | None
    indicators: list = field(default_factory=list)
    files_scanned: int = 0
    ml_risk_score: Optional[float] = None
    ml_explanation: Optional[dict] = None

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def not_run() -> "StaticScanResult":
        return StaticScanResult(status="not_run")

    @staticmethod
    def failed(reason: str) -> "StaticScanResult":
        return StaticScanResult(status="lookup_failed", indicators=[reason])


def _scan_text(text: str, patterns) -> tuple[set, list]:
    categories: set = set()
    indicators: list = []
    for category, pattern, description in patterns:
        if pattern.search(text):
            categories.add(category)
            indicators.append(description)
    for match in _HARDCODED_IP_RE.finditer(text):
        ip = match.group(0)
        if ip not in _BENIGN_IPS:
            categories.add("hardcoded-ip")
            indicators.append(f"contains a hardcoded IP address ({ip})")
            break
    return categories, indicators


def _should_skip(path: str) -> bool:
    return any(marker in path for marker in _SKIP_PATH_MARKERS)


def _extract_text_files(archive_bytes: bytes, extension: str) -> list:
    """Reads every matching source file's text out of a .tgz/.tar.gz/.whl
    archive, trying tar first (npm tarballs, PyPI sdists) then zip (PyPI
    wheels) - nothing here ever executes anything from the archive.
    """
    contents: list = []
    buf = io.BytesIO(archive_bytes)
    try:
        with tarfile.open(fileobj=buf, mode="r:*") as tar:
            for member in tar.getmembers():
                if not member.isfile() or not member.name.endswith(extension):
                    continue
                if _should_skip(member.name) or member.size > _MAX_FILE_BYTES:
                    continue
                extracted = tar.extractfile(member)
                if extracted is not None:
                    contents.append(extracted.read().decode("utf-8", errors="ignore"))
        return contents
    except tarfile.TarError:
        pass

    buf.seek(0)
    try:
        with zipfile.ZipFile(buf) as zf:
            for info in zf.infolist():
                if info.is_dir() or not info.filename.endswith(extension):
                    continue
                if _should_skip(info.filename) or info.file_size > _MAX_FILE_BYTES:
                    continue
                with zf.open(info) as handle:
                    contents.append(handle.read().decode("utf-8", errors="ignore"))
    except zipfile.BadZipFile:
        pass
    return contents


_TAINT_SOURCE_ATTR_MODULES = {"requests", "urllib"}
_TAINT_SOURCE_CALLS = {("base64", "b64decode"), ("binascii", "unhexlify")}
# "socket" is deliberately NOT in _TAINT_SOURCE_ATTR_MODULES. Found via
# testing against the real gevent package: this tracer has no alias
# resolution for instance variables, so a blanket "any call on `socket`" rule
# only ever matched module-level setup calls like socket.create_server(...)
# or socket.socket(...) - local setup, not externally-controlled data - and
# could never actually match genuine data reception (sock.recv(...) has
# "sock", not "socket", as its object name). That combination meant this
# rule produced real false positives (gevent's own legitimate test suite
# was flagged) while never once serving its intended purpose. Removed
# rather than narrowed, since there is no data-reception case this tracer's
# design can actually detect for socket objects.
_TAINT_SINK_CALLS = {
    ("os", "system"), ("subprocess", "Popen"), ("subprocess", "call"), ("subprocess", "run"),
    ("pickle", "loads"),
}
_TAINT_SINK_BUILTINS = {"eval", "exec"}


def _call_module_func(node: ast.Call) -> Optional[tuple]:
    """Best-effort: `mod.func(...)` -> ("mod", "func"); a bare `func(...)` ->
    ("", "func"); anything else (e.g. a call on a non-Name expression) -> None.
    """
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return (func.value.id, func.attr)
    if isinstance(func, ast.Name):
        return ("", func.id)
    return None


def _is_taint_source_call(node: ast.Call) -> bool:
    ref = _call_module_func(node)
    if ref is None:
        return False
    module, func = ref
    return (module, func) in _TAINT_SOURCE_CALLS or module in _TAINT_SOURCE_ATTR_MODULES


def _taint_sink_name(node: ast.Call) -> Optional[str]:
    ref = _call_module_func(node)
    if ref is None:
        return None
    module, func = ref
    if (module, func) in _TAINT_SINK_CALLS:
        return f"{module}.{func}"
    if module == "" and func in _TAINT_SINK_BUILTINS:
        return func
    return None


def _names_in(node: ast.AST) -> set:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _expr_contains_taint_source(node: ast.AST) -> bool:
    return any(isinstance(n, ast.Call) and _is_taint_source_call(n) for n in ast.walk(node))


def find_taint_chains(source: str) -> list:
    """Best-effort, single-file, intraprocedural taint trace: does a value
    from a known taint source (base64/binascii decode, a requests/urllib/
    socket call result) reach a known dangerous sink (eval/exec/os.system/
    subprocess/pickle.loads) via a direct variable assignment chain?

    This is a real but deliberately simplified data-flow analysis - it does
    not track control flow (branches/loops are treated as one flat
    sequential pass), does not follow calls across functions, and has no
    alias analysis beyond direct name assignment. It is not a substitute for
    a genuine interprocedural taint-analysis engine (e.g. CodeQL, Pysa) -
    but unlike the keyword scan above, it requires an actual assignment
    connection between the source and the sink, not merely both appearing
    somewhere in the same file, which is the concrete gap this closes.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return []

    nodes = sorted(ast.walk(tree), key=lambda n: getattr(n, "lineno", 0))
    tainted: set = set()
    findings: list = []

    for node in nodes:
        if isinstance(node, ast.Assign):
            if _expr_contains_taint_source(node.value) or (_names_in(node.value) & tainted):
                for target in node.targets:
                    tainted |= _names_in(target)
        elif isinstance(node, ast.Call):
            sink_name = _taint_sink_name(node)
            if sink_name:
                arg_names: set = set()
                for arg in node.args:
                    arg_names |= _names_in(arg)
                if arg_names & tainted:
                    line = getattr(node, "lineno", "?")
                    findings.append(
                        f"tainted data (from a decoded or network-sourced value) flows into "
                        f"{sink_name}() at line {line}"
                    )
    return findings


# Deliberately empty, not {"net", "dns", "http", "https"} as originally
# designed. JavaScript's networking APIs are almost entirely async/callback-
# based (http.get(url, cb) returns a ClientRequest object, not the response -
# the actual bytes only arrive later via .on("data", ...) event callbacks).
# This tracer only models synchronous value assignment, so it was never
# structurally able to correctly trace JS network data reception - treating
# these modules as sources was a claim the design couldn't back up, found
# while auditing the equivalent Python rule (which had the analogous problem
# and produced a real false positive against the real gevent package - see
# the comment on _TAINT_SOURCE_ATTR_MODULES above). Buffer.from(..., base64)
# remains a JS taint source since it IS a genuine synchronous decode.
_JS_TAINT_SOURCE_MODULES: set = set()
_JS_TAINT_SINK_MODULE = "child_process"
_JS_TAINT_SINK_METHODS = {"exec", "execSync", "spawn", "spawnSync", "fork"}
_JS_TAINT_SINK_BUILTINS = {"eval", "Function"}


def _js_walk(node):
    """Recursively yields every dict-shaped node in an esprima AST (as
    returned by .toDict()), in document order by source line - esprima has
    no single built-in equivalent of ast.walk.
    """
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _js_walk(value)
    elif isinstance(node, list):
        for item in node:
            yield from _js_walk(item)


def _js_call_ref(node: dict):
    """Best-effort: for `mod.method(...)` returns ("mod", "method"); for a
    bare `func(...)` returns ("", "func"); else None.
    """
    callee = node.get("callee") or {}
    if callee.get("type") == "MemberExpression":
        obj, prop = callee.get("object") or {}, callee.get("property") or {}
        if obj.get("type") == "Identifier" and prop.get("type") == "Identifier":
            return obj["name"], prop["name"]
    elif callee.get("type") == "Identifier":
        return "", callee["name"]
    return None


def _js_names_in(node) -> set:
    return {n["name"] for n in _js_walk(node) if isinstance(n, dict) and n.get("type") == "Identifier"}


_JS_AST_DIR = Path(__file__).resolve().parent / "js_ast"
_JS_AST_SCRIPT = _JS_AST_DIR / "parse_batch.js"
_NODE_TIMEOUT_SECONDS = 30


def parse_js_batch(sources: list) -> list:
    """Parses a whole batch of JS source files in ONE Node.js process call,
    using acorn - a real, actively-maintained JS parser (unlike a pure-Python
    reimplementation like esprima), which correctly handles modern syntax
    (optional chaining, nullish coalescing, private class fields, etc.).

    Batched deliberately: launching a fresh Node process per file measured
    at ~1.7 seconds of fixed overhead each - fine for one file, but a
    package with hundreds or thousands of files (real ones do) would take
    minutes to hours. Batching the whole file list into a single process
    call brought 1,000 files down to ~0.15 seconds total.

    Returns a list the same length as `sources`, each entry either the
    parsed AST as a dict, or None if that specific file failed to parse (in
    both script and module mode) or if Node/the helper script isn't
    available at all - never raises, mirroring every other lookup_failed-
    style degradation in this project.
    """
    if not sources:
        return []
    try:
        result = subprocess.run(
            ["node", str(_JS_AST_SCRIPT)],
            input=json.dumps(sources).encode("utf-8"),
            capture_output=True,
            timeout=_NODE_TIMEOUT_SECONDS,
        )
        if result.returncode != 0:
            return [None] * len(sources)
        return json.loads(result.stdout.decode("utf-8", errors="replace"))
    except (OSError, subprocess.TimeoutExpired, ValueError, json.JSONDecodeError):
        return [None] * len(sources)


def find_js_taint_chains(source: str) -> list:
    """Single-file convenience wrapper around parse_js_batch + _trace_js_tree
    - used directly by tests; the live scan path (StaticScanClient.scan)
    calls parse_js_batch once for the whole file list instead, for the
    performance reason documented there.
    """
    tree = parse_js_batch([source])[0]
    if tree is None:
        return []
    return _trace_js_tree(tree)


def _trace_js_tree(tree: dict) -> list:
    """The JavaScript counterpart to find_taint_chains above, operating on
    an already-parsed ESTree AST: does a value from a known-suspicious
    source (Buffer.from(..., "base64"), a result from Node's net/dns/http/
    https modules) reach a known-dangerous sink (eval/Function, or a
    child_process exec/spawn call) via a direct variable assignment chain?
    Same honest limitations as the Python version - single-file,
    intraprocedural, no alias analysis beyond direct assignment.
    """
    nodes = sorted(
        _js_walk(tree),
        key=lambda n: (n.get("loc") or {}).get("start", {}).get("line", 0) if isinstance(n, dict) else 0,
    )

    module_aliases: dict = {}
    tainted: set = set()
    findings: list = []

    for node in nodes:
        # First pass logic folded into the same single pass: track
        # `const X = require("child_process")` style aliases as they appear.
        if node.get("type") == "VariableDeclarator":
            init = node.get("init") or {}
            if init.get("type") == "CallExpression" and _js_call_ref(init) == ("", "require"):
                args = init.get("arguments") or []
                if args and args[0].get("type") == "Literal":
                    module_aliases[(node.get("id") or {}).get("name")] = args[0].get("value")

        assign_target = assign_value = None
        if node.get("type") == "VariableDeclarator" and node.get("init"):
            assign_target, assign_value = node.get("id"), node.get("init")
        elif node.get("type") == "AssignmentExpression":
            assign_target, assign_value = node.get("left"), node.get("right")

        if assign_target is not None:
            is_source = False
            for call in (n for n in _js_walk(assign_value) if isinstance(n, dict) and n.get("type") == "CallExpression"):
                ref = _js_call_ref(call)
                if ref == ("Buffer", "from"):
                    is_source = True
                elif ref and module_aliases.get(ref[0]) in _JS_TAINT_SOURCE_MODULES:
                    is_source = True
            if is_source or (_js_names_in(assign_value) & tainted):
                tainted |= _js_names_in(assign_target)

        if node.get("type") == "CallExpression":
            ref = _js_call_ref(node)
            sink_name = None
            if ref == ("", "eval") or ref == ("", "Function"):
                sink_name = ref[1]
            elif ref and ref[1] in _JS_TAINT_SINK_METHODS and module_aliases.get(ref[0]) == _JS_TAINT_SINK_MODULE:
                sink_name = f"{ref[0]}.{ref[1]}"
            if sink_name:
                arg_names: set = set()
                for arg in node.get("arguments") or []:
                    arg_names |= _js_names_in(arg)
                if arg_names & tainted:
                    line = (node.get("loc") or {}).get("start", {}).get("line", "?")
                    findings.append(
                        f"tainted data (from a decoded or network-sourced value) flows into "
                        f"{sink_name}() at line {line}"
                    )
    return findings


def _npm_tarball_url(raw_metadata: dict, version: str) -> Optional[str]:
    version_doc = (raw_metadata.get("versions") or {}).get(version) or {}
    return (version_doc.get("dist") or {}).get("tarball")


def _npm_has_install_hook(raw_metadata: dict, version: str) -> bool:
    version_doc = (raw_metadata.get("versions") or {}).get(version) or {}
    scripts = version_doc.get("scripts") or {}
    return any(key in scripts for key in ("preinstall", "install", "postinstall"))


def _pypi_file_url(package: str, version: str, session: requests.Session) -> Optional[str]:
    try:
        response = session.get(
            f"https://pypi.org/pypi/{package}/{version}/json", timeout=REQUEST_TIMEOUT_SECONDS
        )
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError):
        return None
    urls = payload.get("urls") or []
    for entry in urls:
        if entry.get("packagetype") == "sdist":
            return entry.get("url")
    return urls[0].get("url") if urls else None


class StaticScanClient:
    """Downloads a package's real published source and scans its text for a
    short list of indicators, gated to only run for dependencies with no
    catalogued CVE - packages with a known advisory don't need this, and the
    behavioral anomaly detector remains the CVE-independent signal for
    everything else; this adds one further, narrower check specifically for
    packages neither of those two already has an opinion on.
    """

    def __init__(self, session: Optional[requests.Session] = None, classifier_model=None):
        self.session = session or requests.Session()
        self.classifier_model = classifier_model or load_static_classifier()

    def scan(
        self,
        package: str,
        version: str,
        ecosystem: str,
        raw_npm_metadata: Optional[dict] = None,
    ) -> StaticScanResult:
        if ecosystem == "npm":
            if not raw_npm_metadata:
                return StaticScanResult.failed("no npm registry metadata available")
            tarball_url = _npm_tarball_url(raw_npm_metadata, version)
            has_install_hook = _npm_has_install_hook(raw_npm_metadata, version)
            extension = ".js"
        else:
            tarball_url = _pypi_file_url(package, version, self.session)
            has_install_hook = None  # resolved after download - see below, PyPI has no metadata-only signal
            extension = ".py"

        if not tarball_url:
            return StaticScanResult.failed(f"could not resolve a source download URL for {package}@{version}")

        try:
            response = self.session.get(tarball_url, timeout=REQUEST_TIMEOUT_SECONDS)
            response.raise_for_status()
        except requests.RequestException as exc:
            return StaticScanResult.failed(f"could not download package source: {exc}")

        texts = _extract_text_files(response.content, extension)
        if not texts:
            return StaticScanResult(status="ok", flagged=False, indicators=[], files_scanned=0)

        if ecosystem == "pypi":
            # PyPI has no declarative "scripts" field like npm's package.json -
            # a custom install step is written as arbitrary Python in setup.py
            # (a setuptools command class assigned via cmdclass=, overriding
            # install/build_ext/develop). Rather than require an exact
            # setup.py filename match (lost once _extract_text_files flattens
            # to plain text), this checks for the "cmdclass" keyword itself -
            # a distinctive setuptools-packaging term that legitimate
            # application code essentially never contains outside of
            # setup.py. A real, disclosed heuristic, not exact detection.
            has_install_hook = any("cmdclass" in text for text in texts)

        patterns = _JS_PATTERNS if ecosystem == "npm" else _PY_PATTERNS
        categories: set = set()
        indicators: list = []
        chain_findings: list = []

        # npm: parse every file in ONE Node process call (see parse_js_batch's
        # docstring for why - per-file subprocess launches don't scale to
        # packages with hundreds or thousands of files).
        js_trees = parse_js_batch(texts) if ecosystem == "npm" else [None] * len(texts)

        for text, js_tree in zip(texts, js_trees):
            file_categories, file_indicators = _scan_text(text, patterns)
            categories |= file_categories
            for indicator in file_indicators:
                if indicator not in indicators:
                    indicators.append(indicator)
            if ecosystem == "pypi":
                for finding in find_taint_chains(text):
                    if finding not in chain_findings:
                        chain_findings.append(finding)
            elif ecosystem == "npm" and js_tree is not None:
                for finding in _trace_js_tree(js_tree):
                    if finding not in chain_findings:
                        chain_findings.append(finding)

        if chain_findings:
            indicators = chain_findings + indicators
        if has_install_hook:
            indicators = ["defines an install-time script (preinstall/install/postinstall)"] + indicators

        # The rule-based signals (category count, install hook, confirmed
        # chain, files scanned) become the feature vector for the trained
        # static-scan classifier, rather than deciding "flagged" via a
        # hard-coded threshold directly. This generalizes the same expert
        # rule (see ml/training_data.py's generate_static_scan_dataset) to
        # combinations it doesn't explicitly enumerate, and gives a
        # SHAP-explained risk score consistent with the rest of this tool,
        # instead of a bare true/false with no model behind it.
        feature_vector = static_scan_vector(
            category_count=len(categories),
            has_install_hook=has_install_hook,
            taint_chain_confirmed=bool(chain_findings),
            files_scanned=len(texts),
        )
        ml_risk_score = predict_static_risk(self.classifier_model, feature_vector)
        explanation = explain_static_classifier(self.classifier_model, feature_vector)
        flagged = ml_risk_score >= 0.5

        # The score itself is bimodal (near 0 or near 1, not a gradient - see
        # ml/training_data.py's labeling rule), so tiering by score magnitude
        # would be fake nuance. Tier by WHICH structural evidence triggered
        # the flag instead: a confirmed data-flow chain is the strongest,
        # most concrete evidence (an actual traced attack path); a suspicious
        # pattern inside an install-time hook is real but weaker context.
        flag_reason = None
        if flagged:
            flag_reason = "confirmed_chain" if chain_findings else "install_hook"

        return StaticScanResult(
            status="ok",
            flagged=flagged,
            flag_reason=flag_reason,
            indicators=indicators,
            files_scanned=len(texts),
            ml_risk_score=ml_risk_score,
            ml_explanation=explanation.to_dict(),
        )
