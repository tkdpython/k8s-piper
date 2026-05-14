"""Rich terminal output for k8s-piper analysis results.

Compatible with rich 9.x (Python 3.6) through rich 13.x (Python 3.12+).
Avoids rich.console.Group which was only introduced in rich 10.2.
"""

from typing import List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich import box

from k8s_piper.cert_analyzer import CertBundle

# Threshold in days at which we warn about upcoming expiry
_EXPIRY_WARN_DAYS = 30
_EXPIRY_CRITICAL_DAYS = 7

_console = Console()

# Column widths for the label column
_LABEL_WIDTH = 26


def _validity_style(days_remaining, is_expired):
    # type: (int, bool) -> str
    if is_expired or days_remaining <= _EXPIRY_CRITICAL_DAYS:
        return "bold red"
    if days_remaining <= _EXPIRY_WARN_DAYS:
        return "bold yellow"
    return "bold green"


def _validity_icon(days_remaining, is_expired):
    # type: (int, bool) -> str
    if is_expired:
        return "\u2717 EXPIRED"
    if days_remaining <= _EXPIRY_CRITICAL_DAYS:
        return "\u26a0 CRITICAL ({0} days)".format(days_remaining)
    if days_remaining <= _EXPIRY_WARN_DAYS:
        return "\u26a0 EXPIRING SOON ({0} days)".format(days_remaining)
    return "\u2713 Valid ({0} days remaining)".format(days_remaining)


def _fmt_dt(dt):
    # type: (object) -> str
    """Format a datetime as a friendly UTC string."""
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else "N/A"


def _build_cert_table(cert_info):
    # type: (dict) -> Table
    """Build a single rich Table containing all sections for one certificate.

    Uses a two-column grid layout compatible with rich 9.x+.  Section
    headings are inserted as full-width rows (empty label, styled value).
    """
    tbl = Table.grid(padding=(0, 1), expand=True)
    tbl.add_column(
        style="dim",
        justify="right",
        no_wrap=True,
        min_width=_LABEL_WIDTH,
        max_width=_LABEL_WIDTH,
    )
    tbl.add_column(ratio=1)

    days = cert_info["days_remaining"]
    expired = cert_info["is_expired"]

    def section(title):
        # type: (str) -> None
        """Add a blank spacer then a section heading row."""
        tbl.add_row("", "")
        tbl.add_row(
            "",
            Text(title, style="bold bright_white underline"),
        )

    def row(label, value, value_style=""):
        # type: (str, object, str) -> None
        """Add a label/value row; value may be a string or a Text instance."""
        if isinstance(value, Text):
            val = value
        else:
            val = Text(str(value), style=value_style)
        tbl.add_row(Text(label, style="dim"), val)

    # ── Subject ──────────────────────────────────────────────────
    section("\U0001f4cb  Subject")
    for k, v in cert_info["subject"]:
        row(k, v)

    # ── Issuer ───────────────────────────────────────────────────
    section("\U0001f3db   Issuer")
    for k, v in cert_info["issuer"]:
        row(k, v)

    # ── Validity ─────────────────────────────────────────────────
    validity_style = _validity_style(days, expired)
    section("\u23f1   Validity")
    row("Not Before", _fmt_dt(cert_info["not_before"]))
    row("Not After", _fmt_dt(cert_info["not_after"]))
    row("Status", Text(_validity_icon(days, expired), style=validity_style))

    # ── Public Key ───────────────────────────────────────────────
    section("\U0001f511  Public Key")
    row("Algorithm", cert_info["key_type"])
    row(
        "Key Size",
        "{0} bits".format(cert_info["key_bits"]) if cert_info["key_bits"] else "N/A",
    )
    row("Signature Algorithm", cert_info["signature_algorithm"])

    # ── SANs ─────────────────────────────────────────────────────
    sans = cert_info["sans"]
    section(
        "\U0001f310  Subject Alternative Names  [{0}]".format(len(sans))
        if sans
        else "\U0001f310  Subject Alternative Names  [none]"
    )
    if sans:
        for san_type, san_val in sans:
            row(san_type, san_val, value_style="cyan")
    else:
        row("", Text("(none)", style="dim"))

    # ── Key Usage ────────────────────────────────────────────────
    section("\U0001f6e1   Key Usage")
    if cert_info["key_usage"]:
        row("Key Usage", ", ".join(cert_info["key_usage"]))
    else:
        row("Key Usage", Text("(not set)", style="dim"))
    if cert_info["extended_key_usage"]:
        row("Extended Key Usage", ", ".join(cert_info["extended_key_usage"]))
    else:
        row("Extended Key Usage", Text("(not set)", style="dim"))

    # ── OCSP / Revocation ────────────────────────────────────────
    section("\U0001f512  OCSP / Revocation")
    if cert_info["ocsp_urls"]:
        for url in cert_info["ocsp_urls"]:
            row("OCSP URL", url)
    else:
        row("OCSP URL", Text("(not present)", style="dim"))
    if cert_info["ca_issuer_urls"]:
        for url in cert_info["ca_issuer_urls"]:
            row("CA Issuers URL", url)
    if cert_info["crl_urls"]:
        for url in cert_info["crl_urls"]:
            row("CRL Distribution Point", url)
    row(
        "OCSP Must-Staple",
        Text("Yes", style="green")
        if cert_info["ocsp_must_staple"]
        else Text("No", style="dim"),
    )

    # ── Fingerprints ─────────────────────────────────────────────
    section("\U0001f50d  Fingerprints")
    row("SHA-256", cert_info["fingerprint_sha256"])
    row("SHA-1", Text(cert_info["fingerprint_sha1"], style="dim yellow"))

    # ── Additional Details ───────────────────────────────────────
    section("\u2139   Additional Details")
    row("Serial Number", cert_info["serial"])
    row(
        "Self-Signed",
        Text("Yes", style="yellow")
        if cert_info["is_self_signed"]
        else Text("No", style="dim"),
    )
    row(
        "Is CA",
        Text("Yes", style="cyan")
        if cert_info["is_ca"]
        else Text("No", style="dim"),
    )
    if cert_info["path_length"] is not None:
        row("Path Length Constraint", str(cert_info["path_length"]))
    if cert_info["subject_key_id"]:
        row("Subject Key ID", cert_info["subject_key_id"])
    if cert_info["authority_key_id"]:
        row("Authority Key ID", cert_info["authority_key_id"])

    # trailing blank row for breathing room
    tbl.add_row("", "")
    return tbl


def _cert_panel(cert_info, index, total):
    # type: (dict, int, int) -> Panel
    """Return a rich Panel wrapping the cert table."""
    days = cert_info["days_remaining"]
    expired = cert_info["is_expired"]
    border_style = _validity_style(days, expired)

    title = Text()
    title.append(
        "  Certificate {0} of {1}  ".format(index, total),
        style="bold white",
    )
    if cert_info["is_self_signed"]:
        title.append("[Self-Signed] ", style="italic yellow")
    if cert_info["is_ca"]:
        title.append("[CA] ", style="italic cyan")

    return Panel(
        _build_cert_table(cert_info),
        title=title,
        border_style=border_style,
        box=box.ROUNDED,
        padding=(0, 1),
    )


def display_certs(manifest, bundles):
    # type: (object, List[CertBundle]) -> None
    """Print all certificate bundles to the terminal."""
    _console.print()
    _console.print(
        Panel(
            Text(manifest.source_label, style="bold white"),
            title="[bold cyan]k8s-piper  \u2022  Certificate Analysis[/bold cyan]",
            border_style="cyan",
            box=box.DOUBLE,
        )
    )

    if not bundles:
        _console.print(
            "\n[yellow]No certificates found in the manifest data fields.[/yellow]\n"
        )
        return

    for bundle in bundles:
        _console.print()
        _console.rule(
            "[bold white]Data Key: [cyan]{0}[/cyan][/bold white]  "
            "({1} certificate{2})".format(
                bundle.source_key,
                len(bundle.certs),
                "s" if len(bundle.certs) != 1 else "",
            )
        )

        total = len(bundle.certs)
        for i, cert_info in enumerate(bundle.certs, start=1):
            _console.print(_cert_panel(cert_info, i, total))

        for err in bundle.errors:
            _console.print("[red]  Warning: {0}[/red]".format(err))

    _console.print()

def pager_context():
    """Return a context manager that sends all console output through a pager.

    Usage::

        with pager_context():
            display_certs(...)
            display_non_cert_data(...)
    """
    return _console.pager(styles=True)


# ---------------------------------------------------------------------------
# Non-certificate data display (ConfigMap / Secret)
# ---------------------------------------------------------------------------

def _guess_lexer(key, value):
    # type: (str, str) -> str
    """Best-effort guess of a Pygments lexer name from the key extension or value content."""
    lower = key.lower()
    if lower.endswith((".yaml", ".yml")):
        return "yaml"
    if lower.endswith(".json"):
        return "json"
    if lower.endswith((".sh", ".bash")):
        return "bash"
    if lower.endswith(".xml"):
        return "xml"
    if lower.endswith((".properties", ".ini", ".cfg", ".conf")):
        return "ini"
    stripped = value.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        return "json"
    if stripped.startswith("---") or stripped.startswith("apiVersion:"):
        return "yaml"
    return "text"


def display_non_cert_data(manifest, non_cert_data):
    # type: (object, List[Tuple[str, str]]) -> None
    """Print non-certificate data entries from a ConfigMap or Secret."""
    if not non_cert_data:
        return

    _console.print()
    _console.rule(
        "[bold white]\U0001f4c4  Other Data Entries  ({0} key{1})[/bold white]".format(
            len(non_cert_data),
            "s" if len(non_cert_data) != 1 else "",
        )
    )

    for key, value in non_cert_data:
        lexer = _guess_lexer(key, value)
        if lexer != "text":
            content = Syntax(
                value,
                lexer,
                theme="monokai",
                word_wrap=True,
                background_color="default",
            )
        else:
            content = Text(value)

        _console.print()
        _console.print(
            Panel(
                content,
                title="[bold cyan]{0}[/bold cyan]".format(key),
                border_style="dim",
                box=box.ROUNDED,
                padding=(0, 1),
            )
        )

    _console.print()




def _icon_bool(value, true_style="green", false_style="dim"):
    # type: (Optional[bool], str, str) -> Text
    """Return a styled tick/cross Text for a boolean value."""
    if value is True:
        return Text("\u2713 Yes", style=true_style)
    if value is False:
        return Text("\u2717 No", style=false_style)
    return Text("(not set)", style="dim")


def _resource_cell(value, label=""):
    # type: (Optional[str], str) -> Text
    """Return a styled cell for a resource value; warns when absent."""
    if value:
        return Text(value)
    return Text("\u26a0 (none)", style="bold yellow")


def _build_images_table(containers, init_containers):
    # type: (list, list) -> Table
    tbl = Table(box=box.SIMPLE_HEAD, show_header=True, expand=True)
    tbl.add_column("Container", style="cyan", no_wrap=True)
    tbl.add_column("Type", style="dim", no_wrap=True)
    tbl.add_column("Image", no_wrap=False)
    tbl.add_column("Tag / Digest")
    tbl.add_column("Pull Policy")

    def _add_rows(ctrs, ctype):
        for c in ctrs:
            tag_cell = Text()
            if c.has_digest:
                tag_cell.append("@digest", style="dim cyan")
            elif c.image_tag is None:
                tag_cell.append("\u26a0 (none \u2014 implicit latest)", style="bold yellow")
            elif c.image_tag == "latest":
                tag_cell.append("\u26a0 latest", style="bold yellow")
            else:
                tag_cell.append(c.image_tag, style="green")

            policy = c.pull_policy or "(unset)"
            if policy == "Always":
                policy_cell = Text("Always", style="yellow")
            else:
                policy_cell = Text(policy)

            tbl.add_row(c.name, ctype, c.image_name or c.image, tag_cell, policy_cell)

    _add_rows(init_containers, "init")
    _add_rows(containers, "app")
    return tbl


def _build_resources_table(containers, init_containers):
    # type: (list, list) -> Table
    tbl = Table(box=box.SIMPLE_HEAD, show_header=True, expand=True)
    tbl.add_column("Container", style="cyan", no_wrap=True)
    tbl.add_column("Type", style="dim", no_wrap=True)
    tbl.add_column("CPU Request")
    tbl.add_column("CPU Limit")
    tbl.add_column("Mem Request")
    tbl.add_column("Mem Limit")

    def _add_rows(ctrs, ctype):
        for c in ctrs:
            r = c.resources
            tbl.add_row(
                c.name,
                ctype,
                _resource_cell(r["cpu_request"]),
                _resource_cell(r["cpu_limit"]),
                _resource_cell(r["memory_request"]),
                _resource_cell(r["memory_limit"]),
            )

    _add_rows(init_containers, "init")
    _add_rows(containers, "app")
    return tbl


def _build_security_table(workload_info):
    # type: (object) -> Table
    tbl = Table.grid(padding=(0, 1), expand=True)
    tbl.add_column(style="dim", justify="right", no_wrap=True, min_width=_LABEL_WIDTH, max_width=_LABEL_WIDTH)
    tbl.add_column(ratio=1)

    def section(title):
        tbl.add_row("", "")
        tbl.add_row("", Text(title, style="bold bright_white underline"))

    def row(label, value):
        if isinstance(value, Text):
            tbl.add_row(Text(label, style="dim"), value)
        else:
            tbl.add_row(Text(label, style="dim"), Text(str(value)))

    psc = workload_info.pod_security_context
    any_pod_sc = any(v is not None for v in psc.values() if not isinstance(v, list))
    section("\U0001f3e0  Pod Security Context")
    if any_pod_sc or psc.get("sysctls") or psc.get("supplemental_groups"):
        row("Run As Non-Root", _icon_bool(psc["run_as_non_root"]))
        if psc["run_as_user"] is not None:
            row("Run As User", str(psc["run_as_user"]))
        if psc["run_as_group"] is not None:
            row("Run As Group", str(psc["run_as_group"]))
        if psc["fs_group"] is not None:
            row("FS Group", str(psc["fs_group"]))
        if psc.get("seccomp_profile"):
            sp = psc["seccomp_profile"]
            row("Seccomp Profile", "{0}: {1}".format(sp.get("type", ""), sp.get("localhostProfile", "")))
        if psc.get("sysctls"):
            for s in psc["sysctls"]:
                row("Sysctl", "{0}={1}".format(s.get("name", ""), s.get("value", "")))
    else:
        row("", Text("(none set)", style="dim"))

    all_containers = workload_info.init_containers + workload_info.containers
    for c in all_containers:
        sc = c.security_context
        label = "\U0001f4e6  {0} ({1})".format(c.name, "init" if c.is_init else "app")
        section(label)

        row("Privileged", _icon_bool(sc["privileged"], true_style="bold red", false_style="green"))
        row("Allow Priv Escalation", _icon_bool(sc["allow_privilege_escalation"], true_style="bold red", false_style="green"))
        row("Read-only Root FS", _icon_bool(sc["read_only_root_filesystem"], true_style="green", false_style="yellow"))
        row("Run As Non-Root", _icon_bool(sc["run_as_non_root"]))
        if sc["run_as_user"] is not None:
            row("Run As User", str(sc["run_as_user"]))
        if sc["capabilities_add"]:
            row("Capabilities Add", Text(", ".join(sc["capabilities_add"]), style="bold red"))
        else:
            row("Capabilities Add", Text("(none)", style="dim"))
        if sc["capabilities_drop"]:
            row("Capabilities Drop", Text(", ".join(sc["capabilities_drop"]), style="green"))
        else:
            row("Capabilities Drop", Text("(none)", style="dim"))

    tbl.add_row("", "")
    return tbl


def display_workload(manifest, workload_info):
    # type: (object, object) -> None
    """Print images, resources, and security analysis for a workload resource."""
    _console.print()
    _console.print(
        Panel(
            Text(manifest.source_label, style="bold white"),
            title="[bold cyan]k8s-piper  \u2022  Workload Analysis[/bold cyan]",
            border_style="cyan",
            box=box.DOUBLE,
        )
    )

    all_containers = workload_info.init_containers + workload_info.containers
    if not all_containers:
        _console.print("\n[yellow]No containers found in this manifest.[/yellow]\n")
        return

    # --- Images ---
    _console.print()
    _console.rule("[bold white]\U0001f4e6  Container Images[/bold white]")
    _console.print(_build_images_table(workload_info.containers, workload_info.init_containers))

    # --- Resources ---
    _console.print()
    _console.rule("[bold white]\U0001f4ca  Resource Requests & Limits[/bold white]")
    _console.print(_build_resources_table(workload_info.containers, workload_info.init_containers))

    # --- Security ---
    _console.print()
    _console.rule("[bold white]\U0001f6e1   Security Contexts[/bold white]")
    _console.print(_build_security_table(workload_info))

    _console.print()


# ---------------------------------------------------------------------------
# RBAC display
# ---------------------------------------------------------------------------

def _build_rules_table(rules):
    # type: (list) -> Table
    tbl = Table(box=box.SIMPLE_HEAD, show_header=True, expand=True)
    tbl.add_column("API Groups")
    tbl.add_column("Resources")
    tbl.add_column("Verbs")
    tbl.add_column("Resource Names", style="dim")

    for rule in rules:
        groups_str = ", ".join(rule["api_groups"]) if rule["api_groups"] else '""'
        resources_str = ", ".join(rule["resources"]) if rule["resources"] else "(none)"
        verbs_str = ", ".join(rule["verbs"]) if rule["verbs"] else "(none)"
        names_str = ", ".join(rule["resource_names"]) if rule["resource_names"] else ""

        if rule["wildcard_group"]:
            groups_cell = Text(groups_str, style="bold red")
        else:
            groups_cell = Text(groups_str)

        if rule["wildcard_resource"]:
            resources_cell = Text(resources_str, style="bold red")
        else:
            resources_cell = Text(resources_str)

        if rule["wildcard_verb"]:
            verb_cell = Text(verbs_str + "  \u26a0", style="bold red")
        elif rule["is_dangerous"]:
            verb_cell = Text(verbs_str, style="bold red")
        else:
            verb_cell = Text(verbs_str)

        tbl.add_row(groups_cell, resources_cell, verb_cell, names_str)

    return tbl


def _build_subjects_table(subjects):
    # type: (list) -> Table
    tbl = Table(box=box.SIMPLE_HEAD, show_header=True, expand=True)
    tbl.add_column("Kind", style="cyan")
    tbl.add_column("Name")
    tbl.add_column("Namespace", style="dim")

    for s in subjects:
        tbl.add_row(
            s.get("kind", ""),
            s.get("name", ""),
            s.get("namespace") or "(cluster-wide)",
        )

    return tbl


def display_rbac(manifest, rbac_info):
    # type: (object, object) -> None
    """Print RBAC rules and subjects analysis."""
    _console.print()
    _console.print(
        Panel(
            Text(manifest.source_label, style="bold white"),
            title="[bold cyan]k8s-piper  \u2022  RBAC Analysis[/bold cyan]",
            border_style="cyan",
            box=box.DOUBLE,
        )
    )

    # Role / ClusterRole — show policy rules
    if rbac_info.kind in ("Role", "ClusterRole"):
        _console.print()
        if rbac_info.rules:
            _console.rule("[bold white]\U0001f4dc  Policy Rules[/bold white]")
            _console.print(_build_rules_table(rbac_info.rules))

            dangerous = [r for r in rbac_info.rules if r["is_dangerous"]]
            if dangerous:
                _console.print(
                    "[bold red]\u26a0  {0} rule(s) grant wildcard verbs on wildcard resources \u2014 "
                    "review carefully.[/bold red]".format(len(dangerous))
                )
        else:
            _console.print("\n[yellow]No policy rules defined.[/yellow]")

    # RoleBinding / ClusterRoleBinding — show role ref and subjects
    if rbac_info.kind in ("RoleBinding", "ClusterRoleBinding"):
        if rbac_info.role_ref:
            _console.print()
            _console.rule("[bold white]\U0001f517  Role Reference[/bold white]")
            ref_tbl = Table.grid(padding=(0, 1))
            ref_tbl.add_column(style="dim", justify="right", min_width=12)
            ref_tbl.add_column()
            ref_tbl.add_row("Kind", rbac_info.role_ref["kind"])
            ref_tbl.add_row("Name", rbac_info.role_ref["name"])
            ref_tbl.add_row("API Group", rbac_info.role_ref["api_group"] or '""')
            _console.print(ref_tbl)

        _console.print()
        _console.rule("[bold white]\U0001f465  Subjects[/bold white]")
        if rbac_info.subjects:
            _console.print(_build_subjects_table(rbac_info.subjects))
        else:
            _console.print("[yellow]No subjects defined.[/yellow]")

    _console.print()
