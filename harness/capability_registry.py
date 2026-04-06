from __future__ import annotations

from .models import Capability, CapabilityBacklog


CAPABILITIES: tuple[Capability, ...] = (
    Capability(
        name="rspamd_scan_email",
        kind="tool",
        source_hint="mcp_server.py / skills/rspamd/skill.py",
        responsibility="Scan a raw RFC822 email with rspamd and return normalized risk signals.",
        trigger_terms=("phishing", "spam", "eml", "rfc822", "raw email", "scan email", "钓鱼", "垃圾邮件", "分析邮件"),
        followups=("email_header_auth_check", "urgency_check", "url_reputation_check"),
    ),
    Capability(
        name="email_header_auth_check",
        kind="tool",
        source_hint="mcp_server.py / skills/header_auth/skill.py",
        responsibility="Analyze SPF, DKIM, DMARC, ARC, and routing/authentication header signals.",
        trigger_terms=("headers", "spf", "dkim", "dmarc", "arc", "routing", "邮件头", "认证"),
    ),
    Capability(
        name="urgency_check",
        kind="tool",
        source_hint="mcp_server.py / skills/urgency/skill.py",
        responsibility="Score the urgency and social-pressure level of an email.",
        trigger_terms=("urgency", "pressure", "social engineering", "urgent", "紧急", "催促"),
    ),
    Capability(
        name="url_reputation_check",
        kind="tool",
        source_hint="mcp_server.py / skills/url_reputation/skill.py",
        responsibility="Score URL and content phishing risk from email text.",
        trigger_terms=("url", "link", "reputation", "domain", "phishing link", "链接", "域名", "网址"),
    ),
    Capability(
        name="error_pattern_memory_check",
        kind="tool",
        source_hint="mcp_server.py / skills/error_patterns/skill.py",
        responsibility="Consult stored dataset-derived error patterns before finalizing an email verdict.",
        trigger_terms=("error pattern", "memory check", "false positive", "false negative", "误判模式", "错误模式", "记忆检查"),
    ),
    Capability(
        name="list_error_patterns",
        kind="tool",
        source_hint="mcp_server.py / skills/error_patterns/skill.py",
        responsibility="List stored dataset-derived error patterns that can influence future verdicts.",
        trigger_terms=("list error patterns", "show error patterns", "stored patterns", "查看错误pattern", "查看错误模式", "错误模式列表"),
    ),
    Capability(
        name="list_bound_imap_mailboxes",
        kind="tool",
        source_hint="mcp_server.py / skills/imap_monitor/skill.py",
        responsibility="List locally saved IMAP mailbox bindings before asking the user for credentials again.",
        trigger_terms=("my inbox", "my email", "my mailbox", "recent emails", "bound mailbox", "我的邮箱", "我的收件箱", "最近邮件"),
    ),
    Capability(
        name="bind_imap_mailbox",
        kind="tool",
        source_hint="mcp_server.py / skills/imap_monitor/skill.py",
        responsibility="Bind a mailbox for IMAP monitoring and store its credentials locally.",
        trigger_terms=("bind gmail", "bind mailbox", "connect mailbox", "monitor mailbox", "绑定邮箱", "连接邮箱"),
    ),
    Capability(
        name="setup_imap_monitor",
        kind="tool",
        source_hint="mcp_server.py / skills/imap_monitor/skill.py",
        responsibility="Bind a mailbox, poll it once, and start background monitoring in one step.",
        trigger_terms=("setup monitor", "start monitoring", "watch inbox", "开启监控", "开始监控"),
        nested_tools=(
            "bind_imap_mailbox",
            "poll_imap_mailboxes_once",
            "start_imap_monitor",
            "rspamd_scan_email",
            "email_header_auth_check",
        ),
    ),
    Capability(
        name="start_imap_monitor",
        kind="tool",
        source_hint="mcp_server.py / skills/imap_monitor/skill.py",
        responsibility="Start the background IMAP monitor daemon.",
        trigger_terms=("start monitor", "resume monitor", "启动监控"),
    ),
    Capability(
        name="stop_imap_monitor",
        kind="tool",
        source_hint="mcp_server.py / skills/imap_monitor/skill.py",
        responsibility="Stop the background IMAP monitor daemon.",
        trigger_terms=("stop monitor", "disable monitor", "停止监控"),
    ),
    Capability(
        name="imap_monitor_status",
        kind="tool",
        source_hint="mcp_server.py / skills/imap_monitor/skill.py",
        responsibility="Show IMAP monitor status, bound mailbox count, and recent errors.",
        trigger_terms=("monitor status", "is monitor running", "bound mailboxes", "监控状态"),
    ),
    Capability(
        name="poll_imap_mailboxes_once",
        kind="tool",
        source_hint="mcp_server.py / skills/imap_monitor/skill.py",
        responsibility="Poll bound IMAP mailboxes once immediately for newly arrived mail.",
        trigger_terms=("poll mailbox", "check now", "fetch new mail", "立即检查", "拉取新邮件"),
        nested_tools=("rspamd_scan_email", "email_header_auth_check"),
        requires_bound_mailbox=True,
    ),
    Capability(
        name="list_recent_email_results",
        kind="tool",
        source_hint="mcp_server.py / skills/imap_monitor/skill.py",
        responsibility="Read cached recent mailbox scan results from local storage.",
        trigger_terms=("recent results", "stored results", "history", "历史结果", "最近结果"),
        requires_bound_mailbox=True,
    ),
    Capability(
        name="record_email_correction",
        kind="tool",
        source_hint="mcp_server.py / skills/imap_monitor/skill.py",
        responsibility="Store a correction pattern from a past misclassification so future similar emails can use memory guidance.",
        trigger_terms=("remember this", "remember pattern", "this was wrong", "misclassified", "record correction", "记住这个", "记住模式", "刚才错了", "误判"),
        requires_bound_mailbox=True,
    ),
    Capability(
        name="list_decision_memory",
        kind="tool",
        source_hint="mcp_server.py / skills/imap_monitor/skill.py",
        responsibility="List stored correction-memory patterns used to reduce repeated false positives or false negatives.",
        trigger_terms=("memory", "remembered patterns", "correction memory", "stored corrections", "记忆模块", "纠错记忆", "记住的模式"),
    ),
    Capability(
        name="scan_recent_imap_emails",
        kind="tool",
        source_hint="mcp_server.py / skills/imap_monitor/skill.py",
        responsibility="Fetch and analyze the latest N emails from a bound mailbox on demand.",
        trigger_terms=("recent emails", "latest emails", "newest emails", "my inbox", "phishing emails", "最近邮件", "最新邮件", "钓鱼邮件"),
        nested_tools=("rspamd_scan_email", "email_header_auth_check"),
        requires_bound_mailbox=True,
    ),
)


def capability_names() -> list[str]:
    return [item.name for item in CAPABILITIES]


def build_capability_backlog() -> CapabilityBacklog:
    return CapabilityBacklog(title="Capability surface", capabilities=list(CAPABILITIES))


def get_capability(name: str) -> Capability | None:
    needle = name.lower()
    for item in CAPABILITIES:
        if item.name.lower() == needle:
            return item
    return None


def tool_usage_guidance() -> list[str]:
    return [
        "- Use `list_bound_imap_mailboxes` first when the user asks about recent mailbox emails, monitoring, or \"my inbox\".",
        "- If exactly one mailbox is already bound, reuse it directly instead of asking for credentials again.",
        "- Use `rspamd_scan_email` when raw RFC822 email content is available and you need a scanner-backed verdict.",
        "- Use `email_header_auth_check` when the user provides headers only or asks about SPF, DKIM, DMARC, ARC, routing, or sender-domain mismatches.",
        "- If the evidence is incomplete, you may use both tools when helpful.",
        "- Use `error_pattern_memory_check` before finalizing an ambiguous verdict when repeated false positives or false negatives are a concern.",
        "- Use `list_error_patterns` when the user asks which dataset-derived error patterns are currently remembered.",
        "- Use `bind_imap_mailbox` when the user wants continuous mailbox monitoring over IMAP.",
        "- Prefer `setup_imap_monitor` when the user provides enough IMAP credentials and wants one-step setup.",
        "- After binding a mailbox, use `start_imap_monitor` to begin background polling.",
        "- Use `poll_imap_mailboxes_once` for immediate testing after binding credentials.",
        "- Use `imap_monitor_status` and `list_recent_email_results` to report monitoring progress and recent verdicts.",
        "- Use `record_email_correction` when the user says a past email verdict was wrong and wants future similar emails handled better.",
        "- Use `list_decision_memory` when the user asks what correction patterns are currently remembered.",
        "- Use `scan_recent_imap_emails` when the user asks about the latest or most recent emails in a bound mailbox, especially queries like \"latest 2 emails\", \"recent 50 emails\", or \"are the newest emails spam?\".",
    ]
