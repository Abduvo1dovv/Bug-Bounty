"""
Super Monster v1.0.0 - Notification System Module

Multi-channel notification engine for bug bounty intelligence alerts.
Supports console (colored), file logging, and webhook delivery to
Discord, Slack, and Telegram. Features rate limiting, quiet hours,
batch aggregation, and configurable severity thresholds.

Channels:
  - Console: Colored terminal output with severity badges
  - File Log: Plain text append to configurable log file
  - Webhook: JSON POST to Discord/Slack/Telegram/generic endpoints

Event Types:
  - NEW_CRITICAL: New critical or high severity finding discovered
  - FINDING_FIXED: Previously reported finding confirmed fixed
  - NEW_SUBDOMAIN: New subdomain discovered during recon
  - STALE_FINDING: Finding persists beyond threshold (default 30 days)
  - ATTACK_CHAIN_DETECTED: New attack chain correlation identified
"""

import json
import os
import sys
import time
import hashlib
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
import urllib.request
import urllib.error
import urllib.parse

try:
    from colorama import Fore, Back, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    class _FakeColor:
        def __getattr__(self, name):
            return ""
    Fore = _FakeColor()
    Back = _FakeColor()
    Style = _FakeColor()

from super_monster.config import (
    Colors,
    TOOL_NAME,
    TOOL_BANNER,
    NOTIFICATION_THRESHOLDS,
    SEVERITY_LEVELS,
    WEBHOOK_CONFIG,
    SLACK_CONFIG,
    get_notification_level,
)


# =============================================================================
# EVENT TYPE CONSTANTS
# =============================================================================

EVENT_NEW_CRITICAL = "NEW_CRITICAL"
EVENT_FINDING_FIXED = "FINDING_FIXED"
EVENT_NEW_SUBDOMAIN = "NEW_SUBDOMAIN"
EVENT_STALE_FINDING = "STALE_FINDING"
EVENT_ATTACK_CHAIN_DETECTED = "ATTACK_CHAIN_DETECTED"

ALL_EVENT_TYPES = [
    EVENT_NEW_CRITICAL,
    EVENT_FINDING_FIXED,
    EVENT_NEW_SUBDOMAIN,
    EVENT_STALE_FINDING,
    EVENT_ATTACK_CHAIN_DETECTED,
]


# =============================================================================
# CHANNEL CONSTANTS
# =============================================================================

CHANNEL_CONSOLE = "console"
CHANNEL_FILE_LOG = "file_log"
CHANNEL_WEBHOOK = "webhook"

ALL_CHANNELS = [CHANNEL_CONSOLE, CHANNEL_FILE_LOG, CHANNEL_WEBHOOK]


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class NotificationEvent:
    """Represents a single notification event to be dispatched."""

    event_type: str = ""
    severity: str = "INFO"
    title: str = ""
    message: str = ""
    timestamp: str = ""
    finding_id: str = ""
    domain: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat() + "Z"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the event to a dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NotificationEvent":
        """Create event from dictionary."""
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


@dataclass
class NotificationConfig:
    """Configuration for the notification system."""

    enabled_channels: List[str] = field(default_factory=lambda: [CHANNEL_CONSOLE])
    webhook_urls: List[str] = field(default_factory=list)
    log_file_path: str = "super_monster_notifications.log"
    batch_enabled: bool = False
    batch_interval: int = 300
    max_per_hour: int = 20
    quiet_hours_start: int = 23
    quiet_hours_end: int = 7
    discord_webhook: str = ""
    slack_webhook: str = ""
    telegram_webhook: str = ""
    telegram_chat_id: str = ""

    @classmethod
    def from_env(cls) -> "NotificationConfig":
        """Load configuration from environment variables."""
        config = cls()
        config.discord_webhook = os.environ.get("SM_DISCORD_WEBHOOK", "")
        config.slack_webhook = os.environ.get("SM_SLACK_WEBHOOK", "")
        config.telegram_webhook = os.environ.get("SM_TELEGRAM_WEBHOOK", "")
        config.telegram_chat_id = os.environ.get("SM_TELEGRAM_CHAT_ID", "")
        log_path = os.environ.get("SM_NOTIFICATION_LOG", "")
        if log_path:
            config.log_file_path = log_path
        channels_str = os.environ.get("SM_NOTIFICATION_CHANNELS", "")
        if channels_str:
            config.enabled_channels = [
                ch.strip() for ch in channels_str.split(",") if ch.strip()
            ]
        max_hour = os.environ.get("SM_MAX_NOTIFICATIONS_HOUR", "")
        if max_hour.isdigit():
            config.max_per_hour = int(max_hour)
        if config.discord_webhook or config.slack_webhook or config.telegram_webhook:
            if CHANNEL_WEBHOOK not in config.enabled_channels:
                config.enabled_channels.append(CHANNEL_WEBHOOK)
        return config


# =============================================================================
# NOTIFICATION MANAGER
# =============================================================================

class NotificationManager:
    """
    Central notification dispatch engine.

    Manages multi-channel delivery with rate limiting, quiet hours,
    batch aggregation, and per-channel formatting. Tracks notification
    history and provides statistics for monitoring.
    """

    def __init__(self, config: Optional[NotificationConfig] = None):
        """Initialize the notification manager with optional config."""
        self.config = config or NotificationConfig()
        self._history: List[Dict[str, Any]] = []
        self._batch_queue: List[NotificationEvent] = []
        self._last_sent: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._notification_count: int = 0
        self._hourly_reset: datetime = datetime.utcnow()
        self._hourly_count: int = 0
        self._total_sent: int = 0
        self._total_failed: int = 0
        self._channel_stats: Dict[str, Dict[str, int]] = {
            CHANNEL_CONSOLE: {"sent": 0, "failed": 0},
            CHANNEL_FILE_LOG: {"sent": 0, "failed": 0},
            CHANNEL_WEBHOOK: {"sent": 0, "failed": 0},
        }

    def notify(self, event: NotificationEvent) -> bool:
        """
        Main dispatch method. Sends notification through all configured channels.

        Returns True if at least one channel successfully delivered the notification.
        """
        with self._lock:
            if not self._should_send(event):
                self._history.append({
                    "event": event.to_dict(),
                    "status": "suppressed",
                    "reason": "rate_limit_or_quiet_hours",
                    "timestamp": datetime.utcnow().isoformat(),
                })
                return False

            if self.config.batch_enabled and event.severity not in ("CRITICAL", "HIGH"):
                self.add_to_batch(event)
                return True

            results = self._dispatch_to_channels(event)
            success = any(results.values())

            self._history.append({
                "event": event.to_dict(),
                "status": "sent" if success else "failed",
                "channel_results": results,
                "timestamp": datetime.utcnow().isoformat(),
            })

            if success:
                self._notification_count += 1
                self._hourly_count += 1
                self._total_sent += 1
                event_key = f"{event.event_type}:{event.finding_id}:{event.domain}"
                self._last_sent[event_key] = time.time()
            else:
                self._total_failed += 1

            return success

    def _should_send(self, event: NotificationEvent) -> bool:
        """Check rate limits, quiet hours, and deduplication thresholds."""
        if event.severity == "CRITICAL":
            return True

        if self._is_quiet_hours() and event.severity not in ("CRITICAL", "HIGH"):
            return False

        if not self._check_rate_limit():
            return False

        event_key = f"{event.event_type}:{event.finding_id}:{event.domain}"
        last_time = self._last_sent.get(event_key)
        if last_time is not None:
            elapsed = time.time() - last_time
            if elapsed < 60:
                return False

        return True

    def _is_quiet_hours(self) -> bool:
        """Check if current time falls within quiet hours."""
        current_hour = datetime.utcnow().hour
        start = self.config.quiet_hours_start
        end = self.config.quiet_hours_end

        if start > end:
            return current_hour >= start or current_hour < end
        else:
            return start <= current_hour < end

    def _check_rate_limit(self) -> bool:
        """Check if we are within the hourly rate limit."""
        now = datetime.utcnow()
        if (now - self._hourly_reset).total_seconds() >= 3600:
            self._hourly_count = 0
            self._hourly_reset = now

        return self._hourly_count < self.config.max_per_hour

    def _dispatch_to_channels(self, event: NotificationEvent) -> Dict[str, bool]:
        """Send notification to all configured channels. Returns per-channel results."""
        results: Dict[str, bool] = {}

        if CHANNEL_CONSOLE in self.config.enabled_channels:
            success = self._send_console(event)
            results[CHANNEL_CONSOLE] = success
            self._channel_stats[CHANNEL_CONSOLE]["sent" if success else "failed"] += 1

        if CHANNEL_FILE_LOG in self.config.enabled_channels:
            success = self._send_file_log(event)
            results[CHANNEL_FILE_LOG] = success
            self._channel_stats[CHANNEL_FILE_LOG]["sent" if success else "failed"] += 1

        if CHANNEL_WEBHOOK in self.config.enabled_channels:
            webhook_success = False
            if self.config.discord_webhook:
                if self._send_webhook(event, self.config.discord_webhook, "discord"):
                    webhook_success = True
            if self.config.slack_webhook:
                if self._send_webhook(event, self.config.slack_webhook, "slack"):
                    webhook_success = True
            if self.config.telegram_webhook:
                if self._send_webhook(event, self.config.telegram_webhook, "telegram"):
                    webhook_success = True
            for url in self.config.webhook_urls:
                if self._send_webhook(event, url, "generic"):
                    webhook_success = True
            results[CHANNEL_WEBHOOK] = webhook_success
            self._channel_stats[CHANNEL_WEBHOOK][
                "sent" if webhook_success else "failed"
            ] += 1

        return results

    def _send_console(self, event: NotificationEvent) -> bool:
        """Send colored notification to console output."""
        try:
            formatted = self._format_console_message(event)
            print(formatted, file=sys.stderr)
            return True
        except Exception:
            return False

    def _send_file_log(self, event: NotificationEvent) -> bool:
        """Append plain text notification to log file."""
        try:
            log_path = Path(self.config.log_file_path)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            formatted = self._format_file_message(event)
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(formatted + "\n")
            return True
        except Exception:
            return False

    def _send_webhook(self, event: NotificationEvent, url: str, platform: str) -> bool:
        """Send notification via webhook POST to the specified platform."""
        try:
            if platform == "discord":
                payload = self._build_discord_payload(event)
            elif platform == "slack":
                payload = self._build_slack_payload(event)
            elif platform == "telegram":
                payload = self._build_telegram_payload(event)
            else:
                payload = self._build_generic_payload(event)

            return self._post_webhook(
                url, payload, timeout=WEBHOOK_CONFIG.get("timeout", 10)
            )
        except Exception:
            return False

    def _format_console_message(self, event: NotificationEvent) -> str:
        """Format notification for colored console output."""
        severity_color = Colors.severity_color(event.severity)
        reset = Colors.RESET
        emoji = self._get_event_emoji(event.event_type)

        badge = f"{severity_color}[{event.severity}]{reset}"
        header = f"{Colors.HEADER}[{TOOL_NAME}]{reset}"
        title_str = f"{Colors.LABEL}{event.title}{reset}"
        time_str = f"{Colors.TIMER}{event.timestamp[:19]}{reset}"

        lines = [
            f"{header} {emoji} {badge} {title_str}",
            f"  {Colors.VALUE}{event.message}{reset}",
        ]

        if event.domain:
            lines.append(f"  {Colors.SUBHEADER}Domain:{reset} {event.domain}")
        if event.finding_id:
            lines.append(f"  {Colors.SUBHEADER}Finding:{reset} {event.finding_id}")
        if event.details:
            for key, value in list(event.details.items())[:5]:
                lines.append(f"  {Colors.DIMMED}{key}:{reset} {value}")

        lines.append(f"  {time_str}")
        lines.append("")

        return "\n".join(lines)

    def _format_file_message(self, event: NotificationEvent) -> str:
        """Format notification as plain text for file logging."""
        ts = event.timestamp[:19] if event.timestamp else datetime.utcnow().strftime(
            "%Y-%m-%dT%H:%M:%S"
        )
        parts = [
            f"[{ts}]",
            f"[{event.severity}]",
            f"[{event.event_type}]",
            event.title,
        ]
        line = " ".join(parts)

        if event.message:
            line += f" | {event.message}"
        if event.domain:
            line += f" | domain={event.domain}"
        if event.finding_id:
            line += f" | finding_id={event.finding_id}"
        if event.details:
            detail_str = "; ".join(
                f"{k}={v}" for k, v in list(event.details.items())[:5]
            )
            line += f" | {detail_str}"

        return line

    def _format_webhook_message(self, event: NotificationEvent) -> str:
        """Format notification as markdown for webhook delivery."""
        emoji = self._get_event_emoji(event.event_type)
        lines = [
            f"{emoji} **[{event.severity}]** {event.title}",
            "",
            event.message,
            "",
        ]

        if event.domain:
            lines.append(f"**Domain:** `{event.domain}`")
        if event.finding_id:
            lines.append(f"**Finding ID:** `{event.finding_id}`")
        if event.details:
            lines.append("")
            lines.append("**Details:**")
            for key, value in list(event.details.items())[:8]:
                lines.append(f"- {key}: {value}")

        lines.append("")
        lines.append(f"_Sent by {TOOL_BANNER} at {event.timestamp[:19]}_")

        return "\n".join(lines)

    def _build_discord_payload(self, event: NotificationEvent) -> dict:
        """Build Discord embed payload with color sidebar."""
        color_hex = self._get_severity_color_hex(event.severity)
        color_int = int(color_hex.lstrip("#"), 16)

        embed = {
            "title": f"{self._get_event_emoji(event.event_type)} {event.title}",
            "description": event.message,
            "color": color_int,
            "timestamp": event.timestamp,
            "footer": {"text": TOOL_BANNER},
            "fields": [],
        }

        if event.severity:
            embed["fields"].append({
                "name": "Severity",
                "value": event.severity,
                "inline": True,
            })
        if event.domain:
            embed["fields"].append({
                "name": "Domain",
                "value": event.domain,
                "inline": True,
            })
        if event.event_type:
            embed["fields"].append({
                "name": "Event Type",
                "value": event.event_type.replace("_", " ").title(),
                "inline": True,
            })
        if event.finding_id:
            embed["fields"].append({
                "name": "Finding ID",
                "value": f"`{event.finding_id}`",
                "inline": True,
            })

        if event.details:
            detail_lines = []
            for key, value in list(event.details.items())[:6]:
                detail_lines.append(f"**{key}:** {value}")
            if detail_lines:
                embed["fields"].append({
                    "name": "Details",
                    "value": "\n".join(detail_lines),
                    "inline": False,
                })

        return {"embeds": [embed]}

    def _build_slack_payload(self, event: NotificationEvent) -> dict:
        """Build Slack Block Kit payload."""
        emoji = self._get_event_emoji(event.event_type)
        color = self._get_severity_color_hex(event.severity)

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} {event.title}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": event.message,
                },
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{event.severity}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Event:*\n{event.event_type.replace('_', ' ').title()}",
                    },
                ],
            },
        ]

        if event.domain or event.finding_id:
            fields = []
            if event.domain:
                fields.append({
                    "type": "mrkdwn",
                    "text": f"*Domain:*\n`{event.domain}`",
                })
            if event.finding_id:
                fields.append({
                    "type": "mrkdwn",
                    "text": f"*Finding:*\n`{event.finding_id}`",
                })
            blocks.append({"type": "section", "fields": fields})

        if event.details:
            detail_text = "\n".join(
                f"*{k}:* {v}" for k, v in list(event.details.items())[:6]
            )
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": detail_text},
            })

        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"{TOOL_BANNER} | {event.timestamp[:19]}",
                }
            ],
        })

        return {
            "blocks": blocks,
            "attachments": [{"color": color, "blocks": []}],
        }

    def _build_telegram_payload(self, event: NotificationEvent) -> dict:
        """Build Telegram sendMessage payload with HTML formatting."""
        emoji = self._get_event_emoji(event.event_type)
        lines = [
            f"{emoji} <b>[{event.severity}] {event.title}</b>",
            "",
            event.message,
            "",
        ]

        if event.domain:
            lines.append(f"<b>Domain:</b> <code>{event.domain}</code>")
        if event.finding_id:
            lines.append(f"<b>Finding:</b> <code>{event.finding_id}</code>")
        if event.details:
            lines.append("")
            for key, value in list(event.details.items())[:5]:
                lines.append(f"<b>{key}:</b> {value}")

        lines.append("")
        lines.append(f"<i>{TOOL_BANNER} | {event.timestamp[:19]}</i>")

        text = "\n".join(lines)

        payload = {
            "chat_id": self.config.telegram_chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }

        return payload

    def _build_generic_payload(self, event: NotificationEvent) -> dict:
        """Build generic JSON webhook payload."""
        return {
            "source": TOOL_BANNER,
            "event_type": event.event_type,
            "severity": event.severity,
            "title": event.title,
            "message": event.message,
            "timestamp": event.timestamp,
            "finding_id": event.finding_id,
            "domain": event.domain,
            "details": event.details,
            "metadata": event.metadata,
        }

    def _get_severity_color_hex(self, severity: str) -> str:
        """Get hex color code for a severity level."""
        color_map = {
            "CRITICAL": "#FF0000",
            "HIGH": "#FF6600",
            "MEDIUM": "#FFCC00",
            "LOW": "#0099FF",
            "INFO": "#999999",
        }
        return color_map.get(severity.upper(), "#999999")

    def _get_event_emoji(self, event_type: str) -> str:
        """Get emoji representation for an event type."""
        emoji_map = {
            EVENT_NEW_CRITICAL: "\U0001f6a8",
            EVENT_FINDING_FIXED: "\u2705",
            EVENT_NEW_SUBDOMAIN: "\U0001f310",
            EVENT_STALE_FINDING: "\u23f0",
            EVENT_ATTACK_CHAIN_DETECTED: "\u26d3\ufe0f",
        }
        return emoji_map.get(event_type, "\U0001f514")

    def _post_webhook(self, url: str, payload: dict, timeout: int = 10) -> bool:
        """Execute HTTP POST to webhook URL using urllib.request."""
        try:
            json_data = json.dumps(payload).encode("utf-8")

            if len(json_data) > WEBHOOK_CONFIG.get("max_payload_size", 65536):
                return False

            headers = {
                "Content-Type": "application/json",
                "User-Agent": f"{TOOL_NAME}/{__import__('super_monster.config', fromlist=['TOOL_VERSION']).TOOL_VERSION}",
            }

            req = urllib.request.Request(
                url, data=json_data, headers=headers, method="POST"
            )

            max_retries = WEBHOOK_CONFIG.get("max_retries", 3)
            retry_delay = WEBHOOK_CONFIG.get("retry_delay", 5)

            for attempt in range(max_retries):
                try:
                    response = urllib.request.urlopen(req, timeout=timeout)
                    status = response.getcode()
                    if 200 <= status < 300:
                        return True
                    if status >= 500 and attempt < max_retries - 1:
                        time.sleep(retry_delay)
                        continue
                    return False
                except urllib.error.HTTPError as e:
                    if e.code >= 500 and attempt < max_retries - 1:
                        time.sleep(retry_delay)
                        continue
                    return False
                except urllib.error.URLError:
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)
                        continue
                    return False
                except OSError:
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)
                        continue
                    return False

            return False
        except Exception:
            return False

    def batch_flush(self) -> int:
        """Flush all queued batch notifications. Returns count of flushed items."""
        with self._lock:
            if not self._batch_queue:
                return 0

            count = len(self._batch_queue)
            summary_event = NotificationEvent(
                event_type=EVENT_NEW_CRITICAL,
                severity="MEDIUM",
                title=f"Batch Notification Summary ({count} events)",
                message=self._build_batch_summary(),
                details={"batch_count": count},
            )

            self._dispatch_to_channels(summary_event)
            flushed = count
            self._batch_queue.clear()
            return flushed

    def _build_batch_summary(self) -> str:
        """Build a summary message from queued batch events."""
        if not self._batch_queue:
            return "No events in queue."

        type_counts: Dict[str, int] = {}
        severity_counts: Dict[str, int] = {}
        domains: set = set()

        for evt in self._batch_queue:
            type_counts[evt.event_type] = type_counts.get(evt.event_type, 0) + 1
            severity_counts[evt.severity] = severity_counts.get(evt.severity, 0) + 1
            if evt.domain:
                domains.add(evt.domain)

        lines = [f"Batched {len(self._batch_queue)} notifications:"]
        for etype, count in sorted(type_counts.items()):
            lines.append(f"  - {etype}: {count}")
        lines.append("Severity breakdown:")
        for sev, count in sorted(severity_counts.items()):
            lines.append(f"  - {sev}: {count}")
        if domains:
            lines.append(f"Domains affected: {', '.join(sorted(domains)[:10])}")

        return "\n".join(lines)

    def add_to_batch(self, event: NotificationEvent) -> None:
        """Add an event to the batch queue for later delivery."""
        self._batch_queue.append(event)

    def get_history(self) -> List[Dict[str, Any]]:
        """Get the notification history log."""
        with self._lock:
            return list(self._history)

    def get_statistics(self) -> dict:
        """Get notification delivery statistics."""
        with self._lock:
            return {
                "total_sent": self._total_sent,
                "total_failed": self._total_failed,
                "total_notifications": self._notification_count,
                "hourly_count": self._hourly_count,
                "batch_queue_size": len(self._batch_queue),
                "history_size": len(self._history),
                "channel_stats": dict(self._channel_stats),
                "rate_limit_max": self.config.max_per_hour,
                "quiet_hours": f"{self.config.quiet_hours_start}:00-{self.config.quiet_hours_end}:00",
                "enabled_channels": list(self.config.enabled_channels),
            }

    def clear_history(self) -> None:
        """Clear all notification history."""
        with self._lock:
            self._history.clear()
            self._notification_count = 0
            self._total_sent = 0
            self._total_failed = 0
            for channel in self._channel_stats:
                self._channel_stats[channel] = {"sent": 0, "failed": 0}


# =============================================================================
# HELPER FUNCTIONS - Event creation from various sources
# =============================================================================

def create_event_from_finding(finding, event_type: str) -> NotificationEvent:
    """
    Create a NotificationEvent from a Finding dataclass instance.

    Args:
        finding: A Finding dataclass with standard fields.
        event_type: The event type constant (e.g., EVENT_NEW_CRITICAL).

    Returns:
        A populated NotificationEvent ready for dispatch.
    """
    title_map = {
        EVENT_NEW_CRITICAL: f"New {finding.severity} Finding: {finding.title}",
        EVENT_FINDING_FIXED: f"Finding Fixed: {finding.title}",
        EVENT_STALE_FINDING: f"Stale Finding: {finding.title}",
        EVENT_ATTACK_CHAIN_DETECTED: f"Attack Chain: {finding.title}",
        EVENT_NEW_SUBDOMAIN: f"New Subdomain: {finding.domain}",
    }

    message_map = {
        EVENT_NEW_CRITICAL: (
            f"A new {finding.severity} severity vulnerability has been detected. "
            f"Type: {finding.finding_type}. Target: {finding.url or finding.domain}."
        ),
        EVENT_FINDING_FIXED: (
            f"The vulnerability '{finding.title}' has been confirmed as fixed. "
            f"Originally found on {finding.domain}."
        ),
        EVENT_STALE_FINDING: (
            f"The finding '{finding.title}' has been open for an extended period. "
            f"Consider escalation or re-verification."
        ),
        EVENT_ATTACK_CHAIN_DETECTED: (
            f"A new attack chain has been identified involving '{finding.title}'. "
            f"Check correlation details for exploitation path."
        ),
        EVENT_NEW_SUBDOMAIN: (
            f"New subdomain discovered: {finding.domain}. "
            f"Initiating reconnaissance."
        ),
    }

    details = {}
    if finding.url:
        details["url"] = finding.url
    if finding.finding_type:
        details["type"] = finding.finding_type
    if finding.cvss_score:
        details["cvss"] = str(finding.cvss_score)
    if finding.evidence:
        details["evidence"] = finding.evidence[:200]
    if finding.cwe_id:
        details["cwe"] = finding.cwe_id

    return NotificationEvent(
        event_type=event_type,
        severity=finding.severity,
        title=title_map.get(event_type, f"{event_type}: {finding.title}"),
        message=message_map.get(event_type, finding.description[:300]),
        finding_id=finding.id,
        domain=finding.domain,
        details=details,
        metadata={
            "source_report": getattr(finding, "source_report", ""),
            "priority_score": getattr(finding, "priority_score", 0.0),
        },
    )


def create_chain_event(chain_info: dict) -> NotificationEvent:
    """
    Create a notification event for a newly detected attack chain.

    Args:
        chain_info: Dictionary with chain details including:
            - chain_name: Name/identifier of the chain
            - severity: Overall chain severity
            - findings: List of finding IDs in the chain
            - description: Human-readable chain description
            - domain: Primary domain affected
            - confidence: Correlation confidence score

    Returns:
        A NotificationEvent for the attack chain detection.
    """
    chain_name = chain_info.get("chain_name", "Unknown Chain")
    severity = chain_info.get("severity", "HIGH")
    findings = chain_info.get("findings", [])
    description = chain_info.get("description", "")
    domain = chain_info.get("domain", "")
    confidence = chain_info.get("confidence", 0.0)

    title = f"Attack Chain Detected: {chain_name}"
    message = (
        f"A {len(findings)}-step attack chain has been identified with "
        f"{confidence:.0%} confidence. {description}"
    )

    details = {
        "chain_name": chain_name,
        "chain_length": str(len(findings)),
        "confidence": f"{confidence:.2f}",
        "finding_ids": ", ".join(findings[:5]),
    }

    return NotificationEvent(
        event_type=EVENT_ATTACK_CHAIN_DETECTED,
        severity=severity,
        title=title,
        message=message,
        domain=domain,
        details=details,
        metadata={"full_chain_info": chain_info},
    )


def create_subdomain_event(subdomain: str, domain: str) -> NotificationEvent:
    """
    Create a notification event for a newly discovered subdomain.

    Args:
        subdomain: The full subdomain that was discovered.
        domain: The parent domain.

    Returns:
        A NotificationEvent for the new subdomain.
    """
    title = f"New Subdomain Discovered: {subdomain}"
    message = (
        f"The subdomain '{subdomain}' has been identified under '{domain}'. "
        f"Automated reconnaissance will be initiated."
    )

    return NotificationEvent(
        event_type=EVENT_NEW_SUBDOMAIN,
        severity="INFO",
        title=title,
        message=message,
        domain=domain,
        details={
            "subdomain": subdomain,
            "parent_domain": domain,
        },
    )


def create_stale_event(finding, days_stale: int) -> NotificationEvent:
    """
    Create a notification event for a stale (long-unresolved) finding.

    Args:
        finding: The Finding dataclass that has gone stale.
        days_stale: Number of days the finding has been open.

    Returns:
        A NotificationEvent for the stale finding alert.
    """
    severity = "HIGH" if days_stale > 60 else "MEDIUM" if days_stale > 30 else "LOW"

    title = f"Stale Finding ({days_stale} days): {finding.title}"
    message = (
        f"The {finding.severity} finding '{finding.title}' has been open for "
        f"{days_stale} days without resolution. Original severity: {finding.severity}. "
        f"Consider escalation or vendor follow-up."
    )

    details = {
        "days_stale": str(days_stale),
        "original_severity": finding.severity,
        "finding_type": finding.finding_type,
        "status": getattr(finding, "status", "unknown"),
    }
    if finding.url:
        details["url"] = finding.url

    return NotificationEvent(
        event_type=EVENT_STALE_FINDING,
        severity=severity,
        title=title,
        message=message,
        finding_id=finding.id,
        domain=finding.domain,
        details=details,
    )


def create_fixed_event(finding) -> NotificationEvent:
    """
    Create a notification event for a finding that has been confirmed fixed.

    Args:
        finding: The Finding dataclass that is now fixed.

    Returns:
        A NotificationEvent for the fixed finding alert.
    """
    title = f"Finding Fixed: {finding.title}"
    message = (
        f"The vulnerability '{finding.title}' ({finding.severity}) on "
        f"{finding.domain} has been confirmed as remediated. "
        f"Type: {finding.finding_type}."
    )

    details = {
        "finding_type": finding.finding_type,
        "original_severity": finding.severity,
    }
    if finding.url:
        details["url"] = finding.url
    if finding.cvss_score:
        details["cvss"] = str(finding.cvss_score)

    return NotificationEvent(
        event_type=EVENT_FINDING_FIXED,
        severity="INFO",
        title=title,
        message=message,
        finding_id=finding.id,
        domain=finding.domain,
        details=details,
    )


# =============================================================================
# NOTIFICATION FORMATTER
# =============================================================================

class NotificationFormatter:
    """
    Utility class for formatting notification content across channels.

    Provides consistent formatting for severity badges, timestamps,
    finding summaries, and chain descriptions.
    """

    @staticmethod
    def format_severity_badge(severity: str) -> str:
        """
        Format a severity level as a colored console badge.

        Args:
            severity: Severity level string (CRITICAL, HIGH, MEDIUM, LOW, INFO).

        Returns:
            Colorized badge string for terminal display.
        """
        color = Colors.severity_color(severity)
        reset = Colors.RESET
        badge_chars = {
            "CRITICAL": f"{color}[!!!]{reset}",
            "HIGH": f"{color}[!! ]{reset}",
            "MEDIUM": f"{color}[!  ]{reset}",
            "LOW": f"{color}[.  ]{reset}",
            "INFO": f"{color}[i  ]{reset}",
        }
        return badge_chars.get(severity.upper(), f"{color}[?  ]{reset}")

    @staticmethod
    def format_timestamp(dt: Optional[datetime] = None) -> str:
        """
        Format a datetime as a consistent notification timestamp.

        Args:
            dt: Datetime object. Uses current UTC time if None.

        Returns:
            ISO 8601 formatted timestamp string.
        """
        if dt is None:
            dt = datetime.utcnow()
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def format_finding_summary(finding) -> str:
        """
        Create a one-line summary of a finding for notification context.

        Args:
            finding: Finding dataclass instance.

        Returns:
            Concise one-line finding summary.
        """
        parts = []
        if finding.severity:
            parts.append(f"[{finding.severity}]")
        if finding.finding_type:
            parts.append(finding.finding_type)
        if finding.title:
            title = finding.title[:60] + "..." if len(finding.title) > 60 else finding.title
            parts.append(title)
        if finding.domain:
            parts.append(f"({finding.domain})")
        if finding.cvss_score:
            parts.append(f"CVSS:{finding.cvss_score}")

        return " ".join(parts)

    @staticmethod
    def format_chain_summary(chain: dict) -> str:
        """
        Create a summary string for an attack chain.

        Args:
            chain: Dictionary with chain_name, findings, confidence, description.

        Returns:
            Multi-line chain summary suitable for notifications.
        """
        name = chain.get("chain_name", "Unknown")
        findings = chain.get("findings", [])
        confidence = chain.get("confidence", 0.0)
        description = chain.get("description", "")

        lines = [
            f"Chain: {name} ({len(findings)} steps, {confidence:.0%} confidence)",
        ]
        if description:
            lines.append(f"  {description}")
        if findings:
            steps = " -> ".join(findings[:5])
            if len(findings) > 5:
                steps += f" -> ... (+{len(findings) - 5} more)"
            lines.append(f"  Path: {steps}")

        return "\n".join(lines)

    @staticmethod
    def truncate_message(msg: str, max_len: int = 500) -> str:
        """
        Truncate a message to a maximum length with ellipsis indicator.

        Args:
            msg: The message string to truncate.
            max_len: Maximum allowed length.

        Returns:
            Original or truncated message.
        """
        if not msg:
            return ""
        if len(msg) <= max_len:
            return msg
        return msg[: max_len - 3] + "..."


# =============================================================================
# NOTIFICATION FILTER
# =============================================================================

class NotificationFilter:
    """
    Filter engine for determining which events should trigger notifications.

    Supports filtering by minimum severity, event type whitelist,
    and domain matching patterns.
    """

    def __init__(
        self,
        min_severity: str = "INFO",
        event_types: Optional[List[str]] = None,
        domains: Optional[List[str]] = None,
    ):
        """
        Initialize the notification filter.

        Args:
            min_severity: Minimum severity level to allow (inclusive).
            event_types: Whitelist of event types. None means all types.
            domains: Whitelist of domains. None means all domains.
        """
        self.min_severity = min_severity.upper()
        self.event_types = event_types
        self.domains = [d.lower() for d in domains] if domains else None
        self._severity_order = {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "INFO": 1,
        }

    def should_notify(self, event: NotificationEvent) -> bool:
        """
        Determine if an event passes all filter criteria.

        Args:
            event: The NotificationEvent to evaluate.

        Returns:
            True if the event should be dispatched, False otherwise.
        """
        if not self.matches_severity(event.severity):
            return False

        if not self.matches_event_type(event.event_type):
            return False

        if not self.matches_domain(event.domain):
            return False

        return True

    def matches_severity(self, severity: str) -> bool:
        """
        Check if a severity level meets the minimum threshold.

        Args:
            severity: The severity level to check.

        Returns:
            True if severity is at or above the minimum.
        """
        if not severity:
            return False
        event_order = self._severity_order.get(severity.upper(), 0)
        min_order = self._severity_order.get(self.min_severity, 1)
        return event_order >= min_order

    def matches_event_type(self, event_type: str) -> bool:
        """
        Check if an event type is in the allowed whitelist.

        Args:
            event_type: The event type string to check.

        Returns:
            True if event type is allowed or no whitelist is set.
        """
        if self.event_types is None:
            return True
        return event_type in self.event_types

    def matches_domain(self, domain: str) -> bool:
        """
        Check if a domain matches the domain whitelist.

        Args:
            domain: The domain string to check.

        Returns:
            True if domain is allowed or no whitelist is set.
        """
        if self.domains is None:
            return True
        if not domain:
            return True
        domain_lower = domain.lower()
        for allowed in self.domains:
            if allowed in domain_lower or domain_lower.endswith(allowed):
                return True
        return False
