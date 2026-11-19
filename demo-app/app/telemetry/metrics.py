"""Business metrics — only metrics that automatic instrumentation cannot provide.

HTTP metrics (request count, duration, error rate, active requests) are generated
automatically by the FastAPI/ASGI instrumentation; we do not duplicate them.
"""

from opentelemetry import metrics


class BusinessMetrics:
    """Counters for business events, labeled with low-cardinality attributes only."""

    def __init__(self) -> None:
        meter = metrics.get_meter("centralwatch-demo-app.business", "1.0.0")
        # NOTE: the Collector's Prometheus exporter applies the namespace
        # "centralwatch", so these names surface as e.g.
        # centralwatch_orders_created_total in Prometheus.
        self.orders_created = meter.create_counter(
            "orders.created_total",
            description="Total number of orders created",
            unit="1",
        )
        self.images_processed = meter.create_counter(
            "images.processed_total",
            description="Total number of images processed",
            unit="1",
        )
        self.notifications_sent = meter.create_counter(
            "notifications.sent_total",
            description="Total number of notifications sent",
            unit="1",
        )
        self.file_uploads = meter.create_counter(
            "files.uploaded_total",
            description="Total number of files uploaded",
            unit="1",
        )
        self.retry_attempts = meter.create_counter(
            "retry.attempts_total",
            description="Total number of AWS SDK retry attempts",
            unit="1",
        )
        self.security_scans = meter.create_counter(
            "security.scans_total",
            description="Total number of AWS minimum-security scans",
            unit="1",
        )
        self.security_remediations = meter.create_counter(
            "security.remediations_total",
            description="Total number of permission-gated AWS security remediations",
            unit="1",
        )
        # API exposure scanner. Brace units keep the Prometheus exporter from adding a unit suffix.
        self.api_exposure_apis = meter.create_gauge(
            "api_exposure.apis",
            description="APIs in the AWS account at the last scan, by exposure (total/public/unauthenticated)",
            unit="{api}",
        )
        self.api_exposure_findings = meter.create_gauge(
            "api_exposure.findings",
            description="API exposure findings at the last scan, by severity",
            unit="{finding}",
        )
        self.api_exposure_rescans = meter.create_counter(
            "api_exposure.rescans_total",
            description="API exposure scans, by trigger (manual/startup/scheduled)",
            unit="{scan}",
        )
        self.api_exposure_up = meter.create_gauge(
            "api_exposure.up",
            description="1 if the exposed API answered the last probe without only server errors, else 0",
            unit="{state}",
        )
        self.api_exposure_response_time = meter.create_gauge(
            "api_exposure.response_time",
            description="Average response time of the exposed API's probed routes at the last scan",
            unit="ms",
        )
        self.api_exposure_leaks = meter.create_gauge(
            "api_exposure.leaks",
            description="Data leaks found at the last probed scan, by kind and severity",
            unit="{leak}",
        )
        self.api_exposure_deep_test_findings = meter.create_gauge(
            "api_exposure.deep_test_findings",
            description="OWASP ASTF deep test findings at the last run, by severity",
            unit="{finding}",
        )
