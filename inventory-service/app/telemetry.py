import os

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor


def configure_telemetry(app=None) -> None:
    """Set up OpenTelemetry tracing for the inventory service."""
    service_name = os.getenv("SERVICE_NAME", "centralwatch-inventory")
    environment = os.getenv("ENVIRONMENT", "development")
    otlp_endpoint = os.getenv(
        "OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4318"
    )

    resource = Resource.create(
        {
            "service.name": service_name,
            "service.version": "1.0.0",
            "deployment.environment": environment,
        }
    )

    provider = TracerProvider(resource=resource)

    exporter = OTLPSpanExporter(
        endpoint=f"{otlp_endpoint}/v1/traces",
    )
    provider.add_span_processor(BatchSpanProcessor(exporter))

    trace.set_tracer_provider(provider)

    # Instrument requests library for outbound HTTP calls
    RequestsInstrumentor().instrument()

    # Instrument FastAPI (must be called after app creation)
    if app is not None:
        FastAPIInstrumentor.instrument_app(app)
