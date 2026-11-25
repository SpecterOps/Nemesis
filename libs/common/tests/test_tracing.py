"""Tracing setup: no span recording without monitoring; with it, export and client instrumentation (once)."""

import common.tracing as tracing
import pytest
from fastapi import FastAPI
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import NonRecordingSpan

INSTRUMENTORS = (
    "opentelemetry.instrumentation.grpc.GrpcInstrumentorClient",
    "opentelemetry.instrumentation.grpc.GrpcAioInstrumentorClient",
    "opentelemetry.instrumentation.asyncpg.AsyncPGInstrumentor",
    "opentelemetry.instrumentation.psycopg.PsycopgInstrumentor",
    "opentelemetry.instrumentation.urllib3.URLLib3Instrumentor",
    "opentelemetry.instrumentation.aiohttp_client.AioHttpClientInstrumentor",
    "opentelemetry.instrumentation.httpx.HTTPXClientInstrumentor",
)


@pytest.fixture
def providers(monkeypatch):
    """Reset the module singletons and capture the provider instead of installing it globally."""
    monkeypatch.setattr(tracing, "_tracer", None)
    monkeypatch.setattr(tracing, "_instrumented", False)
    installed = []
    monkeypatch.setattr(tracing.trace, "set_tracer_provider", installed.append)
    yield installed
    for provider in installed:
        provider.shutdown()


@pytest.fixture
def exporter(monkeypatch):
    exp = InMemorySpanExporter()
    created = {}

    def fake_exporter(**kwargs):
        created.update(kwargs)
        return exp

    monkeypatch.setattr(tracing, "OTLPSpanExporter", fake_exporter)
    exp.created_with = created
    return exp


@pytest.fixture
def instrument_calls(monkeypatch):
    calls = []
    for target in INSTRUMENTORS:
        monkeypatch.setattr(f"{target}.instrument", lambda self, _t=target: calls.append(_t))
        monkeypatch.setattr(f"{target}.is_instrumented_by_opentelemetry", False, raising=False)
    monkeypatch.setattr(
        "opentelemetry.instrumentation.fastapi.FastAPIInstrumentor.instrument_app",
        staticmethod(lambda app, **kwargs: calls.append(("fastapi", app, kwargs))),
    )
    return calls


def test_spans_are_not_recorded_without_monitoring(providers, instrument_calls, monkeypatch):
    monkeypatch.delenv("NEMESIS_MONITORING", raising=False)
    tracing.setup_tracing(FastAPI(), "svc")
    with tracing.get_tracer().start_as_current_span("x") as span:
        assert isinstance(span, NonRecordingSpan)
    assert instrument_calls == []
    assert len(providers) == 1


def test_spans_are_exported_with_monitoring(providers, exporter, instrument_calls, monkeypatch):
    monkeypatch.setenv("NEMESIS_MONITORING", "enabled")
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", raising=False)
    tracing.setup_tracing(FastAPI(), "svc")
    with tracing.get_tracer().start_as_current_span("x") as span:
        assert span.is_recording()
    providers[0].force_flush()

    (finished,) = exporter.get_finished_spans()
    assert finished.name == "x"
    assert finished.resource.attributes["service.name"] == "svc"
    assert finished.resource.attributes["service.version"] == "unknown"  # no package named "svc"
    assert exporter.created_with["endpoint"] == tracing.DEFAULT_OTLP_ENDPOINT


def test_exporter_endpoint_comes_from_the_environment(providers, exporter, instrument_calls, monkeypatch):
    monkeypatch.setenv("NEMESIS_MONITORING", "enabled")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://collector.example:4317")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT_INSECURE", "false")
    tracing.setup_tracing(FastAPI(), "svc")
    assert exporter.created_with == {"endpoint": "http://collector.example:4317", "insecure": False}


def test_setup_instruments_app_and_clients_once(providers, exporter, instrument_calls, monkeypatch):
    monkeypatch.setenv("NEMESIS_MONITORING", "enabled")
    app = FastAPI()
    tracing.setup_tracing(app, "svc")
    tracing.setup_tracing(app, "svc")

    assert len(providers) == 1
    assert len(instrument_calls) == len(INSTRUMENTORS) + 1
    _, instrumented_app, kwargs = next(c for c in instrument_calls if c[0] == "fastapi")
    assert instrumented_app is app
    assert "healthz" in kwargs["excluded_urls"]


def test_setup_skips_libraries_already_instrumented(providers, exporter, instrument_calls, monkeypatch):
    """The Dapr workflow SDK instruments sync gRPC itself; instrumenting again would only log a warning."""
    monkeypatch.setenv("NEMESIS_MONITORING", "enabled")
    monkeypatch.setattr(
        "opentelemetry.instrumentation.grpc.GrpcInstrumentorClient.is_instrumented_by_opentelemetry", True
    )
    tracing.setup_tracing(FastAPI(), "svc")
    assert "opentelemetry.instrumentation.grpc.GrpcInstrumentorClient" not in instrument_calls


def test_get_tracer_before_setup_is_safe(monkeypatch):
    monkeypatch.setattr(tracing, "_tracer", None)
    with tracing.get_tracer().start_as_current_span("x") as span:
        assert not span.is_recording()
