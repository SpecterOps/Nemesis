"""Tracing setup: no span recording without monitoring, client instrumentation only with it."""

import file_enrichment.tracing as tracing
import pytest
from fastapi import FastAPI
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import NonRecordingSpan


@pytest.fixture
def fresh(monkeypatch):
    """Reset the module singletons and stop setup from touching the global provider and libraries."""
    monkeypatch.setattr(tracing, "_tracer", None)
    monkeypatch.setattr(tracing, "_instrumented", False)
    providers = []
    monkeypatch.setattr(tracing.trace, "set_tracer_provider", providers.append)
    return providers


def test_spans_are_not_recorded_without_monitoring(fresh, monkeypatch):
    monkeypatch.delenv("NEMESIS_MONITORING", raising=False)
    with tracing.get_tracer().start_as_current_span("x") as span:
        assert isinstance(span, NonRecordingSpan)


def test_spans_are_recorded_and_exported_with_monitoring(fresh, monkeypatch):
    monkeypatch.setenv("NEMESIS_MONITORING", "enabled")
    exporter = InMemorySpanExporter()
    monkeypatch.setattr(tracing, "OTLPSpanExporter", lambda **kwargs: exporter)
    with tracing.get_tracer().start_as_current_span("x") as span:
        assert span.is_recording()
    fresh[0].force_flush()
    assert [s.name for s in exporter.get_finished_spans()] == ["x"]
    fresh[0].shutdown()


def test_tracer_is_created_once(fresh, monkeypatch):
    monkeypatch.delenv("NEMESIS_MONITORING", raising=False)
    assert tracing.get_tracer() is tracing.get_tracer()
    assert len(fresh) == 1


INSTRUMENTORS = (
    "opentelemetry.instrumentation.grpc.GrpcAioInstrumentorClient",
    "opentelemetry.instrumentation.asyncpg.AsyncPGInstrumentor",
    "opentelemetry.instrumentation.urllib3.URLLib3Instrumentor",
    "opentelemetry.instrumentation.aiohttp_client.AioHttpClientInstrumentor",
)


@pytest.fixture
def instrument_calls(monkeypatch):
    calls = []
    for target in INSTRUMENTORS:
        monkeypatch.setattr(f"{target}.instrument", lambda self, _t=target: calls.append(_t))
    monkeypatch.setattr(
        "opentelemetry.instrumentation.fastapi.FastAPIInstrumentor.instrument_app",
        staticmethod(lambda app, **kwargs: calls.append(("fastapi", app, kwargs))),
    )
    return calls


def test_setup_skips_instrumentation_without_monitoring(fresh, instrument_calls, monkeypatch):
    monkeypatch.setenv("NEMESIS_MONITORING", "disabled")
    tracing.setup_tracing(FastAPI())
    assert instrument_calls == []
    assert len(fresh) == 1  # the (non-recording) provider is still installed


def test_setup_instruments_app_and_clients_once_with_monitoring(fresh, instrument_calls, monkeypatch):
    monkeypatch.setenv("NEMESIS_MONITORING", "enabled")
    monkeypatch.setattr(tracing, "OTLPSpanExporter", lambda **kwargs: InMemorySpanExporter())
    app = FastAPI()
    tracing.setup_tracing(app)
    tracing.setup_tracing(app)

    assert len(instrument_calls) == len(INSTRUMENTORS) + 1
    _, instrumented_app, kwargs = next(c for c in instrument_calls if c[0] == "fastapi")
    assert instrumented_app is app
    assert "healthz" in kwargs["excluded_urls"]
    fresh[0].shutdown()
