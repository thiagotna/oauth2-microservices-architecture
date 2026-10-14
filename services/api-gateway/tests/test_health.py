from src.presentation.main import HealthResponse, app


def test_gateway_app_initialized() -> None:
    assert app.title == "OAuth 2.0 API Gateway"
    resp = HealthResponse(status="healthy", service="api-gateway")
    assert resp.status == "healthy"