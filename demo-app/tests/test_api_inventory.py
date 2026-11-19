"""The API crawl inventories every source, flags the risky settings, and keeps going when one source fails."""

import json
import threading
import time
from types import SimpleNamespace

from botocore.exceptions import ClientError

from app.services import api_inventory


class Fake:
    """Answers any boto3 call (direct or paginated) with a canned response."""

    def __init__(self, **responses):
        self.responses = responses

    def get_paginator(self, operation):
        call = getattr(self, operation)
        return SimpleNamespace(paginate=lambda **kwargs: [call(**kwargs)])

    def __getattr__(self, operation):
        response = self.responses[operation]

        def call(**_):
            if isinstance(response, Exception):
                raise response
            return response
        return call


CLIENTS = {
    "apigateway": Fake(
        get_usage_plans={"items": []},
        get_rest_apis={"items": [{"id": "rest1", "name": "legacy", "endpointConfiguration": {"types": ["REGIONAL"]}}]},
        # no throttling, logging or WAF; one stage variable holds a token
        get_stages={"item": [{"stageName": "dev", "variables": {"apiToken": "tok_live_123456", "region": "ap-south-1"}}]},
        get_resources={"items": [
            {"id": "r1", "path": "/users", "resourceMethods": {
                "GET": {"authorizationType": "NONE"},
                "OPTIONS": {"authorizationType": "NONE"},  # CORS preflight: not a finding
            }},
            {"id": "r2", "path": "/admin", "resourceMethods": {"POST": {"authorizationType": "AWS_IAM", "apiKeyRequired": True}}},
        ]},
    ),
    "apigatewayv2": Fake(
        get_apis={"Items": [{
            "ApiId": "http1", "Name": "orders", "ProtocolType": "HTTP", "ApiEndpoint": "https://http1.example",
            "CorsConfiguration": {"AllowOrigins": ["*"]},
        }]},
        get_stages={"Items": [{
            "StageName": "$default",
            "DefaultRouteSettings": {"ThrottlingRateLimit": 50.0},
            "AccessLogSettings": {"DestinationArn": "arn:logs"},
        }]},
        get_routes={"Items": [
            {"RouteId": "a", "RouteKey": "GET /orders", "AuthorizationType": "JWT"},
            {"RouteId": "b", "RouteKey": "DELETE /orders/{id}", "AuthorizationType": "NONE"},
        ]},
    ),
    "lambda": Fake(
        list_functions={"Functions": [{"FunctionName": "resize", "FunctionArn": "arn:resize", "Environment": {"Variables": {
            "DB_PASSWORD": "hunter2-long",  # secret by name
            "LEGACY": "AKIAABCDEFGHIJKLMNOP",  # secret by value
            "TOKEN_TTL_SECONDS": "86400",  # a number, not a secret
            "SECRET_ARN": "arn:aws:secretsmanager:ap-south-1:1:secret:db",  # a reference: the right way
            "LOG_LEVEL": "INFO",
        }}}]},
        list_function_url_configs={"FunctionUrlConfigs": [{"FunctionUrl": "https://resize.lambda-url", "AuthType": "NONE"}]},
        get_function_concurrency={},
    ),
    "appsync": Fake(list_graphql_apis=ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, "List")),
    "elbv2": Fake(describe_load_balancers={"LoadBalancers": []}),
    "wafv2": Fake(),
    "ec2": Fake(
        describe_regions={"Regions": [{"RegionName": "ap-south-1"}]},
        describe_instances={"Reservations": [{"Instances": [
            {"InstanceId": "i-1", "PublicIpAddress": "13.0.0.1", "SecurityGroups": [{"GroupId": "sg-1"}]},
            {"InstanceId": "i-2"},  # no public IP: not part of the exposed inventory
        ]}]},
        describe_security_groups={"SecurityGroups": [{"GroupId": "sg-1", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 8000, "ToPort": 8000, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]},
            {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
        ]}]},
    ),
    "cloudfront": Fake(list_distributions={"DistributionList": {"Quantity": 0}}),
}


def test_crawl_inventories_every_source_and_flags_risky_settings(monkeypatch):
    monkeypatch.setattr(api_inventory, "make_client", lambda _session, service, _settings, region=None: CLIENTS[service])
    settings = SimpleNamespace(aws_endpoint_url="", aws_region="ap-south-1")

    result = api_inventory.crawl(object(), settings)
    apis = {api["id"]: api for api in result["apis"]}

    assert set(apis) == {"rest1", "http1", "resize", "i-1"}
    assert apis["rest1"]["urls"] == ["https://rest1.execute-api.ap-south-1.amazonaws.com/dev"]
    assert {"route": "POST /admin", "auth": "AWS_IAM+API_KEY"} in apis["rest1"]["routes"]
    assert apis["http1"]["urls"] == ["https://http1.example"]
    assert apis["i-1"]["urls"] == ["http://13.0.0.1:8000"]

    found = {(f["api"], f["check"], f["target"], f["severity"]) for f in result["findings"]}
    assert found == {
        ("legacy", "route_no_auth", "GET /users", "high"),
        ("legacy", "no_throttling", "stage dev", "medium"),
        ("legacy", "no_access_logs", "stage dev", "medium"),
        ("legacy", "no_waf", "stage dev", "medium"),
        ("legacy", "non_prod_stage", "stage dev", "low"),
        ("legacy", "settings_secret", "stage dev variable apiToken", "high"),
        ("orders", "route_no_auth", "DELETE /orders/{id}", "critical"),
        ("orders", "cors_any_origin", "CORS", "medium"),
        ("resize", "url_no_auth", "function URL", "critical"),
        ("resize", "no_throttling", "function URL", "medium"),
        ("resize", "settings_secret", "environment variable DB_PASSWORD", "high"),
        ("resize", "settings_secret", "environment variable LEGACY", "high"),
        ("i-1", "open_port", "sg-1 port 8000", "medium"),
        ("i-1", "open_port", "sg-1 port 22", "high"),
    }
    assert result["findings"][0]["severity"] == "critical"
    assert all(f["fix"] and f["owasp"].startswith("API") for f in result["findings"])
    assert "--resource-id r1 --http-method GET" in next(f["command"] for f in result["findings"] if f["target"] == "GET /users")
    assert not any(secret in json.dumps(result) for secret in ("hunter2", "AKIAABCD", "tok_live"))  # names only, never values

    assert result["summary"] == {
        "total": 4, "public": 4, "unauthenticated": 3, "regions": 1, "errors": 1,
        "findings": {"critical": 2, "high": 5, "medium": 6, "low": 1}, "probed_requests": 0,
        "health": {"up": 0, "errors": 0, "down": 0}, "leaks": 3,
    }
    assert result["errors"][0]["source"] == "AppSync GraphQL"
    assert result["errors"][0]["error"].startswith("AccessDeniedException")


def test_crawl_returns_within_its_time_budget_when_a_source_hangs(monkeypatch):
    release = threading.Event()

    def hanging(region, client):  # e.g. an endpoint whose DNS lookup never returns
        release.wait(5)
        return []

    monkeypatch.setitem(api_inventory.REGIONAL_SOURCES, "Lambda function URL", (("lambda",), hanging))
    monkeypatch.setattr(api_inventory, "make_client", lambda _session, service, _settings, region=None: CLIENTS[service])
    settings = SimpleNamespace(aws_endpoint_url="", aws_region="ap-south-1", api_scan_time_budget_seconds=1)

    started = time.monotonic()
    result = api_inventory.crawl(object(), settings)
    release.set()

    assert time.monotonic() - started < 3
    assert {api["id"] for api in result["apis"]} == {"rest1", "http1", "i-1"}  # everything that answered is still reported
    late = next(e for e in result["errors"] if e["source"] == "Lambda function URL")
    assert "No answer within 1s" in late["error"]


def test_probe_confirms_open_routes_and_adds_live_findings(monkeypatch):
    called = []
    leaky = json.dumps({
        "users": [{"email": "jane.doe@example.com", "card": "4111111111111111", "created": "1795061836148"}],
        "debug": "key AKIAABCDEFGHIJKLMNOP",
    })

    def fake_get(url):
        called.append(url)
        if url.endswith("/users"):
            headers = {"Access-Control-Allow-Origin": "*", "Content-Type": "application/json", "Server": "nginx/1.18.0"}
            return {"status": 200, "headers": headers, "bytes": len(leaky), "text": leaky, "ms": 120}
        return {"status": 403, "headers": {}, "bytes": 20, "text": "Forbidden", "ms": 80}

    monkeypatch.setattr(api_inventory, "_get", fake_get)
    monkeypatch.setattr(api_inventory, "_old_tls", lambda host, port: "TLSv1")
    monkeypatch.setattr(api_inventory, "_cert_days", lambda host, port: 10)
    open_get = api_inventory._open_route("GET /users", "cmd")
    open_post = api_inventory._open_route("POST /users", "cmd")
    api = api_inventory._api(
        "API Gateway REST", "ap-south-1", "rest1", "legacy", ["https://rest1.example/dev"], "MIXED",
        [{"route": "GET /users", "auth": "NONE"}, {"route": "POST /users", "auth": "NONE"}, {"route": "GET /admin/{id}", "auth": "AWS_IAM"}],
        public=True, findings=[open_get, open_post],
    )

    api_inventory._probe(api)

    assert called == ["https://rest1.example/dev/users", "https://rest1.example/dev/admin/1"]  # never the POST route
    assert open_get["confirmed"] is True and open_get["severity"] == "critical"
    assert "returned 200 with JSON with 1 record and no credentials, including" in open_get["evidence"]
    assert "an email address" in open_get["evidence"]
    assert "confirmed" not in open_post
    added = {f["check"]: f for f in api["findings"][2:]}
    assert set(added) == {"missing_security_headers", "cors_any_origin", "old_tls", "version_header", "response_leak", "cert_expiring"}
    assert "Strict-Transport-Security, X-Content-Type-Options, Cache-Control" in added["missing_security_headers"]["evidence"]
    assert "disableExecuteApiEndpoint" in added["old_tls"]["command"]
    assert "Server: nginx/1.18.0" in added["version_header"]["evidence"]
    assert added["cert_expiring"]["severity"] == "medium" and "10 days" in added["cert_expiring"]["evidence"]

    # The card number passes the Luhn check; the 13-digit timestamp is not mistaken for one.
    leaks = {f["kind"]: f for f in api["findings"] if f["check"] == "response_leak"}
    assert {kind: (f["severity"], f["owasp"][:4]) for kind, f in leaks.items()} == {
        "aws_access_key": ("critical", "API8"), "card_number": ("critical", "API3"), "email": ("high", "API3"),
    }
    assert "AKIA…" in leaks["aws_access_key"]["evidence"] and "jane…" in leaks["email"]["evidence"]
    stored = json.dumps(api)
    assert not any(raw in stored for raw in ("AKIAABCD", "jane.doe", "4111111111111111"))  # masked, never kept

    assert api["health"] == {"status": "up", "checked": 2, "answered": 2, "server_errors": 0, "avg_ms": 100, "max_ms": 120, "cert_days": 10}
    assert [r["status"] for r in api["probe"]] == [200, 403] and "headers" not in api["probe"][0] and "text" not in api["probe"][0]
    assert api["probe"][0]["leaks"] == ["aws_access_key", "card_number", "email"]


def test_probe_reports_an_api_that_does_not_answer_as_down(monkeypatch):
    monkeypatch.setattr(api_inventory, "_get", lambda url: {"status": None, "headers": {}, "bytes": 0, "text": "", "ms": 5000, "error": "TimeoutError"})
    monkeypatch.setattr(api_inventory, "_old_tls", lambda host, port: None)
    monkeypatch.setattr(api_inventory, "_cert_days", lambda host, port: None)
    api = api_inventory._api("Lambda function URL", "ap-south-1", "fn", "fn", ["https://fn.lambda-url"], "NONE", [], public=True, findings=[])

    api_inventory._probe(api)

    assert api["health"]["status"] == "down" and api["health"]["answered"] == 0
    assert api["findings"] == []  # an outage is health, not a security finding
