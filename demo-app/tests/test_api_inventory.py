"""The API crawl inventories every source, flags the risky settings, and keeps going when one source fails."""

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
        get_stages={"item": [{"stageName": "dev"}]},  # no throttling, logging or WAF
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
        list_functions={"Functions": [{"FunctionName": "resize", "FunctionArn": "arn:resize"}]},
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
        ("orders", "route_no_auth", "DELETE /orders/{id}", "critical"),
        ("orders", "cors_any_origin", "CORS", "medium"),
        ("resize", "url_no_auth", "function URL", "critical"),
        ("resize", "no_throttling", "function URL", "medium"),
        ("i-1", "open_port", "sg-1 port 8000", "medium"),
        ("i-1", "open_port", "sg-1 port 22", "high"),
    }
    assert result["findings"][0]["severity"] == "critical"
    assert all(f["fix"] and f["owasp"].startswith("API") for f in result["findings"])
    assert "--resource-id r1 --http-method GET" in next(f["command"] for f in result["findings"] if f["target"] == "GET /users")

    assert result["summary"] == {
        "total": 4, "public": 4, "unauthenticated": 3, "regions": 1, "errors": 1,
        "findings": {"critical": 2, "high": 2, "medium": 6, "low": 1}, "probed_requests": 0,
    }
    assert result["errors"][0]["source"] == "AppSync GraphQL"
    assert result["errors"][0]["error"].startswith("AccessDeniedException")


def test_probe_confirms_open_routes_and_adds_live_findings(monkeypatch):
    called = []

    def fake_get(url):
        called.append(url)
        if url.endswith("/users"):
            return {"status": 200, "headers": {"Access-Control-Allow-Origin": "*", "Content-Type": "application/json"}, "bytes": 50}
        return {"status": 403, "headers": {}, "bytes": 20}

    monkeypatch.setattr(api_inventory, "_get", fake_get)
    monkeypatch.setattr(api_inventory, "_old_tls", lambda host, port: "TLSv1")
    open_get = api_inventory._open_route("GET /users", "cmd")
    open_post = api_inventory._open_route("POST /users", "cmd")
    api = api_inventory._api(
        "API Gateway REST", "ap-south-1", "rest1", "legacy", ["https://rest1.example/dev"], "MIXED",
        [{"route": "GET /users", "auth": "NONE"}, {"route": "POST /users", "auth": "NONE"}, {"route": "GET /admin/{id}", "auth": "AWS_IAM"}],
        public=True, findings=[open_get, open_post],
    )

    api_inventory._probe(api)

    assert called == ["https://rest1.example/dev/users", "https://rest1.example/dev/admin/1"]  # never the POST route
    assert open_get["confirmed"] is True and open_get["severity"] == "critical" and "returned 200" in open_get["evidence"]
    assert "confirmed" not in open_post
    added = {f["check"]: f for f in api["findings"][2:]}
    assert set(added) == {"missing_security_headers", "cors_any_origin", "old_tls"}
    assert "Strict-Transport-Security, X-Content-Type-Options, Cache-Control" in added["missing_security_headers"]["evidence"]
    assert "disableExecuteApiEndpoint" in added["old_tls"]["command"]
    assert [r["status"] for r in api["probe"]] == [200, 403] and "headers" not in api["probe"][0]
