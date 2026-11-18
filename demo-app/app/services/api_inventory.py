"""Read-only crawl of every API the AWS account exposes, with the risky settings found on each.

Sources: API Gateway (REST, HTTP, WebSocket), Lambda function URLs, AppSync,
CloudFront, load balancers (ALB/NLB) and EC2 instances with a public IP.
Each API comes back as one dict: where it is, its URLs, how callers authenticate,
and its routes when AWS knows them. Each risky setting becomes a finding with a
severity, its OWASP API Security Top 10 (2023) category, evidence, the fix, and
an AWS CLI command for the fix. Nothing in AWS is changed.

With ``probe=True`` it also sends one unauthenticated GET per readable route and
one TLS handshake per host, to confirm what is really open (see "Safe probe").
"""

import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from ..utils.aws import make_client

WORLD = {"0.0.0.0/0", "::/0"}
READ_METHODS = {"GET", "HEAD", "$connect"}
NON_PROD_STAGES = {"dev", "development", "test", "testing", "qa", "staging", "stage", "sandbox", "demo", "beta", "old", "tmp", "temp"}
SENSITIVE_PORTS = (22, 3389, 3306, 5432, 1433, 1521, 27017, 6379, 9200, 5601, 11211, 2375)
MODERN_ELB_TLS = re.compile(r"TLS13-1-[23]|TLS-1-2|FS-1-2")
OLD_CLOUDFRONT_TLS = {"SSLv3", "TLSv1", "TLSv1_2016", "TLSv1.1_2016"}
ACCOUNT_DEFAULT_RATE = 10000  # requests/s API Gateway allows per region when no stage limit is set
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
NO_AUTH_CHECKS = {"route_no_auth", "url_no_auth"}

API2 = "API2:2023 Broken Authentication"
API4 = "API4:2023 Unrestricted Resource Consumption"
API8 = "API8:2023 Security Misconfiguration"
API9 = "API9:2023 Improper Inventory Management"


def crawl(session, settings, probe: bool = False) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    regions = _regions(session, settings, errors)
    # boto3 sessions are not thread-safe for client creation, so build every client here first.
    jobs = [
        (source, region, collect, [make_client(session, s, settings, region=region) for s in services])
        for region in regions
        for source, (services, collect) in REGIONAL_SOURCES.items()
    ]
    jobs.append(("CloudFront", "global", _cloudfront, [make_client(session, "cloudfront", settings, region="us-east-1")]))

    def run(job):
        source, region, collect, clients = job
        try:
            return collect(region, *clients)
        except Exception as exc:  # noqa: BLE001 - one unreadable source must not hide the others
            errors.append({"source": source, "region": region, "error": _error_text(exc)})
            return []

    def probe_one(api):
        try:
            _probe(api)
        except Exception as exc:  # noqa: BLE001 - a probe bug must not lose the inventory
            errors.append({"source": f"Probe of {api['name']}", "region": api["region"], "error": _error_text(exc)})

    with ThreadPoolExecutor(max_workers=16) as pool:
        apis = [api for found in pool.map(run, jobs) for api in found]
        if probe:
            list(pool.map(probe_one, [api for api in apis if api["public"]]))

    apis.sort(key=lambda api: (not api["public"], api["source"], api["region"], api["name"]))
    findings = sorted(
        (
            {"id": f"{api['id']}:{f['check']}:{f['target']}", "source": api["source"], "region": api["region"], "api": api["name"], **f}
            for api in apis
            for f in api.pop("findings")
        ),
        key=lambda f: (SEVERITY_ORDER[f["severity"]], f["api"], f["target"]),
    )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "regions": regions,
        "summary": {
            "total": len(apis),
            "public": sum(api["public"] for api in apis),
            "unauthenticated": len({(f["source"], f["region"], f["api"]) for f in findings if f["check"] in NO_AUTH_CHECKS}),
            "regions": len(regions),
            "errors": len(errors),
            "findings": {level: sum(f["severity"] == level for f in findings) for level in SEVERITY_ORDER},
            "probed_requests": sum(len(api.get("probe", [])) for api in apis),
        },
        "apis": apis,
        "findings": findings,
        "errors": sorted(errors, key=lambda e: (e["source"], e["region"])),
    }


def _regions(session, settings, errors) -> list[str]:
    if settings.aws_endpoint_url:  # LocalStack: one emulated region
        return [settings.aws_region]
    try:
        found = make_client(session, "ec2", settings, region=settings.aws_region).describe_regions()["Regions"]
        return sorted(region["RegionName"] for region in found)
    except Exception as exc:  # noqa: BLE001
        errors.append({"source": "EC2 regions", "region": settings.aws_region, "error": _error_text(exc)})
        return [settings.aws_region]


def _api(source, region, api_id, name, urls, auth, routes, public, findings, **details) -> dict[str, Any]:
    return {
        "source": source,
        "region": region,
        "id": api_id,
        "name": name,
        "urls": urls,
        "public": bool(public),
        "auth": auth,  # None = left to the application behind it
        "routes": routes,  # [{"route": "GET /orders", "auth": "NONE"}]
        "details": details,
        "findings": findings if public else [],  # settings only matter on what the internet can reach
    }


def _finding(check, severity, owasp, target, evidence, fix, command="") -> dict[str, str]:
    return {"check": check, "severity": severity, "owasp": owasp, "target": target, "evidence": evidence, "fix": fix, "command": command}


def _summary_auth(routes) -> str | None:
    kinds = {route["auth"] for route in routes}
    return kinds.pop() if len(kinds) == 1 else ("MIXED" if kinds else None)


def _open_route(route_key, command):
    severity = "high" if route_key.split(" ", 1)[0] in READ_METHODS else "critical"
    return _finding(
        "route_no_auth", severity, API2, route_key,
        "Anyone on the internet can call this route without credentials."
        + ("" if severity == "high" else " It can change data or catches every path."),
        "Attach an authorizer (Cognito/JWT, Lambda or IAM), or delete the route if it should not be public.",
        command,
    )


def _cors_any(target, command):
    return _finding(
        "cors_any_origin", "medium", API8, target,
        "CORS allows any origin, so any website can call this API from a visitor's browser.",
        "List only the origins that need access.", command,
    )


def _stage_findings(name, throttled, logged, waf, commands):
    """Shared stage checks; waf=None means the API type cannot use AWS WAF."""
    target = f"stage {name}"
    found = []
    if not throttled:
        found.append(_finding(
            "no_throttling", "medium", API4, target,
            f"No stage or usage-plan rate limit; only the account-wide {ACCOUNT_DEFAULT_RATE} requests/s applies, "
            "so one caller can run up cost or starve everyone else.",
            "Set a stage rate and burst limit (or a usage plan with throttling).", commands["throttle"],
        ))
    if not logged:
        found.append(_finding(
            "no_access_logs", "medium", API8, target,
            "Access logging is off, so there is no record of who called the API or what they got back.",
            "Send access logs to a CloudWatch Logs group.", commands["logs"],
        ))
    if waf is False:
        found.append(_finding(
            "no_waf", "medium", API8, target,
            "No AWS WAF web ACL filters requests before they reach the API.",
            "Associate a WAF web ACL that uses the AWS managed rule groups.", commands["waf"],
        ))
    if name.lower() in NON_PROD_STAGES:
        found.append(_finding(
            "non_prod_stage", "low", API9, target,
            f"Non-production stage '{name}' is reachable from the internet.",
            "Delete the stage, or move test traffic to a private API.", commands["delete"],
        ))
    return found


def _rest_apis(region, client):
    cli = f"aws apigateway --region {region}"
    usage_plan_throttled = {
        (stage["apiId"], stage["stage"])
        for page in client.get_paginator("get_usage_plans").paginate()
        for plan in page["items"]
        if plan.get("throttle")
        for stage in plan.get("apiStages", [])
    }
    apis = []
    for page in client.get_paginator("get_rest_apis").paginate():
        for item in page["items"]:
            api_id = item["id"]
            private = "PRIVATE" in item.get("endpointConfiguration", {}).get("types", [])
            stages = client.get_stages(restApiId=api_id)["item"]
            names = [stage["stageName"] for stage in stages]
            base = f"https://{api_id}.execute-api.{region}.amazonaws.com"
            urls = [] if item.get("disableExecuteApiEndpoint") else [f"{base}/{name}" for name in names]
            routes, findings = [], []
            for resources in client.get_paginator("get_resources").paginate(restApiId=api_id, embed=["methods"]):
                for resource in resources["items"]:
                    for verb, method in resource.get("resourceMethods", {}).items():
                        auth, keyed = method.get("authorizationType", "NONE"), method.get("apiKeyRequired", False)
                        key = f"{verb} {resource['path']}"
                        routes.append({"route": key, "auth": auth + ("+API_KEY" if keyed else "")})
                        if auth != "NONE" or verb == "OPTIONS":  # OPTIONS is the CORS preflight
                            continue
                        fix = (
                            f"{cli} update-method --rest-api-id {api_id} --resource-id {resource['id']} --http-method {verb} "
                            f"--patch-operations op=replace,path=/authorizationType,value=AWS_IAM "
                            f"&& {cli} create-deployment --rest-api-id {api_id} --stage-name {names[0] if names else '<stage>'}"
                        )
                        if keyed:
                            findings.append(_finding(
                                "api_key_only", "medium", API2, key,
                                "Only an API key protects this route. API keys identify callers for usage plans; "
                                "AWS advises against using them for authorization.",
                                "Add an authorizer (Cognito, Lambda or IAM) and keep the key for metering.", fix,
                            ))
                        else:
                            findings.append(_open_route(key, fix))
            for stage in stages:
                name = stage["stageName"]
                rate = stage.get("methodSettings", {}).get("*/*", {}).get("throttlingRateLimit")
                stage_cli = f"{cli} update-stage --rest-api-id {api_id} --stage-name {name} --patch-operations"
                findings += _stage_findings(
                    name,
                    throttled=(rate is not None and rate < ACCOUNT_DEFAULT_RATE) or (api_id, name) in usage_plan_throttled,
                    logged=bool(stage.get("accessLogSettings", {}).get("destinationArn")),
                    waf=bool(stage.get("webAclArn")),
                    commands={
                        "throttle": f"{stage_cli} op=replace,path=/*/*/throttling/rateLimit,value=100 op=replace,path=/*/*/throttling/burstLimit,value=200",
                        "logs": f"{stage_cli} op=replace,path=/accessLogSettings/destinationArn,value=<log-group-arn>",
                        "waf": f"aws wafv2 associate-web-acl --region {region} --web-acl-arn <web-acl-arn> "
                               f"--resource-arn arn:aws:apigateway:{region}::/restapis/{api_id}/stages/{name}",
                        "delete": f"{cli} delete-stage --rest-api-id {api_id} --stage-name {name}",
                    },
                )
            apis.append(_api(
                "API Gateway REST", region, api_id, item["name"], urls, _summary_auth(routes), routes,
                public=urls and not private, findings=findings, stages=names, endpoint_type="PRIVATE" if private else "PUBLIC",
            ))
    return apis


def _http_apis(region, client):
    cli = f"aws apigatewayv2 --region {region}"
    apis = []
    for page in client.get_paginator("get_apis").paginate():
        for item in page["Items"]:
            api_id, endpoint, protocol = item["ApiId"], item["ApiEndpoint"], item["ProtocolType"]
            stages = [s for p in client.get_paginator("get_stages").paginate(ApiId=api_id) for s in p["Items"]]
            names = [stage["StageName"] for stage in stages]
            urls = [] if item.get("DisableExecuteApiEndpoint") else [
                endpoint if name == "$default" else f"{endpoint}/{name}" for name in names
            ]
            routes, findings = [], []
            for p in client.get_paginator("get_routes").paginate(ApiId=api_id):
                for route in p["Items"]:
                    key, auth = route["RouteKey"], route.get("AuthorizationType", "NONE")
                    routes.append({"route": key, "auth": auth + ("+API_KEY" if route.get("ApiKeyRequired") else "")})
                    # WebSocket APIs authorize once, on $connect; HTTP OPTIONS is the CORS preflight.
                    skip = key.startswith("OPTIONS ") or (protocol == "WEBSOCKET" and key != "$connect")
                    if auth == "NONE" and not skip:
                        findings.append(_open_route(
                            key, f"{cli} update-route --api-id {api_id} --route-id {route['RouteId']} --authorization-type AWS_IAM",
                        ))
            if "*" in item.get("CorsConfiguration", {}).get("AllowOrigins", []):
                findings.append(_cors_any(
                    "CORS", f"{cli} update-api --api-id {api_id} --cors-configuration AllowOrigins=https://app.example.com",
                ))
            for stage in stages:
                name = stage["StageName"]
                rate = (stage.get("DefaultRouteSettings") or {}).get("ThrottlingRateLimit")
                stage_cli = f"{cli} update-stage --api-id {api_id} --stage-name '{name}'"
                findings += _stage_findings(
                    name,
                    throttled=rate is not None and rate < ACCOUNT_DEFAULT_RATE,
                    logged=bool((stage.get("AccessLogSettings") or {}).get("DestinationArn")),
                    waf=None,  # HTTP and WebSocket APIs cannot use AWS WAF directly
                    commands={
                        "throttle": f"{stage_cli} --default-route-settings ThrottlingRateLimit=100,ThrottlingBurstLimit=200",
                        "logs": f"{stage_cli} --access-log-settings "
                                "DestinationArn=<log-group-arn>,Format='$context.requestId $context.identity.sourceIp $context.routeKey $context.status'",
                        "delete": f"{cli} delete-stage --api-id {api_id} --stage-name '{name}'",
                    },
                )
            apis.append(_api(
                f"API Gateway {protocol.title()}", region, api_id, item["Name"], urls,
                _summary_auth(routes), routes, public=urls, findings=findings, stages=names,
            ))
    return apis


def _lambda_urls(region, client):
    cli = f"aws lambda --region {region}"
    apis = []
    for page in client.get_paginator("list_functions").paginate():
        for function in page["Functions"]:
            name = function["FunctionName"]
            for config in client.list_function_url_configs(FunctionName=function["FunctionArn"])["FunctionUrlConfigs"]:
                findings = []
                if config["AuthType"] == "NONE":
                    findings.append(_finding(
                        "url_no_auth", "critical", API2, "function URL",
                        "Anyone on the internet can invoke this function without credentials.",
                        "Switch the URL to AWS_IAM auth (or put API Gateway / CloudFront in front), "
                        "then remove the public statements from the function's resource policy.",
                        f"{cli} update-function-url-config --function-name {name} --auth-type AWS_IAM",
                    ))
                    if "ReservedConcurrentExecutions" not in client.get_function_concurrency(FunctionName=name):
                        findings.append(_finding(
                            "no_throttling", "medium", API4, "function URL",
                            "No concurrency cap: a flood of requests scales the function, and the bill, up to the account limit.",
                            "Reserve a small concurrency limit for the function.",
                            f"{cli} put-function-concurrency --function-name {name} --reserved-concurrent-executions 10",
                        ))
                if "*" in config.get("Cors", {}).get("AllowOrigins", []):
                    findings.append(_cors_any(
                        "CORS", f"{cli} update-function-url-config --function-name {name} --cors AllowOrigins=https://app.example.com",
                    ))
                apis.append(_api(
                    "Lambda function URL", region, name, name, [config["FunctionUrl"]], config["AuthType"], [],
                    public=True, findings=findings,
                ))
    return apis


def _appsync(region, client):
    cli = f"aws appsync --region {region}"
    apis = []
    for page in client.get_paginator("list_graphql_apis").paginate():
        for item in page["graphqlApis"]:
            api_id, name = item["apiId"], item["name"]
            modes = [item["authenticationType"]] + [
                extra["authenticationType"] for extra in item.get("additionalAuthenticationProviders", [])
            ]
            findings = []
            if item["authenticationType"] == "API_KEY":
                findings.append(_finding(
                    "api_key_only", "high", API2, "GraphQL endpoint",
                    "The default authorization is an API key, a shared secret that ends up in client code.",
                    "Use Cognito user pools, OIDC or IAM as the default; keep API keys for public read-only data.",
                    f"{cli} update-graphql-api --api-id {api_id} --name {name} --authentication-type AWS_IAM",
                ))
            if not item.get("wafWebAclArn"):
                findings.append(_finding(
                    "no_waf", "medium", API8, "GraphQL endpoint",
                    "No AWS WAF web ACL filters requests before they reach the API.",
                    "Associate a WAF web ACL that uses the AWS managed rule groups.",
                    f"aws wafv2 associate-web-acl --region {region} --web-acl-arn <web-acl-arn> --resource-arn {item['arn']}",
                ))
            if not item.get("logConfig"):
                findings.append(_finding(
                    "no_access_logs", "medium", API8, "GraphQL endpoint",
                    "Logging is off, so there is no record of who called the API.",
                    "Turn on CloudWatch logging for the API.",
                    f"{cli} update-graphql-api --api-id {api_id} --name {name} "
                    "--log-config fieldLogLevel=ERROR,cloudWatchLogsRoleArn=<role-arn>",
                ))
            apis.append(_api(
                "AppSync GraphQL", region, api_id, name, [item["uris"]["GRAPHQL"]], "+".join(modes), [],
                public=item.get("visibility", "GLOBAL") == "GLOBAL", findings=findings,
            ))
    return apis


def _cloudfront(region, client):
    console = "CloudFront console > distribution {id} > {where}"
    apis = []
    for page in client.get_paginator("list_distributions").paginate():
        for item in page["DistributionList"].get("Items", []):
            dist_id = item["Id"]
            hosts = [item["DomainName"], *item.get("Aliases", {}).get("Items", [])]
            routes = [
                {"route": f"ANY {behavior['PathPattern']}", "auth": None}
                for behavior in item.get("CacheBehaviors", {}).get("Items", [])
            ]
            findings = []
            if not item.get("WebACLId"):
                findings.append(_finding(
                    "no_waf", "medium", API8, "distribution",
                    "No AWS WAF web ACL filters requests at the edge.",
                    "Attach a WAF web ACL (scope CLOUDFRONT, created in us-east-1).",
                    console.format(id=dist_id, where="Security > Edit"),
                ))
            if item["DefaultCacheBehavior"]["ViewerProtocolPolicy"] == "allow-all":
                findings.append(_finding(
                    "plain_http", "medium", API8, "default behavior",
                    "Viewers can use plain HTTP, so traffic can be read or changed in transit.",
                    "Set the viewer protocol policy to redirect-to-https.",
                    console.format(id=dist_id, where="Behaviors > Default > Viewer protocol policy"),
                ))
            cert = item.get("ViewerCertificate", {})
            if not cert.get("CloudFrontDefaultCertificate") and cert.get("MinimumProtocolVersion") in OLD_CLOUDFRONT_TLS:
                findings.append(_finding(
                    "old_tls", "medium", API8, "viewer certificate",
                    f"Minimum protocol {cert['MinimumProtocolVersion']} allows TLS older than 1.2.",
                    "Set the security policy to TLSv1.2_2021 or newer.",
                    console.format(id=dist_id, where="General > Settings > Security policy"),
                ))
            apis.append(_api(
                "CloudFront", region, dist_id, hosts[-1], [f"https://{host}" for host in hosts], None, routes,
                public=item["Enabled"], findings=findings, origins=[origin["DomainName"] for origin in item["Origins"]["Items"]],
            ))
    return apis


def _load_balancers(region, client, waf):
    cli = f"aws elbv2 --region {region}"
    apis = []
    for page in client.get_paginator("describe_load_balancers").paginate():
        for lb in page["LoadBalancers"]:
            lb_arn = lb["LoadBalancerArn"]
            listeners = [
                listener
                for p in client.get_paginator("describe_listeners").paginate(LoadBalancerArn=lb_arn)
                for listener in p["Listeners"]
            ]
            routes, findings = [], []
            for listener in listeners:
                arn, protocol, target = listener["ListenerArn"], listener["Protocol"], f"listener {listener['Protocol']}:{listener['Port']}"
                if protocol == "HTTP" and not any(a["Type"] == "redirect" for a in listener.get("DefaultActions", [])):
                    findings.append(_finding(
                        "plain_http", "medium", API8, target,
                        "The listener serves plain HTTP instead of redirecting to HTTPS.",
                        "Make the HTTP listener redirect to HTTPS.",
                        f"{cli} modify-listener --listener-arn {arn} "
                        "--default-actions 'Type=redirect,RedirectConfig={Protocol=HTTPS,Port=443,StatusCode=HTTP_301}'",
                    ))
                policy = listener.get("SslPolicy")
                if policy and not MODERN_ELB_TLS.search(policy):
                    findings.append(_finding(
                        "old_tls", "medium", API8, target,
                        f"Security policy {policy} allows TLS older than 1.2.",
                        "Use a TLS 1.2+ policy.",
                        f"{cli} modify-listener --listener-arn {arn} --ssl-policy ELBSecurityPolicy-TLS13-1-2-2021-06",
                    ))
                if lb["Type"] == "application":
                    for p in client.get_paginator("describe_rules").paginate(ListenerArn=arn):
                        for rule in p["Rules"]:
                            gated = any(a["Type"].startswith("authenticate") for a in rule.get("Actions", []))
                            for condition in rule.get("Conditions", []):
                                if condition["Field"] == "path-pattern":
                                    for path in condition.get("PathPatternConfig", {}).get("Values") or condition.get("Values", []):
                                        routes.append({"route": f"ANY {path}", "auth": "ALB_AUTH" if gated else None})
            public = lb["Scheme"] == "internet-facing" and listeners
            if public:
                attributes = client.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)["Attributes"]
                if {a["Key"]: a["Value"] for a in attributes}.get("access_logs.s3.enabled") != "true":
                    findings.append(_finding(
                        "no_access_logs", "medium", API8, "load balancer",
                        "Access logging is off, so there is no record of who called the API.",
                        "Turn on access logs to an S3 bucket.",
                        f"{cli} modify-load-balancer-attributes --load-balancer-arn {lb_arn} "
                        "--attributes Key=access_logs.s3.enabled,Value=true Key=access_logs.s3.bucket,Value=<bucket>",
                    ))
                if lb["Type"] == "application" and not waf.get_web_acl_for_resource(ResourceArn=lb_arn).get("WebACL"):
                    findings.append(_finding(
                        "no_waf", "medium", API8, "load balancer",
                        "No AWS WAF web ACL filters requests before they reach the targets.",
                        "Associate a WAF web ACL that uses the AWS managed rule groups.",
                        f"aws wafv2 associate-web-acl --region {region} --web-acl-arn <web-acl-arn> --resource-arn {lb_arn}",
                    ))
            apis.append(_api(
                f"Load balancer ({lb['Type']})", region, lb["LoadBalancerName"], lb["LoadBalancerName"],
                [f"{listener['Protocol'].lower()}://{lb['DNSName']}:{listener['Port']}" for listener in listeners],
                None, routes, public=public, findings=findings,
            ))
    return apis


def _ec2(region, client):
    instances = [
        instance
        for page in client.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        )
        for reservation in page["Reservations"]
        for instance in reservation["Instances"]
        if instance.get("PublicIpAddress")
    ]
    if not instances:
        return []
    group_ids = sorted({g["GroupId"] for i in instances for g in i.get("SecurityGroups", [])})
    open_rules = {
        group["GroupId"]: _world_rules(group)
        for page in client.get_paginator("describe_security_groups").paginate(GroupIds=group_ids)
        for group in page["SecurityGroups"]
    }
    apis = []
    for instance in instances:
        ip = instance["PublicIpAddress"]
        name = next((t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"), instance["InstanceId"])
        ports, findings = set(), []
        for group in instance.get("SecurityGroups", []):
            gid = group["GroupId"]
            for label, low, high, protocol in open_rules.get(gid, []):
                ports.add(label)
                sensitive = [port for port in SENSITIVE_PORTS if low <= port <= high]
                severity = "critical" if label == "all" else "high" if sensitive else "medium"
                findings.append(_finding(
                    "open_port", severity, API8, f"{gid} port {label}",
                    f"Security group {gid} opens {'every port' if label == 'all' else f'port {label}'} to the whole internet"
                    + (f", including admin/database port {sensitive[0]}." if sensitive and label != "all" else "."),
                    "Close admin and database ports to the internet (use SSM Session Manager or a VPN); "
                    "serve the API through a load balancer or API Gateway with WAF and let only that reach the instance."
                    if severity != "medium" else
                    "Serve the API through a load balancer or API Gateway with WAF and let only that reach the instance.",
                    f"aws ec2 revoke-security-group-ingress --region {region} --group-id {gid} "
                    + ("--protocol all" if label == "all" else f"--protocol {protocol} --port {label}") + " --cidr 0.0.0.0/0",
                ))
        apis.append(_api(
            "EC2 instance", region, instance["InstanceId"], name,
            [f"http://{ip}:{port}" for port in sorted(ports) if port.isdigit() and int(port) not in SENSITIVE_PORTS],
            None, [],
            public=ports, findings=findings, open_ports=sorted(ports), public_ip=ip,
        ))
    return apis


def _world_rules(group) -> list[tuple[str, int, int, str]]:
    """(label, low port, high port, protocol) for each rule open to the whole internet."""
    rules = []
    for perm in group.get("IpPermissions", []):
        cidrs = {r.get("CidrIp") for r in perm.get("IpRanges", [])} | {r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", [])}
        if not cidrs & WORLD:
            continue
        low, high, protocol = perm.get("FromPort"), perm.get("ToPort"), perm.get("IpProtocol")
        if protocol == "-1" or low in (None, -1) or (low, high) == (0, 65535):
            rules.append(("all", 0, 65535, "all"))
        else:
            rules.append((str(low) if low == high else f"{low}-{high}", low, high, protocol))
    return rules


# ---------------------------------------------------------------- Safe probe
# GET only, no credentials, at most PROBE_LIMIT requests per API, bodies capped.
# Write routes are never called; their findings stay configuration-based.

PROBE_LIMIT = 10
PROBE_TIMEOUT = 5
PROBE_BODY_CAP = 64 * 1024
PROBE_ORIGIN = "https://centralwatch-probe.invalid"
PROBE_METHODS = {"GET", "ANY", "$default"}
SECURITY_HEADERS = ("Strict-Transport-Security", "X-Content-Type-Options", "Cache-Control")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # report the 3xx itself instead of following it


_opener = urllib.request.build_opener(_NoRedirect)


def _get(url) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"Origin": PROBE_ORIGIN, "User-Agent": "CentralWatch-API-probe/1.0"})
    try:
        with _opener.open(request, timeout=PROBE_TIMEOUT) as response:
            return {"status": response.status, "headers": dict(response.headers), "bytes": len(response.read(PROBE_BODY_CAP))}
    except urllib.error.HTTPError as error:  # 3xx/4xx/5xx still tell us something
        return {"status": error.code, "headers": dict(error.headers or {}), "bytes": len(error.read(PROBE_BODY_CAP))}
    except Exception as exc:  # noqa: BLE001 - unreachable, TLS failure, timeout
        return {"status": None, "headers": {}, "bytes": 0, "error": f"{type(exc).__name__}: {exc}"[:200]}


def _old_tls(host, port) -> str | None:
    """The TLS 1.0/1.1 version the host still accepts, or None if it refuses both."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname, context.verify_mode = False, ssl.CERT_NONE  # only the protocol version matters here
    context.minimum_version, context.maximum_version = ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1
    context.set_ciphers("DEFAULT:@SECLEVEL=0")  # let this client offer the old versions at all
    try:
        with context.wrap_socket(socket.create_connection((host, port), timeout=PROBE_TIMEOUT), server_hostname=host) as tls:
            return tls.version()
    except (OSError, ssl.SSLError):
        return None


def _probe_targets(api) -> list[tuple[str, str | None]]:
    """(url, route key) pairs to GET. Path parameters get the sample value 1."""
    if api["source"].startswith("API Gateway"):
        keys = [r["route"] for r in api["routes"] if r["route"].split(" ", 1)[0] in PROBE_METHODS]
        pairs = [
            (url.rstrip("/") + re.sub(r"\{[^}]+\}", "1", key.split(" ", 1)[1] if " " in key else "/"), key)
            for url in api["urls"] if url.startswith("http")  # skip wss:// WebSocket endpoints
            for key in keys
        ]
    elif api["source"] == "AppSync GraphQL":
        pairs = []  # every AppSync auth mode needs a credential, so an anonymous GET proves nothing
    else:
        pairs = [(url, None) for url in api["urls"]]
    return pairs[:PROBE_LIMIT]


def _probe(api) -> None:
    """Probe one public API in place: record responses, confirm or annotate findings, add new ones."""
    results = [{"url": url, "route": key, **_get(url)} for url, key in _probe_targets(api)]
    if api["source"] == "CloudFront":
        results += [{"url": f"https://{origin}/", "route": "origin", **_get(f"https://{origin}/")} for origin in api["details"]["origins"]]
    findings, region = api["findings"], api["region"]
    checks = {f["check"] for f in findings}
    answered = [r for r in results if r["status"] is not None and r["route"] != "origin"]

    for finding in findings:  # confirm the "no authentication" findings with real responses
        if finding["check"] not in NO_AUTH_CHECKS:
            continue
        mine = [r for r in answered if finding["check"] == "url_no_auth" or r["route"] == finding["target"]]
        opened = next((r for r in mine if 200 <= r["status"] < 300), None)
        if opened:
            finding.update(confirmed=True, severity="critical")
            finding["evidence"] += f" Confirmed: GET {opened['url']} returned {opened['status']} with {opened['bytes']} bytes and no credentials."
        elif mine:
            finding["confirmed"] = False
            finding["evidence"] += f" The probe got {mine[0]['status']}, so the backend may check credentials itself; verify manually."

    ok = next((r for r in answered if 200 <= r["status"] < 300), None)
    if ok:
        headers = {k.lower(): v for k, v in ok["headers"].items()}
        missing = [h for h in SECURITY_HEADERS if h.lower() not in headers and (h != "Strict-Transport-Security" or ok["url"].startswith("https"))]
        if missing:
            findings.append(_finding(
                "missing_security_headers", "low", API8, "responses",
                f"GET {ok['url']} answered without {', '.join(missing)}.",
                "Return Strict-Transport-Security, X-Content-Type-Options: nosniff and Cache-Control: no-store on API responses "
                "(in the backend, or with a CloudFront response headers policy).",
            ))
        allowed = headers.get("access-control-allow-origin")
        if "cors_any_origin" not in checks and allowed in ("*", PROBE_ORIGIN):
            with_credentials = allowed == PROBE_ORIGIN and headers.get("access-control-allow-credentials", "").lower() == "true"
            findings.append(_finding(
                "cors_any_origin", "high" if with_credentials else "medium", API8, "CORS",
                f"A request from {PROBE_ORIGIN} got Access-Control-Allow-Origin: {allowed}"
                + (" with credentials allowed, so any website can read responses as the signed-in user." if with_credentials else "."),
                "Allow only the origins that need access, and never reflect the request's Origin header.",
            ))

    if api["source"] == "EC2 instance" and any(r["url"].startswith("http://") for r in answered):
        findings.append(_finding(
            "plain_http", "medium", API8, "instance",
            "The instance answers plain HTTP, so traffic can be read or changed in transit.",
            "Terminate TLS in front of it (load balancer, API Gateway or CloudFront) and stop exposing the HTTP port.",
        ))

    if "old_tls" not in checks:
        hosts = {(p.hostname, p.port or 443) for p in map(urllib.parse.urlsplit, api["urls"]) if p.scheme == "https"}
        for host, port in sorted(hosts):
            version = _old_tls(host, port)
            if not version:
                continue
            rest = api["source"] == "API Gateway REST"
            findings.append(_finding(
                "old_tls", "medium", API8, host,
                f"Offered only TLS 1.0 and 1.1, the endpoint accepted ({version}). Both versions are deprecated and have known weaknesses.",
                "Serve the API from a custom domain with the TLS_1_2 security policy, then turn off the default execute-api endpoint."
                if rest else "Turn off TLS 1.0 and 1.1 in the server's TLS settings.",
                f"aws apigateway --region {region} create-domain-name --domain-name api.example.com --regional-certificate-arn <acm-cert-arn> "
                f"--endpoint-configuration types=REGIONAL --security-policy TLS_1_2 && aws apigateway --region {region} update-rest-api "
                f"--rest-api-id {api['id']} --patch-operations op=replace,path=/disableExecuteApiEndpoint,value=true" if rest else "",
            ))
            break

    for origin in (r for r in results if r["route"] == "origin" and r["status"] and r["status"] < 400):
        findings.append(_finding(
            "origin_reachable", "medium", API8, origin["url"],
            f"The origin answered {origin['status']} directly, so callers can skip CloudFront and any WAF on it.",
            "Lock the origin to CloudFront: Origin Access Control for S3 and Lambda URLs, or the CloudFront managed prefix list "
            "plus a secret header for load balancers.",
        ))

    for result in results:
        result.pop("headers")
    api["probe"] = results


def _error_text(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        error = exc.response.get("Error", {})
        return f"{error.get('Code', 'ClientError')}: {error.get('Message', '')}"
    return f"{type(exc).__name__}: {exc}"


REGIONAL_SOURCES = {  # source label -> (boto3 services passed to the collector, collector)
    "API Gateway REST": (("apigateway",), _rest_apis),
    "API Gateway HTTP/WebSocket": (("apigatewayv2",), _http_apis),
    "Lambda function URL": (("lambda",), _lambda_urls),
    "AppSync GraphQL": (("appsync",), _appsync),
    "Load balancer": (("elbv2", "wafv2"), _load_balancers),
    "EC2 instance": (("ec2",), _ec2),
}
