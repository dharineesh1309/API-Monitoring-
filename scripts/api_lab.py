"""Deliberately weak APIs for testing the CentralWatch API scanner. Creates only `cw-lab-*` resources.

    docker exec -i centralwatch-demo-app python - up   < scripts/api_lab.py
    docker exec -i centralwatch-demo-app python - down < scripts/api_lab.py

`up` replaces any previous lab. Uses the container's AWS credentials, AWS_REGION and
LAMBDA_ROLE_ARN (any role Lambda can assume). Costs nothing at lab traffic levels,
but the endpoints are public with no authentication; run `down` when finished.

Creates:
  * Lambda `cw-lab-orders` with a function URL that has auth NONE   (critical)
  * HTTP API `cw-lab-orders-api`: GET/POST /orders open, GET /admin/users IAM-only
  * REST API `cw-lab-legacy-api`: stage `dev`, GET /users open (mock data, no Lambda)
"""

import io
import json
import os
import sys
import zipfile

import boto3

PREFIX = "cw-lab-"
FUNCTION = "cw-lab-orders"
HANDLER = '''
import json
def handler(event, context):
    body = {"lab": "centralwatch", "path": event.get("rawPath", "/"),
            "orders": [{"order_id": "ord_lab_1", "customer_email": "lab-user@example.com", "total": 42.0}]}
    return {"statusCode": 200, "headers": {"content-type": "application/json"}, "body": json.dumps(body)}
'''

region = os.environ["AWS_REGION"]
session = boto3.session.Session(region_name=region)
lam, apigw, apigw2 = session.client("lambda"), session.client("apigateway"), session.client("apigatewayv2")
account = session.client("sts").get_caller_identity()["Account"]


def down():
    try:
        lam.delete_function(FunctionName=FUNCTION)
        print("deleted Lambda", FUNCTION)
    except lam.exceptions.ResourceNotFoundException:
        pass
    for api in apigw2.get_apis()["Items"]:
        if api["Name"].startswith(PREFIX):
            apigw2.delete_api(ApiId=api["ApiId"])
            print("deleted HTTP API", api["Name"])
    for api in apigw.get_rest_apis()["items"]:
        if api["name"].startswith(PREFIX):
            apigw.delete_rest_api(restApiId=api["id"])
            print("deleted REST API", api["name"])


def add_url_invoke_permission():
    """Newer accounts also need lambda:InvokeFunction, limited to calls arriving via the URL."""
    if "InvokedViaFunctionUrl" not in lam.meta.service_model.operation_model("AddPermission").input_shape.members:
        print("WARNING: this boto3 is too old to add InvokedViaFunctionUrl; the Lambda URL may answer 403.")
        print("         Fix: pip install --target /tmp/boto-new boto3, rerun with PYTHONPATH=/tmp/boto-new")
        return
    lam.add_permission(
        FunctionName=FUNCTION, StatementId="public-url-invoke", Action="lambda:InvokeFunction",
        Principal="*", InvokedViaFunctionUrl=True,
    )


def up():
    down()
    code = io.BytesIO()
    with zipfile.ZipFile(code, "w") as archive:
        archive.writestr("lambda_function.py", HANDLER)
    arn = lam.create_function(
        FunctionName=FUNCTION, Runtime="python3.12", Handler="lambda_function.handler",
        Role=os.environ["LAMBDA_ROLE_ARN"], Code={"ZipFile": code.getvalue()}, Timeout=5,
        Description="CentralWatch API scanner lab target. Safe to delete.",
    )["FunctionArn"]
    lam.get_waiter("function_active_v2").wait(FunctionName=FUNCTION)

    url = lam.create_function_url_config(FunctionName=FUNCTION, AuthType="NONE")["FunctionUrl"]
    lam.add_permission(
        FunctionName=FUNCTION, StatementId="public-url", Action="lambda:InvokeFunctionUrl",
        Principal="*", FunctionUrlAuthType="NONE",
    )
    add_url_invoke_permission()
    print("Lambda URL (auth NONE):", url)

    api = apigw2.create_api(Name=f"{PREFIX}orders-api", ProtocolType="HTTP")
    integration = apigw2.create_integration(
        ApiId=api["ApiId"], IntegrationType="AWS_PROXY", IntegrationUri=arn, PayloadFormatVersion="2.0",
    )["IntegrationId"]
    for route, auth in [("GET /orders", "NONE"), ("POST /orders", "NONE"), ("GET /admin/users", "AWS_IAM")]:
        apigw2.create_route(ApiId=api["ApiId"], RouteKey=route, AuthorizationType=auth, Target=f"integrations/{integration}")
    apigw2.create_stage(ApiId=api["ApiId"], StageName="$default", AutoDeploy=True)
    lam.add_permission(
        FunctionName=FUNCTION, StatementId="http-api", Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com", SourceArn=f"arn:aws:execute-api:{region}:{account}:{api['ApiId']}/*",
    )
    print("HTTP API:", api["ApiEndpoint"])

    rest = apigw.create_rest_api(name=f"{PREFIX}legacy-api", endpointConfiguration={"types": ["REGIONAL"]})["id"]
    root = next(r["id"] for r in apigw.get_resources(restApiId=rest)["items"] if r["path"] == "/")
    users = apigw.create_resource(restApiId=rest, parentId=root, pathPart="users")["id"]
    apigw.put_method(restApiId=rest, resourceId=users, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=rest, resourceId=users, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=rest, resourceId=users, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=rest, resourceId=users, httpMethod="GET", statusCode="200",
        responseTemplates={"application/json": json.dumps({"users": [{"id": 1, "email": "lab-user@example.com"}]})},
    )
    apigw.create_deployment(restApiId=rest, stageName="dev")
    print(f"REST API: https://{rest}.execute-api.{region}.amazonaws.com/dev/users")


{"up": up, "down": down, "fix-url": add_url_invoke_permission}[sys.argv[1]]()
