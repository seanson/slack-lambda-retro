import boto3
import uuid
import json
import os

from botocore.exceptions import ClientError
from time import sleep

from dotenv import Dotenv

dotenv = Dotenv(os.path.join(os.path.dirname(__file__), '.env'))
os.environ.update(dotenv)

AWS_LAMBDA_API_NAME = os.environ.get('AWS_LAMBDA_API_NAME')
AWS_REGION = os.environ.get('AWS_REGION')
AWS_ACCT_ID = os.environ.get('AWS_ACCT_ID')

params = {
    'region_name': AWS_REGION,
}

session = boto3.Session(profile_name='lambda_deploy')
rds_client = session.client('sdb', **params)


def create_rest_api(name):
    api_client = session.client('apigateway', **params)
    response = api_client.get_rest_apis()

    api = next((item for item in response['items'] if item['name'] == name), None)

    if api:
        return api
    print('Base REST API not found, creating API')
    api = api_client.create_rest_api(
        name=name,
    )
    return api


def create_lambda_resource_method(target_api, pathPart, method, parent=u'/', key_required=False,
                                  requestParameters=None):
    if requestParameters is None:
        requestParameters = {}
    api_client = session.client('apigateway', **params)
    resources = api_client.get_resources(
        restApiId=target_api['id'],
    )
    parent_resource = next((item for item in resources['items'] if item['path'] == parent), None)
    resource_resp = next((item for item in resources['items'] if item.get('pathPart', '') == pathPart), None)

    if not resource_resp:
        print('Creating resource for pathPart: {}'.format(pathPart))
        resource_resp = api_client.create_resource(
            restApiId=target_api['id'],
            parentId=parent_resource['id'],
            pathPart=pathPart,

        )

    if method not in resource_resp.get('resourceMethods', {}):
        api_client.put_method(
            restApiId=target_api['id'],
            resourceId=resource_resp['id'],
            httpMethod=method,
            authorizationType="NONE",
            apiKeyRequired=key_required,
            requestParameters=requestParameters,
        )
    return resource_resp


def create_resource_integration(target_api, resource, func_name, http_method, http_code=u'200',
                                responseParameters=None, requestTemplates=None):
    if not responseParameters:
        responseParameters = {}
    if not requestTemplates:
        requestTemplates = {}

    api_client = session.client('apigateway', **params)
    aws_lambda = session.client('lambda', **params)
    uri_data = {
        'aws-region': AWS_REGION,
        'api-version': aws_lambda.meta.service_model.api_version,
        'aws-acct-id': AWS_ACCT_ID,
        'lambda-function-name': func_name,
        'aws-api-id': target_api['id'],
        'method': http_method,
        'pathPart': resource['pathPart'],
    }
    uri = ':'.join(['arn',
                    'aws',
                    'apigateway',
                    '{aws-region}',
                    'lambda',
                    'path/{api-version}/functions/arn',
                    'aws',
                    'lambda',
                    '{aws-region}',
                    '{aws-acct-id}',
                    'function',
                    '{lambda-function-name}/invocations']).format(**uri_data)

    source_arn = ':'.join(['arn',
                           'aws',
                           'execute-api',
                           '{aws-region}',
                           '{aws-acct-id}',
                           '{aws-api-id}/*/{method}/{pathPart}']).format(**uri_data)

    lambda_arn = ':'.join(['arn',
                           'aws',
                           'lambda',
                           '{aws-region}',
                           '{aws-acct-id}',
                           'function',
                           '{lambda-function-name}']).format(**uri_data)

    method = api_client.get_method(
        restApiId=target_api['id'],
        resourceId=resource['id'],
        httpMethod=http_method
    )

    integration = method.get('methodIntegration', {})
    if not integration.get(u'uri', None):
        print('Missing integration for uri, creating.')
        api_client.put_integration(
            restApiId=target_api['id'],
            resourceId=resource['id'],
            httpMethod=http_method,
            type="AWS",
            integrationHttpMethod='POST',
            uri=uri,
            requestTemplates=requestTemplates,
        )

    method_response = method.get('methodResponses', {})
    if not method_response.get(http_code, None):
        print('Missing method response, creating.')
        api_client.put_method_response(
            restApiId=target_api['id'],
            resourceId=resource['id'],
            httpMethod=http_method,
            statusCode=http_code,
            responseParameters={key: False for key in responseParameters.keys()},
        )

    integration_response = integration.get('integrationResponses', {})
    if not integration_response.get(http_code, None):
        print('Missing integration response, creating.')
        api_client.put_integration_response(
            restApiId=target_api['id'],
            resourceId=resource['id'],
            httpMethod=http_method,
            statusCode=http_code,
            responseParameters=responseParameters
        )

    print('Granting permissions to {lambda_arn} for {arn}'.format(lambda_arn=lambda_arn, arn=source_arn))
    aws_lambda.add_permission(
        FunctionName=lambda_arn,
        StatementId=uuid.uuid4().hex,
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=source_arn
    )


def create_model(target_api, name, schema):
    api_client = session.client('apigateway', **params)
    models = api_client.get_models(
        restApiId=target_api['id'],
    )
    model = next((item for item in models['items'] if item['name'] == name), None)
    if model:
        response = api_client.update_model(
            restApiId=target_api['id'],
            modelName=name,
            patchOperations=[
                {
                    'op': 'replace',
                    'path': '/schema',
                    'value': json.dumps(schema),
                },
            ],
        )
    else:
        api_client.create_model(
            restApiId=target_api['id'],
            name=name,
            contentType='application/json',
            schema=json.dumps(schema),
        )


def create_deployment(target_api, name):
    api_client = session.client('apigateway', **params)
    api_client.create_deployment(
        restApiId=target_api['id'],
        stageName=name,
    )
    stage = api_client.get_stage(
        restApiId=target_api['id'],
        stageName=name
    )
    return stage


def grant_dynamodb_permissions(table_name, username):
    iam_client = session.client('iam', **params)
    iam_resource = session.resource('iam')
    aws_lambda = session.client('lambda', **params)

    uri_data = {
        'aws-region': AWS_REGION,
        'api-version': aws_lambda.meta.service_model.api_version,
        'aws-acct-id': AWS_ACCT_ID,
        'table_name': table_name,
        'username': username,
    }

    dynamodb_arn = ':'.join(['arn',
                             'aws',
                             'dynamodb',
                             '{aws-region}',
                             '{aws-acct-id}',
                             'table/{table_name}']).format(**uri_data)
    policy_name = 'DB_{table_name}_{username}'.format(**uri_data)
    policy_document = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": uuid.uuid4().hex,
                "Effect": "Allow",
                "Action": [
                    "dynamodb:PutItem",
                    "dynamodb:GetItem",
                    "dynamodb:UpdateItem",
                    "dynamodb:Query",
                ],
                "Resource": [
                    dynamodb_arn,
                ]
            }
        ]
    })

    policy_arn = ':'.join(['arn',
                           'aws',
                           'iam',
                           '',
                           '{aws-acct-id}',
                           'policy/{}'.format(policy_name)]).format(**uri_data)

    try:
        iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=policy_document,
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'EntityAlreadyExists':
            print('Policy already exists: {}'.format(policy_name))

    role = iam_resource.Role(username)
    response = role.attach_policy(PolicyArn=policy_arn)


def grant_sns_permissions(topic_name, username):
    iam_client = session.client('iam', **params)
    iam_resource = session.resource('iam')
    aws_lambda = session.client('lambda', **params)

    uri_data = {
        'aws-region': AWS_REGION,
        'api-version': aws_lambda.meta.service_model.api_version,
        'aws-acct-id': AWS_ACCT_ID,
        'topic_name': topic_name,
        'username': username,
    }

    sns_arn = ':'.join(['arn',
                        'aws',
                        'sns',
                        '{aws-region}',
                        '{aws-acct-id}',
                        '{topic_name}']).format(**uri_data)
    policy_name = 'SNS_{topic_name}_{username}'.format(**uri_data)
    policy_document = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": uuid.uuid4().hex,
                "Effect": "Allow",
                "Action": [
                    "SNS:Publish",
                ],
                "Resource": [
                    sns_arn,
                ]
            }
        ]
    })

    policy_arn = ':'.join(['arn',
                           'aws',
                           'iam',
                           '',
                           '{aws-acct-id}',
                           'policy/{}'.format(policy_name)]).format(**uri_data)

    try:
        iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=policy_document,
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'EntityAlreadyExists':
            print('Policy already exists: {}'.format(policy_name))

    role = iam_resource.Role(username)
    response = role.attach_policy(PolicyArn=policy_arn)


def check_dynamodb_table_exists(table_name):
    client = session.client('dynamodb', **params)
    try:
        client.describe_table(
            TableName=table_name,
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            return False
    return True


def create_simple_dynamodb_table(table_name, table_index, second_index=None, second_type=None, ReadCapacityUnits=10,
                                 WriteCapacityUnits=10,
                                 force=False):
    client = session.client('dynamodb', **params)
    dynamodb = session.resource('dynamodb', **params)

    if check_dynamodb_table_exists(table_name):
        if not force:
            return
        client.delete_table(
            TableName=table_name,
        )

    while check_dynamodb_table_exists(table_name):
        print('.')
        sleep(1)

    if not second_type:
        second_type = 'S'

    key_schemas = [dict(AttributeName=table_index, KeyType='HASH')]
    attribute_definitions = [dict(AttributeName=table_index, AttributeType='S'), ]
    if second_index:
        key_schemas.append(dict(AttributeName=second_index, KeyType='RANGE'))
        attribute_definitions.append(dict(AttributeName=second_index, AttributeType=second_type), )
    table = dynamodb.create_table(
        TableName=table_name,
        KeySchema=key_schemas,
        AttributeDefinitions=attribute_definitions,
        ProvisionedThroughput={'ReadCapacityUnits': ReadCapacityUnits, 'WriteCapacityUnits': WriteCapacityUnits},
    )
    print('Created table, waiting for execution')
    while not check_dynamodb_table_exists(table_name):
        print('.')
        sleep(1)


def create_sns_integation(topic_name, func_name):
    client = session.client('sns', **params)
    sns = session.resource('sns', **params)
    aws_lambda = session.client('lambda', **params)

    new_topic = sns.create_topic(Name=topic_name)
    print new_topic._arn
    uri_data = {
        'aws-region': AWS_REGION,
        'api-version': aws_lambda.meta.service_model.api_version,
        'aws-acct-id': AWS_ACCT_ID,
        'lambda-function-name': func_name,
    }

    lambda_arn = ':'.join(['arn',
                           'aws',
                           'lambda',
                           '{aws-region}',
                           '{aws-acct-id}',
                           'function',
                           '{lambda-function-name}']).format(**uri_data)

    result = client.subscribe(
        TopicArn=new_topic._arn,
        Protocol='lambda',
        Endpoint=lambda_arn,
    )

    print('Granting permissions to {lambda_arn} for {arn}'.format(lambda_arn=lambda_arn, arn=new_topic._arn))

    aws_lambda.add_permission(
        FunctionName='slack-lambda-retro',
        StatementId=uuid.uuid4().hex,
        Action="lambda:InvokeFunction",
        Principal="sns.amazonaws.com",
        SourceArn=new_topic._arn,
    )


create_simple_dynamodb_table('retro_messages', 'team_id', second_index='timestamp', second_type='N')
create_simple_dynamodb_table('retro', 'team_id', second_index='channel_id')
create_simple_dynamodb_table('retro_auth', 'team_id')

grant_dynamodb_permissions('retro', 'slack-lambda-retro_dev')
grant_dynamodb_permissions('retro_messages', 'slack-lambda-retro_dev')
grant_dynamodb_permissions('retro_auth', 'slack-lambda-retro_dev')
grant_dynamodb_permissions('retro_auth', 'slack-lambda-oauth-redirect_dev')

target_api = create_rest_api(AWS_LAMBDA_API_NAME)

code_schema = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "title": "login",
    "type": "object",
    "properties": {
        "code": {"type": "string"},
    }
}

command_schema = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "title": "command",
    "type": "object",
    "properties": {
        "command": {"type": "string"},
    }
}

create_model(target_api, 'QueryStringCode', code_schema)
create_model(target_api, 'QueryStringCode', command_schema)

requestParams = {
    'method.request.querystring.code': False,
}

requestModels = {
    'application/json': 'QueryStringCode',
}

retro = create_lambda_resource_method(target_api, pathPart='slack-lambda-retro', method=u'POST')
oauth = create_lambda_resource_method(target_api, 'slack-lambda-oauth-redirect', method=u'GET',
                                      requestParameters=requestParams)

location = {
    'method.response.header.Location': 'integration.response.body.location'
}

login_request_templates = {
    'application/json': json.dumps({"code": "$input.params('code')"})
}

command_request_templates = {
    'application/x-www-form-urlencoded': json.dumps({"command": "$input.json('$')"})
}

create_resource_integration(target_api, retro, 'slack-lambda-retro', u'POST',
                            requestTemplates=command_request_templates)
create_resource_integration(target_api, oauth, 'slack-lambda-oauth-redirect', http_method=u'GET', http_code=u'302',
                            responseParameters=location, requestTemplates=login_request_templates)

print('Deploying target to DEV')
stage = create_deployment(target_api, 'DEV')

print('deployed the following urls')
print('https://{id}.execute-api.ap-southeast-2.amazonaws.com/{stage}/slack-lambda-retro'.format(id=target_api['id'],
                                                                                                stage=stage[
                                                                                                    'stageName']))
print(
    'https://{id}.execute-api.ap-southeast-2.amazonaws.com/{stage}/slack-lambda-oauth-redirect'.format(
        id=target_api['id'],
        stage=stage[
            'stageName']))

print('Building SNS topics')
create_sns_integation('retro_slack_event', 'slack-lambda-retro')
grant_sns_permissions('retro_slack_event', 'slack-lambda-retro_dev')
