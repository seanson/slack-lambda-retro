from __future__ import print_function
from urllib import urlencode
from urllib2 import urlparse
import logging
import requests
import boto3
import json
import os

from retro import handle_event, handle_command
from dotenv import Dotenv

dotenv = Dotenv(os.path.join(os.path.dirname(__file__), '.env'))
os.environ.update(dotenv)

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    if event.get('challenge', None):
        logging.info('Received challenge event')
        return event['challenge']

    if 'Records' in event:
        for record in event['Records']:
            logging.info('Incoming SNS message')
            event = json.loads(record['Sns']['Message'])
            logging.info(event)
            if 'event' in event:
                handle_event(event)
            elif 'command' in event:
                command = urlparse.parse_qs(event['command'])
                command = dict((key, value[0]) for key, value in command.items())
                logging.info(command)
                result = handle_command(command)
        return

    if 'event' in event or 'command' in event:
        if 'command' in event:
            command = urlparse.parse_qs(event['command'])
            command = dict((key, value[0]) for key, value in command.items())
            token = command.get('token')
        else:
            token = event.get('token')

        if token != os.environ.get('SLACK_CLIENT_TOKEN'):
            raise Exception('Token mismatch!')
        client = boto3.client('sns')

        if event.get('event', {}).get('subtype') == 'bot_message':
            logger.info('Skipping bot message')
            return
        event = json.dumps({
            'default': json.dumps(event),
        })
        topic_arn = ':'.join([
            'arn', 'aws', 'sns', '{AWS_REGION}', '{AWS_ACCOUNT_NUMBER}', '{AWS_SNS_TOPIC_NAME}'
        ]).format(**os.environ)

        publish = client.publish(Message=event, TopicArn=topic_arn,
                                 MessageStructure='json')
        logging.info('publish event: {}'.format(publish))
        return {'text': 'Right away!'}


def lambda_oauth_redirect(event, context):
    logger.info('Received OAuth event')
    logger.debug(event)
    if event.get('code', '') == '':
        params = {
            'client_id': os.environ.get('SLACK_CLIENT_ID'),
            'scope': ','.join(
                ['bot', 'commands',
                 'channels:read', 'channels:write', 'channels:history',
                 'chat:write:bot',
                 'files:read', 'files:write:user',
                 'reactions:read', 'reactions:write']),
        }
        return {
            'location': 'https://slack.com/oauth/authorize?{}'.format(urlencode(params))
        }

    params = {
        'client_id': os.environ.get("SLACK_CLIENT_ID"),
        'client_secret': os.environ.get("SLACK_CLIENT_SECRET"),
        'code': event['code'],
    }
    logger.debug('Received access token: ' + event['code'])
    request = requests.get('https://slack.com/api/oauth.access', params=params)
    data = request.json()
    logger.debug(data)
    client = boto3.resource('dynamodb')
    table = client.Table('retro_auth')

    table.put_item(
        Item={
            'team_id': data['team_id'],
            'bot_scope': data['scope'],
            'team_name': data['team_name'],
            'bot_access_token': data['bot']['bot_access_token'],
            'bot_user_id': data['bot']['bot_user_id'],
        }
    )
    return {
        'location': os.environ.get("REDIRECT_URL")
    }
