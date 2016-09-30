import boto3
import logging
import requests
import json

from operator import itemgetter
from time import time
from decimal import Decimal

from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr

from stages import RETRO_STAGES, ITEM_STAGES, STAGE_MESSAGES

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


def message_clients(channel, text):
    url = 'https://slack.com/api/chat.postMessage'
    data = {
        'token': key,
        'channel': channel,
        'text': text,
    }
    request = requests.post(url, data=data)
    logger.info(request.text)


def message_attachments(channel, text, attachments):
    url = 'https://slack.com/api/chat.postMessage'
    data = {
        'token': key,
        'channel': channel,
        "text": text,
        "attachments": attachments,
    }
    request = requests.post(url, data=data)
    logger.info(request.text)


def message_reaction(channel, timestamp, name):
    url = 'https://slack.com/api/reactions.add'
    data = {
        'token': key,
        'channel': channel,
        'name': name,
        'timestamp': timestamp,
    }
    request = requests.post(url, data=data)
    logger.info(request.text)


def get_retro(team_id, channel_id):
    client = boto3.resource('dynamodb')
    table = client.Table('retro')
    try:
        results = table.get_item(
            Key={
                'team_id': team_id,
                'channel_id': channel_id,
            }
        )
    except ClientError as e:
        return None
        # raise Exception(e.response['Error']['Message'])
    return results.get('Item')


def get_retro_items(team_id, channel_id):
    client = boto3.resource('dynamodb')
    table = client.Table('retro_messages')

    results = table.query(
        KeyConditionExpression=Key('team_id').eq(team_id) & Key('timestamp').gt(0),
        FilterExpression="channel_id = :channel_id and not #s = :actions",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ':channel_id': channel_id,
            ':actions': 'ACTIONS',
        },
    )
    return results.get('Items', [])


def get_action_items(team_id, channel_id):
    client = boto3.resource('dynamodb')
    table = client.Table('retro_messages')

    results = table.query(
        KeyConditionExpression=Key('team_id').eq(team_id) & Key('timestamp').gt(0),
        FilterExpression="channel_id = :channel_id and status = :actions",
        ExpressionAttributeValues={
            ':channel_id': channel_id,
            ':actions': 'ACTIONS',
        },
    )
    return results.get('Items', [])


def set_retro_auth(team_id, channel_id):
    global key

    client = boto3.resource('dynamodb')
    table = client.Table('retro_auth')
    logger.info(team_id)
    try:
        results = table.get_item(
            Key={
                'team_id': team_id,
            }
        )
    except ClientError as e:
        raise Exception(e.response['Error']['Message'])

    if 'Item' not in results:
        raise Exception('No auth found in database, has OAuth been successful?')

    retro_auth = results['Item']

    if 'bot_access_token' not in retro_auth:
        raise Exception(retro_auth)

    try:
        key = retro_auth['bot_access_token']
    except KeyError as e:
        raise (retro_auth)
    return retro_auth


def handle_command(command):
    channel_id = command.get('channel_id')
    team_id = command.get('team_id')
    set_retro_auth(team_id, channel_id)
    retro = get_retro(team_id, channel_id)

    text = command['text'].strip()

    if text == 'start':
        if retro:
            if retro['status'] != RETRO_STAGES[-1]:
                return {'text': 'Sorry, a retro is already in progress for this channel!'}
        start_retro(team_id, channel_id)
        return {'text': 'Retro started!'}
    elif text == 'stop':
        if retro:
            stop_retro(team_id, channel_id)
            return {'text': 'Retro stopped!'}
        return {'text': 'Sorry, there is no retro currently in progress for this channel.'}
    elif text == 'list':
        return list_retro_items(team_id, channel_id)
    elif text == 'top':
        return show_vote_results(team_id, channel_id)
    elif text == 'next':
        advance_retro(team_id, channel_id, retro)
        return {'text': 'Retro advanced to next stage!'}
    else:
        logger.info('Unknown command: {}'.format(text))
        return {'text': 'Unknown command, please try one of the following: start, stop, list, next'}


def handle_event(event):
    team_id = event['team_id']
    item = event['event']
    item_type = item.get('type')
    text = item.get('text')

    if item.get('subtype') == 'bot_message':
        logger.info('Skipping bot message')
        return

    if item_type == 'message':
        channel_id = item.get('channel')
        retro = get_retro(team_id, channel_id)
        status = retro.get('status')

        set_retro_auth(team_id, channel_id)
        logger.info('Message: {}'.format(text))

        if status in ITEM_STAGES:
            add_retro_item(team_id, channel_id, item, status)
            message_reaction(channel_id, item['ts'], 'thumbsup')
            return
        elif status == 'ACTIONS':
            add_retro_item(team_id, channel_id, item, status)
        else:
            logger.info('Skipping message because {} not in ITEM_STAGES'.format(status))
    elif item_type == 'reaction_added':
        change_vote(team_id, item['item']['ts'], 1)
        return
    elif item_type == 'reaction_removed':
        change_vote(team_id, item['item']['ts'], -1)
        return
    else:
        logger.error('Unhandled event type: {}'.format(item_type))
        logger.error(item)


def change_vote(team_id, message_ts, vote_mod=1):
    client = boto3.resource('dynamodb')
    table = client.Table('retro_messages')
    try:
        results = table.get_item(
            Key={
                'team_id': team_id,
                'timestamp': Decimal(message_ts)
            }
        )
    except ClientError as e:
        raise Exception(e.response['Error']['Message'])

    if 'Item' not in results:
        raise Exception('No item in results for voted item? - {}'.format(json.dumps(results)))

    message = results['Item']
    message['votes'] = int(message['votes']) + vote_mod
    table.put_item(
        Item=message,
    )


def start_retro(team_id, channel_id):
    client = boto3.resource('dynamodb')
    table = client.Table('retro')

    table.put_item(
        Item={
            'team_id': team_id,
            'channel_id': channel_id,
            'timestamp': str(time()),
            'status': RETRO_STAGES[0],
        }
    )
    message_clients(channel_id, STAGE_MESSAGES[RETRO_STAGES[0]])
    return {'text': 'Started retro!'}


def stop_retro(team_id, channel_id):
    client = boto3.resource('dynamodb')
    table = client.Table('retro')

    table.put_item(
        Item={
            'team_id': team_id,
            'channel_id': channel_id,
            'timestamp': str(time()),
            'status': RETRO_STAGES[-1],
        }
    )

    message_clients(channel_id, 'Stopping this retro! All items will be cleared from the retro list.')
    clear_retro_items(team_id, channel_id)
    logger.info('Stopping retro for {} - {}'.format(team_id, channel_id))
    return {'text': 'Stopped retro!'}


def show_vote_results(team_id, channel_id):
    items = get_retro_items(team_id, channel_id)
    for x, item in enumerate(items):
        items[x]['votes'] = int(items[x]['votes'])
    items.sort(key=itemgetter('votes'))
    items = items[:3]
    attachments = '\n'.join(['{votes} - {message}'.format(**item) for item in items])
    logger.info(attachments)
    message_clients(channel_id, 'The following three items were the highest voted of the retrospective:\n{}'.format(
        attachments))


def finish_retro(team_id, channel_id):
    pass


def add_retro_item(team_id, channel, item, status):
    client = boto3.resource('dynamodb')
    table = client.Table('retro_messages')
    try:
        result = table.put_item(
            Item={
                'team_id': team_id,
                'timestamp': Decimal(item['ts']),
                'channel_id': channel,
                'status': status,
                'votes': '0',
                'message': item['text'],
            }
        )
    except Exception as e:
        logger.error('Unable to add retro item: {}'.format(json.dumps(e)))
    logger.info('Added retro item "{}"'.format(item['text']))


def list_retro_items(team_id, channel_id):
    messages = get_retro_items(team_id, channel_id)

    if len(messages) == 0:
        return {'text': 'No retro items so far.'}

    for stage in ITEM_STAGES:
        result = '\n'.join(
            ['{votes} - {message}'.format(**message) for message in messages if message['status'] == stage])
        message = '{}\n{}'.format(stage, result)
        message_clients(channel_id, message)


def clear_retro_items(team_id, channel_id):
    retro_items = get_retro_items(team_id, channel_id)
    client = boto3.resource('dynamodb')
    table = client.Table('retro_messages')

    try:
        for item in retro_items:
            table.delete_item(
                Key={
                    'team_id': item['team_id'],
                    'timestamp': item['timestamp'],
                }
            )
    except ClientError as e:
        logger.error('Failed to delete item: {}'.format(e.response['Error']['Code']))

    message_clients(channel_id, 'Cleared {} items from the retro list.'.format(len(retro_items)))


def advance_retro(team_id, channel_id, retro):
    client = boto3.resource('dynamodb')
    table = client.Table('retro')

    current_stage = retro['status']
    current_index = RETRO_STAGES.index(current_stage)
    if current_index == len(RETRO_STAGES):
        logger.error('Trying to advance past end stage {}'.format(current_stage))
        return {'text': "You're already done!"}
    if current_index == -1:
        logger.error('Unknown current stage: {}'.format(current_stage))
    next_stage = RETRO_STAGES[current_index + 1]

    logger.info('Advancing retro from status {} to {}'.format(current_stage, next_stage))
    message_clients(channel_id, STAGE_MESSAGES[next_stage])

    table.put_item(
        Item={
            'team_id': team_id,
            'channel_id': channel_id,
            'timestamp': str(time()),
            'status': next_stage,
        }
    )

    if next_stage == 'RESULTS':
        show_vote_results(team_id, channel_id)
