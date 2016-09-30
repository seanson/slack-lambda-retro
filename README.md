# Slack Lambda Retro

This was code written as an entry in DevPost's [The Serverless Chatbot Competition](http://awschatbot.devpost.com/). 

## Design

The AWS bot works in the following manner:

### Auth

- The user visits the OAuth URL, which is redirected to the Slack API for authorization and return
- Upon return the OAuth and bot configuration is stored in the `retro_auth` table

### Operation 

- All requested Slack events sent by the events API by the `slack-lambda-retro` function, these are validated and then put on the SNS queue and a HTTP 200 is returned immediately to satisfy Slack's timing requirements
- All incoming SNS items are also received by the `slack-lambda-retro` function, which is then dispatched to the `handle_event` or `handle_command` functions appropriately

## Installation

This app requires a few components to install:

### Configuration

Manual configuration is required in a few places:

- An AWS user set up with permissions to deploy a Lambda, configured as a profile in `~/aws.config`. I use the name `lambda_deploy` as a convenience, if different you will need to change `deploy.cfg` and the two kappa `*.yaml`s
- Configuration of the deployment variables in the root `.env`
- Configuration of the runtime variables in the source directory `_src/.env`

### Lambda Deployment

Lambda deployment is covered by the python application [Kappa](https://github.com/garnaat/kappa), as per its
instructions you will need to create your own IAM user for deployment. 

The lambda itself should be deployed with two commands:


`lambda deploy` - This will deploy the main function
`lambda --config kappa_oauth.yaml deploy` - This will deploy the second function for OAuth handling

### Environment Deployment

Deployment is locally invoked through the `deploy.py` function. This will provision the following:

- DynamoDB Tables retro/retro_auth/retro_messages
- SNS Topic
- API Gateway Functions
- IAM Policies for everything to talk to each other

### Slack Deployment

- Create an app integration in your Slack account and place the app's client ID and  token in `_src/.env`
- Enter your deployed API URLs from the environment deployment in the event POST API and command POST API url entries
- Visit your OAuth URL to perform authentication for your application

### Usage

Use the `/retro start` to begin the process!