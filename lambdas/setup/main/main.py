#
# Copyright Sonrai Security All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
import json
import boto3
import logging
import time
import os
import requests
from botocore.exceptions import ClientError
from sonrai.graphql.client import GraphQLClient
from sonrai.graphql.token import GraphQLToken

WAIT_TIME = 5   # Wait for 5 seconds

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)

session = boto3.Session()

sonrai_deployment_name = os.environ["sonrai_deployment_name"]
role_name = os.environ["role_name"]
secret_name = os.environ["secret"]

graphql_client = None
region_name = None

def get_token():

    # Create a Secrets Manager client
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.
    secret = None
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']

    if secret is None:
      raise "Secret not found"
            
    return json.loads(secret)['sonrai_token']


def get_graphql_client():
  global graphql_client
  if graphql_client is None:
    token_str = get_token()
    token = GraphQLToken(token_str)
    graphql_client = GraphQLClient(token)
  
  return graphql_client

def add_accounts_to_sonrai(sonrai_deployment_name, aws_account_numbers, role_name):
  queryPlatformAccounts = '''query get_platform_accounts($name: String) {
    PlatformAccounts (where: {
      cloudType: { value: "aws"}
      name: {value: $name}
    })
    {
      items {
        srn
        containsCloudAccount{
          items{
            srn
            blob
          }
        }
      }
    }
    }'''  
  variables = { }
  variables["name"] = sonrai_deployment_name

  r_platform_accounts = get_graphql_client().query(queryPlatformAccounts, variables)
  platform_accounts = r_platform_accounts['PlatformAccounts']['items']
  if len(platform_accounts) < 1:
    raise 'Deployment not found'

  platform_account_srn = platform_accounts[0]['srn']

  # Get accounts already being scanned
  contained_cloud_accounts = platform_accounts[0]['containsCloudAccount']['items']
  already_scanning = set()
  for cloud_account in contained_cloud_accounts:
    already_scanning.add(cloud_account['blob']['accountNumber'])

  # Add any that aren't already scanned
  mutation_add_account = ''' 
  mutation createSubAccount($account: PlatformcloudaccountCreator!) {
  CreatePlatformcloudaccount(value: $account) {srn blob cloudType  name }}'''
  
  toAdd = aws_account_numbers.difference(already_scanning)

  for account in toAdd:
    role_arn = ("arn:aws:iam::"+account+":role/"+role_name)
    variables =  ('{"account": {"containedByAccount":' +
                                  '{"add": "' + platform_account_srn + '"},' +
                              '"cloudType": "aws",' +
                              '"blob": {'  +
                                  '"accountNumber": "' + account +'",'+
                                  '"roleArn": "' + role_arn + '",' +
                                  '"botRoleArn": "' + role_arn + '",' +
                                  '"runDateTime": ' + str(round(time.time() * 1000)) +
                                  '}'+
                              '}'+
                  '}')
    logging.info('Adding Account {} to Sonrai'.format(account))
    r_add_account = get_graphql_client().query(mutation_add_account, variables)


def assume_role(aws_account_number, role_name, external_id):
    '''
    Assumes the provided role in each account and returns a session object
    :param aws_account_number: AWS Account Number
    :param role_name: Role to assume in target account
    :param aws_region: AWS Region for the Client call
    :return: Session object for the specified AWS Account and Region
    '''
    try:
        sts_client = boto3.client('sts')
        partition = sts_client.get_caller_identity()['Arn'].split(":")[1]
        response = sts_client.assume_role(
            RoleArn='arn:{}:iam::{}:role/{}'.format(
                partition, aws_account_number, role_name),
            RoleSessionName=str(aws_account_number + '-' + role_name),
            ExternalId=external_id
        )
        sts_session = boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken']
        )
        LOGGER.info(
                "Assumed session for {} - {}.".format(
                    aws_account_number, role_name)
                )
        return sts_session

    except Exception as e:
        LOGGER.error("Could not assume role : {}".format(e))
        return False

def get_protected_accounts(management_account, core_accounts):
    '''
    Get List accounts to protect
    '''
    output = list()
    retry_count = 0
    throttle_retry = True

    while throttle_retry and retry_count < 5:
        try:
            orgs_client = session.client('organizations')
            org_paginator = orgs_client.get_paginator('list_accounts')
            org_page_iterator = org_paginator.paginate()
            throttle_retry = False
        except Exception as exe:
            error_msg = exe.response['Error']['Code']
            if error_msg == 'ThrottlingException':
                retry_count += 1
            else:
                LOGGER.error("Could not list accounts for parent : {}".format(exe))
                return False
 
    for page in org_page_iterator:
        output += page['Accounts']

    accounts = []
    for account in output:
      if account['Status'] == 'ACTIVE' and account['Id'] != management_account:
        accounts.append(account['Id'])

    return list((set(accounts)).difference(core_accounts))

def create_stack_instance(
        target_session, stackset_name, org_id, accounts, regions,
        parameter_overrides=None,
        wait_for_completion=False,
        outputs=False,
        allow_failures=False):
    '''
    Create stackset in particular account + region
    '''
    try:
        cfn_client = target_session.client('cloudformation')
        LOGGER.debug(
            "Calling create_stack_instances... StackSetName={}, Accounts={}, Regions={}".format(
                stackset_name, accounts, regions)
            )
        kwargs = {
            'StackSetName': stackset_name,
            'Accounts': accounts,
            'Regions': regions
        }
        if parameter_overrides:
            kwargs['ParameterOverrides'] = parameter_overrides
        if allow_failures:
            kwargs['OperationPreferences'] = {'FailureTolerancePercentage': 100}

        LOGGER.info(f"Create stack instances parameters: {kwargs}")
        response = cfn_client.create_stack_instances(**kwargs)
        operation_id = response["OperationId"]
        LOGGER.debug(response)
        LOGGER.info(
                "Launched stackset instance {} for accounts {} in regions: {} with Operation id: {}".format(
                    stackset_name, accounts, regions, operation_id)
                )

        if not wait_for_completion:
            return True

        status = 'RUNNING'
        while(status == 'RUNNING'):
            time.sleep(WAIT_TIME)
            response = cfn_client.describe_stack_set_operation(
                OperationId=operation_id,
                StackSetName=stackset_name
                )
            status = response['StackSetOperation']['Status']
        if not outputs:
            return True

        result = {}
        for account in accounts:
            result[account] = {}
            account_session = assume_role(
                    account,
                    'AWSControlTowerExecution',
                    org_id)

            for region in regions:
                response = cfn_client.describe_stack_instance(
                        StackSetName=stackset_name,
                        StackInstanceAccount=account,
                        StackInstanceRegion=region)
                stack_id = response['StackInstance']['StackId']
                account_cfn_client = account_session.client('cloudformation')
                response = account_cfn_client.describe_stacks(
                        StackName=stack_id)
                result[account][region] = response['Stacks'][0]['Outputs']
        LOGGER.info(f"{stackset_name} Stackset Outputs: {result}")
        return True, result
    except Exception as e:
        LOGGER.error("Could not create stackset instance : {}".format(e))
        return False

def cfnresponse_send(
        event, context, responseStatus, responseData,
        physicalResourceId=None, noEcho=False):
    '''
    function to signal CloudFormation custom resource
    '''
    responseUrl = event['ResponseURL']
    responseBody = {}
    responseBody['Status'] = responseStatus
    responseBody['Reason'] = 'See the details in CloudWatch Log Stream: ' + context.log_stream_name
    responseBody['PhysicalResourceId'] = physicalResourceId or context.log_stream_name
    responseBody['StackId'] = event['StackId']
    responseBody['RequestId'] = event['RequestId']
    responseBody['LogicalResourceId'] = event['LogicalResourceId']
    responseBody['NoEcho'] = noEcho
    responseBody['Data'] = responseData
    json_responseBody = json.dumps(responseBody)

    headers = {
        'content-type': '',
        'content-length': str(len(json_responseBody))
    }
    try:
        response = requests.put(responseUrl,
                                data=json_responseBody,
                                headers=headers)
        LOGGER.info("CFN Response Status code: " + response.reason)
    except Exception as e:
        LOGGER.info("CFN Response Failed: " + str(e))

def list_stack_instance_by_account(target_session, stack_set_name, account_id):
    '''
    List all stack instances based on the StackSet name and Account Id
    '''
    try:
        cfn_client = target_session.client('cloudformation')
        stackset_result = cfn_client.list_stack_instances(
            StackSetName = stack_set_name,
            StackInstanceAccount=account_id
            )
        
        if stackset_result and 'Summaries' in stackset_result:            
            stackset_list = stackset_result['Summaries']
            while 'NextToken' in stackset_result:
                stackset_result = cfn_client.list_stackset_instance(
                    NextToken = stackset_result['NextToken']
                )
                stackset_list.append(stackset_result['Summaries'])
            
            return stackset_list
        else:
            return False
    except Exception as e:
        LOGGER.error("List Stack Instance error: %s" % e)
        return False

def list_stack_instance_region(target_session, stack_set_name):
    '''
    List all stack instances based on the StackSet name
    '''
    try:
        cfn_client = target_session.client('cloudformation')
        stackset_result = cfn_client.list_stack_instances(
            StackSetName = stack_set_name
            )
        
        if stackset_result and 'Summaries' in stackset_result:            
            stackset_list = stackset_result['Summaries']
            while 'NextToken' in stackset_result:
                stackset_result = cfn_client.list_stackset_instance(
                    NextToken = stackset_result['NextToken']
                )
                stackset_list.append(stackset_result['Summaries'])
            
            stackset_list_region = []
            for instance in stackset_list:
                stackset_list_region.append(instance['Region'])
            stackset_list_region=list(set(stackset_list_region))

            return stackset_list_region
        else:
            return False
    except Exception as e:
        LOGGER.error("List Stack Instance error: %s" % e)
        return False

def create_single_stack_instance(target_session, stackset_name, account, regions):
    '''
    Create stackset in particular account + region
    '''
    try:
        cfn_client = target_session.client('cloudformation')
        response = cfn_client.create_stack_instances(
            StackSetName=stackset_name,
            Accounts=account,
            Regions=regions
            )
        LOGGER.debug(response)
        LOGGER.info("Launched stackset instance {} for account {} in regions: {} with Operation id: {}".format(stackset_name, account, regions, response["OperationId"]))
        return True
    except Exception as e:
        LOGGER.error("Could not create stackset instance : {}".format(e))
        return False

def handle_new_account(event, context):
    global region_name
    region_name = str(context.invoked_function_arn).split(":")[3]
  
    # Check if lifecycle even matches
    if 'detail' in event and event['detail']['eventName'] == 'CreateManagedAccount':
        if event['detail']['serviceEventDetails']['createManagedAccountStatus']['state'] == 'SUCCEEDED':
            account_id = event['detail']['serviceEventDetails']['createManagedAccountStatus']['account']['accountId']
            
            #find if existing stackset instance for this account already exist            
            stackset_name = os.environ["stack_set_name"]
            stackset_instances = list_stack_instance_by_account(session, stackset_name, account_id)
            stackset_instances_regions = list_stack_instance_region(session, stackset_name)
            
            #stackset instance does not exist, create a new one
            if len(stackset_instances) == 0:
                create_single_stack_instance(session, stackset_name, [account_id], stackset_instances_regions)
            
            #stackset instance already exist, check for missing region
            elif len(stackset_instances) > 0:
                stackset_region = []
                for instance in stackset_instances:
                    stackset_region.append(instance['Region'])
                next_region = list(set(stackset_instances_regions) - set(stackset_region))
                if len(next_region) > 0:
                    create_single_stack_instance(session, stackset_name, [account_id], next_region)
                else:
                    LOGGER.info("Stackset instance already exist : {}".format(stackset_instances))

            add_accounts_to_sonrai(sonrai_deployment_name, set([account_id]), role_name)
        else:
             LOGGER.error("Invalid event state, expected: SUCCEEDED : {}".format(event))
    else:
        LOGGER.error("Invalid event received : {}".format(event))

def handle_initial_setup(event, context):
    global region_name
    try:
        if event['RequestType'] in ['Create', 'Update']:
            org_id = event['ResourceProperties']['OrgId']
            log_archive_account = event['ResourceProperties']['LogArchiveAccount']
            audit_account = event['ResourceProperties']['AuditAccount']

            region = str(context.invoked_function_arn).split(":")[3]
            region_name = region
            account = str(context.invoked_function_arn).split(":")[4]

            stackset_name = os.environ["stack_set_name"]

            LOGGER.info("Adding stack instance for core accounts")

            # Create SecurityAccount stack instance first to ensure that
            # SNS Topic is present for other stack instances
            # to publish registration request
            core_accounts = set([log_archive_account, audit_account])
            regions = [event['ResourceProperties']['ManagementRegion']]

            # Deploy stackset to core accounts
            create_stack_instance(
                    target_session=session,
                    stackset_name=stackset_name,
                    org_id=org_id,
                    accounts=list(core_accounts),
                    regions=regions,
                    wait_for_completion=True
                )

            protected_accounts = get_protected_accounts(
                management_account=account,
                core_accounts=core_accounts
                )

            create_stack_instance(
                    target_session=session,
                    stackset_name=stackset_name,
                    org_id=org_id,
                    accounts=protected_accounts,
                    regions=regions,
                    allow_failures=True
                )

            core_accounts.update(list(protected_accounts))
            core_accounts.add(account)

            add_accounts_to_sonrai(sonrai_deployment_name, core_accounts, role_name)

        response_data = {}
        response_data["event"] = event
        cfnresponse_send(
                event, context,
                'SUCCESS', response_data, "CustomResourcePhysicalID")

    except Exception as e:
        LOGGER.exception(e)
        response_data = {}
        response_data["Status"] = str(e)
        cfnresponse_send(
                event, context,
                'FAILED', response_data, "CustomResourcePhysicalID")

def handle(event, context):
    try:
        LOGGER.info('Lambda Handler - Start')
        LOGGER.info('REQUEST RECEIVED: {}'.format(json.dumps(event, default=str)))

        if 'detail' in event and event['detail']['eventName'] == 'CreateManagedAccount':
            handle_new_account(
            event=event, 
            context=context)          

        elif event['RequestType'] in ['Create', 'Update']:
            handle_initial_setup(
              event=event, 
              context=context)
        
        elif event['RequestType'] in ['Delete'] and 'ResponseURL' in event.keys():
            response_data = {}
            response_data["event"] = event
            cfnresponse_send(
                    event, context,
                    'SUCCESS', response_data, "CustomResourcePhysicalID")

        LOGGER.info('Lambda Handler - End')

    except Exception as e:
        LOGGER.exception(e)
        if 'ResponseURL' in event.keys():
          response_data = {}
          response_data["Status"] = str(e)
          cfnresponse_send(
                  event, context,
                  'FAILED', response_data, "CustomResourcePhysicalID")
