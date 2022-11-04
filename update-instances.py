#!/usr/bin/env python3

import boto3
from botocore.exceptions import NoCredentialsError
import csv
import sys


# Update this with the cross-account role to be used
# Control Tower customers using Management Account credentials can leave this unchanged
EXECUTION_ROLE = 'AWSControlTowerExecution'


session = boto3.session.Session()
organizations = session.client('organizations')
sts = session.client('sts')

try:
    identity = sts.get_caller_identity()
    parent_account_id = identity['Account']
except NoCredentialsError as e:
    sys.exit(e)

reader = csv.DictReader(sys.stdin)

for row in reader:
    account_id = row['AccountId']
    region_name = row['Region']
    
    if account_id == parent_account_id:
        # For instances in _this_ account, we do not need to federate and can reuse the current session
        federated_session = session
    else:
        role_arn = f'arn:aws:iam::{account_id}:role/{EXECUTION_ROLE}'
        # This will show up in CloudTrail as 'User name' and you can treat it as an 'User Agent' for identification purpouses
        role_session_name = 'RDSReport-v1'

        credentials = sts.assume_role(RoleArn=role_arn,
                                      RoleSessionName=role_session_name)
        credentials_data = credentials['Credentials']
        federated_session = boto3.session.Session(aws_access_key_id=credentials_data['AccessKeyId'],
                                                  aws_secret_access_key=credentials_data['SecretAccessKey'],
                                                  aws_session_token=credentials_data['SessionToken'])

    rds = federated_session.client('rds', region_name=region_name)

    # Parameters to update across all instances
    parameters = { 'LicenseModel': 'bring-your-own-license' }

    print (f'[{account_id}/{region_name}] Updating DB instance "{row["DBInstanceIdentifier"]}"')

    # "With great power there must also come great responsibility"
    #                                        --- Benjamin Franklin Parker
    #
    # Uncomment the next line only if you know what you're doing
    # rds.modify_db_instance(DBInstanceIdentifier=row['DBInstanceIdentifier'], **parameters)