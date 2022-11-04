#!/usr/bin/env python3

import boto3
from botocore.exceptions import NoCredentialsError
import csv
import sys


# Update this with the list of regions you want to include in the report
REGIONS = ['eu-central-1', 'us-east-1']
# Update this with the cross-account role to be used
# Control Tower customers using Management Account credentials can leave this unchanged
EXECUTION_ROLE = 'AWSControlTowerExecution'


def db_attribute(db_instance, key):
    try:
        return db_instance[key]
    except KeyError:
        return 'N/A'


session = boto3.session.Session()
organizations = session.client('organizations')
sts = session.client('sts')

try:
    identity = sts.get_caller_identity()
    parent_account_id = identity['Account']
except NoCredentialsError as e:
    sys.exit(e)

account_paginator = organizations.get_paginator('list_accounts')
account_iterator = account_paginator.paginate(PaginationConfig={'PageSize': 20})

# Add/Remove/Reorder report columns here
columns = [ 'AccountId', 'Region', 'DBInstanceIdentifier', 'DBInstanceClass', 'VCPUs',
            'MemoryInGiB', 'AllocatedStorageInGiB', 'Engine', 'EngineVersion', 'LicenseModel' ]
writer = csv.DictWriter(sys.stdout, fieldnames=columns, restval='N/A', extrasaction='ignore')
writer.writeheader()

for account_page in account_iterator:
    for account in account_page['Accounts']:
        account_id = account['Id']
        
        if account_id == parent_account_id:
            # The list of accounts will also include _this_ account, in which case we do not need to federate and can reuse the current session
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
            
        for region_name in REGIONS:
            rds = federated_session.client('rds', region_name=region_name)
            ec2 = federated_session.client('ec2', region_name=region_name)

            db_paginator = rds.get_paginator('describe_db_instances')
            db_iterator = db_paginator.paginate(PaginationConfig={'PageSize': 20})

            for db_page in db_iterator:
                for db_instance in db_page['DBInstances']:
                    # To obtain instance size information, we map the RDS instance types back to the underlying EC2 instance types
                    ec2_instance_type = db_instance['DBInstanceClass'].replace('db.', '')
                    ec2_instances = ec2.describe_instance_types(InstanceTypes=[ec2_instance_type])

                    try:
                        instance_vcpus = ec2_instances['InstanceTypes'][0]['VCpuInfo']['DefaultVCpus']
                        instance_memory = ec2_instances['InstanceTypes'][0]['MemoryInfo']['SizeInMiB'] >> 10
                    except (IndexError, KeyError):
                        instance_vcpus = 'N/A'
                        instance_memory = 'N/A'
                    
                    row = { 'AccountId': account_id,
                            'Region': region_name,
                            'DBInstanceIdentifier': db_attribute(db_instance, 'DBInstanceIdentifier'),
                            'DBInstanceClass': db_attribute(db_instance, 'DBInstanceClass'),
                            'VCPUs': instance_vcpus,
                            'MemoryInGiB': instance_memory,
                            'AllocatedStorageInGiB': db_attribute(db_instance, 'AllocatedStorage'),
                            'Engine': db_attribute(db_instance, 'Engine'),
                            'EngineVersion': db_attribute(db_instance, 'EngineVersion'),
                            'LicenseModel': db_attribute(db_instance, 'LicenseModel') }
                    writer.writerow(row)