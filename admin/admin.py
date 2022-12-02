# The MIT License (MIT)
# Copyright (c) 2021-2022 by the xcube development team and contributors
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

"""The admin module provides utilities for ARDC infrastructure configuration
This module is intended for the use of ARDC system administrators and is not
relevant to users.
"""

import json
from datetime import datetime
from typing import Tuple, List
import logging

import boto3
import boto3.session

PERMISSIONS_BOUNDARY = 'user-permissions-boundary'
BUCKET_ACCESS_USER_PREFIX = 's3-user'


class AwsResourceCreator:
    """A class to create the AWS resources necessary to run the ARDC
    This class automatically creates and configures the buckets needed by the
    ARDC application, as well as an IAM "user manager" user with restricted
    permissions to create IAM bucket access users, and a policy to be used as a
    permissions boundary for the bucket access users.
    The resource creation methods in this class are not guaranteed to be
    idempotent: they implicitly assume that the required resources are not
    yet present. If identically-named resources are already present (e.g.
    because a resource creation method is called twice in succession),
    errors may result. It is the caller's responsibility to ensure that no
    identically-named resources are present before calling a resource
    creation method.
    """

    def __init__(self, aws_account_number: str, creator_tag: str,
                 resource_prefix: str, project: str,
                 data_providers: List[str] = None, alert_email: str = None,
                 bucket_size_limit_bytes: int = 1e12, ):
        """Instantiate a new AWS resource creator.
        No AWS resources are created until the *create_resources* method
        is called. See the *create_resources* documentation for details of
        which resources are created.
        Args:
            aws_account_number: number of AWS account under which resources
                   are to be created
            creator_tag: value for the "creator" tag in created resources
            resource_prefix: prefix to apply to name of created resources
            data_providers: list of ARN strings of accounts which should have
                   write access to the data, data-staging, and data-test buckets
            alert_email: email address which should be subscribed to alerts
                   about excess bucket usage. If *alert_email* is omitted,
                   CloudWatch alerts and an SNS topic will still be created, but
                   no emails will be sent.
            bucket_size_limit_bytes: maximum bucket size for
                   user-writeable buckets. If the contents of a user-writeable
                   bucket exceed this size, an email alert will be sent.
        """
        # We assume that a suitable access key and secret are specified
        # in .aws/credentials or the equivalent environment variables where
        # boto3 can find them.
        self.resource_prefix = resource_prefix
        self.data_providers = data_providers
        self.alert_email = alert_email
        self.bucket_size_limit_bytes = bucket_size_limit_bytes
        self.region = 'eu-central-1'
        self.session = boto3.session.Session(region_name=self.region)
        self.iam_client = self.session.client(service_name='iam')
        self.s3_client = self.session.client(service_name='s3')
        self.project = project
        self.tags = [
            dict(Key='creator', Value=creator_tag),
            dict(
                Key='create-date', Value=datetime.now().strftime(r'%Y-%m-%d')
            ),
            dict(Key='project', Value=project),
            dict(Key='cost-center', Value=project),
        ]
        self.aws_account_number = aws_account_number
        self.aws_account_id = 'arn:aws:iam::' + aws_account_number
        self.user_manager_key_id = None
        self.user_manager_key_secret = None

    def create_resources(self):
        """Create and configure the AWS resources required by ARDC.
        NB: these resources do not include the cluster used for ARDC
        deployment, which can be created by following the instruction in
        the operator manual.
        This is a convenience method which calls the following methods:
        *create_buckets*, *configure_buckets*, *create_users_and_policies*,
        and *configure_bucket_usage_alerts*. See the documentation of those
        methods for further details.
        """
        self.create_buckets()
        self.configure_buckets()
        self.create_users_and_policies()
        self.configure_bucket_usage_alerts()

    def create_buckets(self):
        """Create the S3 buckets required by ARDC.
        This method only creates the buckets; it does not configure any IAM
        or lifecycle policies for them.
        """

        bucket_ids = ['user-cubes', 'public']

        # Create standard project buckets
        for bucket_id in bucket_ids:
            bucket_name = self.resource_prefix + '-' + bucket_id
            self.s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={
                    'LocationConstraint': self.region
                },
                ObjectOwnership='BucketOwnerEnforced',
            )
            self.s3_client.put_bucket_tagging(Bucket=bucket_name,
                                              Tagging=dict(TagSet=self.tags))

    def configure_buckets(self):
        """Apply access and lifecycle policies to ARDC buckets"""

        # Apply access policies to data buckets and public user bucket. For
        # the public user bucket, the bucket policy only handles read access;
        # write access is managed by the IAM policy. For the non-public user
        # bucket, there is no bucket policy and access is managed entirely by
        # the IAM policy.
        for bucket_id in 'user-cubes', 'public':
            bucket_name = self.resource_prefix + '-' + bucket_id
            statement = [
                {
                    'Sid': f'AllowReadFor{self.project}Users',
                    'Effect': 'Allow',
                    'Principal': {'AWS': '*'},
                    'Action': ['s3:Get*', 's3:List*'],
                    'Resource': [
                        f'arn:aws:s3:::{bucket_name}',
                        f'arn:aws:s3:::{bucket_name}/*'
                    ],
                    'Condition': {
                        'StringLike': {
                            'aws:PrincipalArn':
                                f'{self.aws_account_id}:user/'
                                f'{self.resource_prefix}-s3-user/'
                                f'{self.resource_prefix}-s3-user-*'
                        }
                    }
                }
            ]
            if self.data_providers and bucket_id.startswith('data'):
                statement.append(
                    {
                        'Sid': 'AllowReadWriteForDataProviders',
                        'Effect': 'Allow',
                        'Principal': {'AWS': self.data_providers},
                        'Action': [
                            's3:GetBucketLocation',
                            's3:GetObject',
                            's3:ListBucket',
                            's3:PutObject',
                            's3:DeleteObject',
                            's3:ReplicateObject',
                            's3:PutObjectAcl',
                            's3:AbortMultipartUpload',
                            's3:ListBucketMultipartUploads',
                            's3:ListMultipartUploadParts'
                        ],
                        'Resource': [
                            f'arn:aws:s3:::{bucket_name}',
                            f'arn:aws:s3:::{bucket_name}/*'
                        ]
                    }
                )
            self.s3_client.put_bucket_policy(
                Bucket=bucket_name,
                Policy=json.dumps(
                    {
                        'Version': '2012-10-17',
                        'Statement': statement
                    }
                )
            )

    def create_users_and_policies(self):
        """Create IAM users and policies required by project"""
        # Create permissions boundary to restrict capabilities of
        # dynamically created bucket users.
        self.iam_client.create_policy(
            PolicyName=self.resource_prefix + '-' + PERMISSIONS_BOUNDARY,
            PolicyDocument=json.dumps(
                {
                    'Version': '2012-10-17',
                    'Statement': [
                        {
                            'Sid': 'AllowedOperations',
                            'Effect': 'Allow',
                            'Action': [
                                's3:AbortMultipartUpload',
                                's3:DeleteObject*',
                                's3:GetObject*',
                                's3:ListBucket',
                                's3:ListMultipartUploadParts',
                                's3:PutObject*'
                            ],
                            'Resource': [
                                f'arn:aws:s3:::{self.resource_prefix}-user',
                                f'arn:aws:s3:::{self.resource_prefix}-user'
                                f'-cubes/*',
                                f'arn:aws:s3:::{self.resource_prefix}-public',
                                f'arn:aws:s3:::{self.resource_prefix}-public/*'
                            ],
                        }
                    ],
                }
            ),
            Description='Limit permissions for ARDC bucket access users',
            Tags=self.tags
                 + [
                     dict(
                         Key='purpose',
                         Value=f'Limit permissions for {self.project} '
                               f'bucket access users',
                     )
                 ],
        )

        # Create "user manager" IAM user (used to create the dynamic
        # bucket users)
        user_manager_username = f'{self.resource_prefix}-user-manager'
        self.iam_client.create_user(
            UserName=user_manager_username, Tags=self.tags
        )

        # Apply a restrictive policy to the "user manager" user. This policy
        # restricts operations to user IDs under the project path, and forces
        # the user manager to apply the permissions boundary to any users it
        # creates, so it can't escalate its permissions by creating more
        # powerful users.
        # user_pattern = f'{self.aws_account_id}:user/{self.resource_prefix}/*'
        user_pattern = f'{self.aws_account_id}:user/{self.resource_prefix}-' \
                       f'{BUCKET_ACCESS_USER_PREFIX}/*'
        self.iam_client.put_user_policy(
            UserName=user_manager_username,
            PolicyName='aws-user-manager-policy',
            PolicyDocument=json.dumps(
                {
                    'Version': '2012-10-17',
                    'Statement': [
                        {
                            'Sid': 'CreateUsersWithBoundaryAndPath',
                            'Effect': 'Allow',
                            'Action': ['iam:CreateUser'],
                            'Resource': user_pattern,
                            'Condition': {
                                'StringEquals': {
                                    'iam:PermissionsBoundary':
                                        f'{self.aws_account_id}:policy/'
                                        f'{self.resource_prefix}-'
                                        f'{PERMISSIONS_BOUNDARY}'
                                }
                            },
                        },
                        {
                            'Sid': 'ManageUsersUnderPath',
                            'Effect': 'Allow',
                            'Action': [
                                'iam:CreateAccessKey',
                                'iam:DeleteAccessKey',
                                'iam:DeleteUser',
                                'iam:GetUser',
                                'iam:ListAccessKeys',
                                'iam:PutUserPolicy',
                                'iam:TagUser'
                            ],
                            'Resource': user_pattern,
                        },
                        {
                            'Sid': 'ListUsers',
                            'Effect': 'Allow',
                            'Action': ['iam:ListUsers'],
                            'Resource': '*',
                        },
                    ],
                }
            ),
        )

        # Create and store credentials for the "user manager" user.
        access_key = self.iam_client.create_access_key(
            UserName=user_manager_username)
        self.user_manager_key_id = access_key['AccessKey']['AccessKeyId']
        self.user_manager_key_secret = access_key['AccessKey'][
            'SecretAccessKey']

    def configure_bucket_usage_alerts(self):
        """Create alarms for excess usage of ARDC buckets
        This method creates an Amazon SNS topic for an excess bucket usage
        alert and adds a subscription for the email address specified in
        the constructor. It then sets up Cloudwatch alarm which is activated
        when the size of any of the user-writeable ARDC buckets exceeds the
        limit, or when the bucket size cannot be determined. The alarm
        is linked to the SNS topic and reported to the subscribed email address.
        """

        topic_arn = self._create_and_subscribe_sns_topic()
        self._create_alarms([topic_arn])

    def _create_and_subscribe_sns_topic(self):
        sns_client = self.session.client(service_name='sns')
        response = sns_client.create_topic(
            Name=self.resource_prefix + '-excess-bucket-usage',
            Attributes={},
            Tags=self.tags
        )
        topic_arn = response['TopicArn']
        if self.alert_email is not None:
            sns_client.subscribe(
                TopicArn=topic_arn,
                Protocol='email',
                Endpoint=self.alert_email,
                Attributes={},
            )
            # A subscription ARN is returned, but we don't need it for anything.
        return topic_arn

    def _create_alarms(self, actions: List[str]):
        client = self.session.client(service_name='cloudwatch')
        for bucket in '-user-cubes', '-public':
            self.create_alarm(client, self.resource_prefix + bucket, actions,
                              self.project)

    def create_alarm(self, client, bucket_name: str, actions: List[str],
                     project: str):
        # See https://docs.aws.amazon.com/AmazonS3/
        # latest/userguide/metrics-dimensions.html
        client.put_metric_alarm(
            AlarmName=bucket_name + '-size',
            AlarmDescription=f'An {project} bucket size exceeds the limit',
            ActionsEnabled=True,
            OKActions=actions,
            AlarmActions=actions,
            InsufficientDataActions=actions,
            MetricName='BucketSizeBytes',
            Namespace='AWS/S3',
            # According to AWS docs, Average is the only valid statistic for
            # BucketSizeBytes. But it doesn't matter here anyway, since in this
            # case it's an average of a single data point.
            Statistic='Average',
            Dimensions=[
                {'Name': 'StorageType', 'Value': 'StandardStorage'},
                {'Name': 'BucketName', 'Value': bucket_name},
            ],
            # BucketSizeBytes is only reported daily, so no point in trying to
            # get higher time resolution here.
            Period=60 * 60 * 24,
            Unit='Seconds',
            EvaluationPeriods=1,
            DatapointsToAlarm=1,
            Threshold=self.bucket_size_limit_bytes,
            ComparisonOperator='GreaterThanThreshold',
            TreatMissingData='breaching',
            Tags=self.tags,
        )


class BucketAccessUserCreator:
    """Create IAM users and credentials for project S3 bucket access
    This class is intended to be used by the Jupyter Hub process when
    spawning a new user environment. It creates (if not already present) an
    IAM user with permissions to read and write to the ARDC platform user's
    prefix in the user bucket, and creates and returns access credentials for
    this IAM user, which the Jupyter Hub process can then pass to the user
    environment in environment variables. In this documentation, this IAM user
    is termed the "bucket access user".
    The design of this class allows for the IAM users to be periodically
    culled or manually deleted if no corresponding user session is currently
    active; the ensure_user_and_create_key method will reuse the existing
    user if it is present, and create a new one on the fly if not. New access
    credentials are always created; if any access credentials are already
    present, the most recently created set will be kept in addition to the
    new credentials.
    """

    def __init__(self, user_name: str, client_id: str, client_secret: str,
                 aws_account_number: str, creator_tag: str,
                 resource_prefix: str, project: str):
        """Instantiate a new bucket access user creator
        No user or access key is created until the ensure_user_and_create_key
        method is called.
        Args:
            user_name: the project username, which will be used as one
                   component of the IAM username
            client_id: the client ID of the IAM user that will be used to
                   create the bucket access user. It is expected that this will
                    be the "user manager" user created during ARDC initialization,
                   but any user with sufficient permissions will work.
            client_secret: the client secret associated with the client_id
                   parameter
            aws_account_number: the number of the AWS account hosting the
                   project
            creator_tag: the value to be used for the "creator" tag applied
                   to the bucket access user
            resource_prefix: prefix to use when constructing the IAM username
             from the project username
        """
        self.user_name = user_name
        self.resource_prefix = resource_prefix
        self.project = project
        # self.iam_user_name = f'{self.resource_prefix}-{self.user_name}'
        self.iam_user_name = f'{self.resource_prefix}-' \
                             f'{BUCKET_ACCESS_USER_PREFIX}-{self.user_name}'
        self.aws_account_number = aws_account_number
        self.client = boto3.client(
            service_name='iam',
            region_name='eu-central-1',
            aws_access_key_id=client_id,
            aws_secret_access_key=client_secret
        )
        self.tags = [
            dict(Key='creator', Value=creator_tag),
            dict(
                Key='create-date', Value=datetime.now().strftime(r'%Y-%m-%d')
            ),
            dict(Key='project', Value=project),
            dict(Key='cost-center', Value=project)
        ]

    def ensure_user_and_create_key(self) -> Tuple[str, str]:
        """Create an IAM user for bucket access (if needed) and access key
        If the IAM user does not exist, it is created. A new access key and
        secret are always created and returned. If the user already exists
        and has more than one existing access key and secret, all but the
        most recently created key/secret pairs are deleted before creating
        the new key/secret pair.
        Returns a tuple consisting of a valid access key and access secret
        for the bucket access user.
        """
        boundary_arn = f'arn:aws:iam::{self.aws_account_number}:' \
                       f'policy/{self.resource_prefix}-{PERMISSIONS_BOUNDARY}'
        try:
            logging.info(f'Trying to create new IAM user {self.iam_user_name}.')
            self.client.create_user(
                # Path=f'/{self.resource_prefix}/',
                Path=f'/{self.resource_prefix}-{BUCKET_ACCESS_USER_PREFIX}/',
                UserName=self.iam_user_name,
                PermissionsBoundary=boundary_arn,
                Tags=self.tags
            )
        except self.client.exceptions.EntityAlreadyExistsException:
            logging.info(f'User {self.iam_user_name} exists; creating new '
                         f'credentials for existing user.')
            # AWS allows maximum two keys per user, so we make sure that
            # we have at most one before trying to create any more.
            self.delete_oldest_access_keys()
        self.add_policy(self.project)

        user_key_id, user_key_secret = self.create_access_key()
        return user_key_id, user_key_secret

    def delete_oldest_access_keys(self):
        """Delete all but the most recent access key for the IAM user"""
        list_response = self.client.list_access_keys(
            UserName=self.iam_user_name)
        sorted_keys = sorted(list_response['AccessKeyMetadata'],
                             key=lambda x: x['CreateDate'])
        for key_record in sorted_keys[:-1]:
            # Delete all but the most recently created key.
            # We don't expect >2 in total, but supporting it requires no
            # additional code.
            key_id = key_record['AccessKeyId']
            logging.info(f'Deleting old access key {key_id} for '
                         f'{self.iam_user_name}.')
            self.client.delete_access_key(
                UserName=self.iam_user_name,
                AccessKeyId=key_id
            )

    def create_access_key(self):
        """Create and return an access key/secret pair for the IAM user"""
        user_key = self.client.create_access_key(UserName=self.iam_user_name)
        user_key_id = user_key['AccessKey']['AccessKeyId']
        user_key_secret = user_key['AccessKey']['SecretAccessKey']
        return user_key_id, user_key_secret

    def add_policy(self, project):
        """Apply an inline access policy to the IAM bucket access user
        The policy added by this method allows some standard S3 operations
        and restricts project-specific user bucket access to paths with the
        user's own prefix. Note that the user's capabilities are also restricted
         by the permissions boundary applied on user creation.
        """
        user_name = self.user_name
        policy = json.dumps({
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Sid': 'AllowList',
                    'Effect': 'Allow',
                    'Action': ['s3:ListBucket'],
                    'Resource': [
                        f'arn:aws:s3:::{self.resource_prefix}-user-cubes',
                        f'arn:aws:s3:::{self.resource_prefix}-user-cubes/{user_name}',
                        f'arn:aws:s3:::{self.resource_prefix}-'
                        f'user/{user_name}/*'
                    ],
                    'Condition': {
                        'ForAllValues:StringLike': {
                            's3:prefix': [
                                f'',
                                f'{user_name}',
                                f'{user_name}/',
                                f'{user_name}/*'
                            ]
                        }
                    }
                },
                {
                    'Sid': 'AllowSomeOperations',
                    'Effect': 'Allow',
                    'Action': [
                        's3:AbortMultipartUpload',
                        's3:DeleteObject*',
                        's3:GetObject*',
                        's3:ListMultipartUploadParts',
                        's3:PutObject*'
                    ],
                    'Resource': [
                        f'arn:aws:s3:::{self.resource_prefix}-user-cubes/{user_name}',
                        f'arn:aws:s3:::{self.resource_prefix}-'
                        f'user/{user_name}/*',
                        f'arn:aws:s3:::{self.resource_prefix}-'
                        f'public/{user_name}',
                        f'arn:aws:s3:::{self.resource_prefix}-'
                        f'public/{user_name}/*'
                    ]
                }
            ]
        })
        self.client.put_user_policy(
            UserName=self.iam_user_name,
            PolicyName=f'{project}-buckets-user-access-policy',
            PolicyDocument=policy
        )
