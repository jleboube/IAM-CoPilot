"""
AWS IAM Condition Key Catalog

Comprehensive catalog of AWS condition keys organized by service.
Updated regularly to match AWS documentation.
"""

from typing import Dict, List, Set, Optional
import logging

logger = logging.getLogger(__name__)


class ConditionKeyCatalog:
    """
    Catalog of AWS IAM condition keys.

    This catalog includes global condition keys and service-specific condition keys
    for comprehensive policy validation.
    """

    # Global condition keys (available for all services)
    GLOBAL_CONDITION_KEYS = {
        # Identity and access
        'aws:CurrentTime': {'type': 'Date', 'description': 'Current date and time'},
        'aws:EpochTime': {'type': 'Numeric', 'description': 'Current time in epoch'},
        'aws:SecureTransport': {'type': 'Boolean', 'description': 'Whether request was sent using SSL'},
        'aws:SourceIp': {'type': 'IpAddress', 'description': 'Source IP address of the requester'},
        'aws:SourceVpce': {'type': 'String', 'description': 'VPC endpoint ID'},
        'aws:SourceVpc': {'type': 'String', 'description': 'VPC ID'},
        'aws:UserAgent': {'type': 'String', 'description': 'User agent of the requester'},
        'aws:userid': {'type': 'String', 'description': 'Unique ID of the requester'},
        'aws:username': {'type': 'String', 'description': 'Name of the requester'},
        'aws:PrincipalType': {'type': 'String', 'description': 'Type of principal (User, Role, etc.)'},
        'aws:PrincipalOrgID': {'type': 'String', 'description': 'Organization ID of the principal'},
        'aws:PrincipalOrgPaths': {'type': 'String', 'description': 'Organization path of the principal'},
        'aws:PrincipalAccount': {'type': 'String', 'description': 'Account ID of the principal'},
        'aws:PrincipalArn': {'type': 'ARN', 'description': 'ARN of the principal'},
        'aws:RequestedRegion': {'type': 'String', 'description': 'AWS region of the request'},
        'aws:SourceAccount': {'type': 'String', 'description': 'Source account ID'},
        'aws:SourceArn': {'type': 'ARN', 'description': 'Source ARN'},

        # MFA
        'aws:MultiFactorAuthPresent': {'type': 'Boolean', 'description': 'Whether MFA was used'},
        'aws:MultiFactorAuthAge': {'type': 'Numeric', 'description': 'Age of MFA authentication in seconds'},

        # Federation
        'aws:FederatedProvider': {'type': 'String', 'description': 'Identity provider for federated users'},
        'aws:TokenIssueTime': {'type': 'Date', 'description': 'Time when token was issued'},

        # VPC
        'aws:VpcSourceIp': {'type': 'IpAddress', 'description': 'Source IP within VPC'},

        # Tags
        'aws:RequestTag/${TagKey}': {'type': 'String', 'description': 'Tag in the request'},
        'aws:ResourceTag/${TagKey}': {'type': 'String', 'description': 'Tag on the resource'},
        'aws:TagKeys': {'type': 'String', 'description': 'Tag keys in the request'},

        # Referer
        'aws:Referer': {'type': 'String', 'description': 'HTTP referer header'},
    }

    # Service-specific condition keys
    SERVICE_CONDITION_KEYS = {
        's3': {
            's3:x-amz-acl': {'type': 'String', 'description': 'Canned ACL for S3 object'},
            's3:x-amz-grant-read': {'type': 'String', 'description': 'Grant read permission'},
            's3:x-amz-grant-write': {'type': 'String', 'description': 'Grant write permission'},
            's3:x-amz-grant-read-acp': {'type': 'String', 'description': 'Grant read ACP permission'},
            's3:x-amz-grant-write-acp': {'type': 'String', 'description': 'Grant write ACP permission'},
            's3:x-amz-grant-full-control': {'type': 'String', 'description': 'Grant full control'},
            's3:x-amz-copy-source': {'type': 'String', 'description': 'Copy source bucket'},
            's3:x-amz-metadata-directive': {'type': 'String', 'description': 'Metadata directive for copy'},
            's3:x-amz-server-side-encryption': {'type': 'String', 'description': 'Server-side encryption method'},
            's3:x-amz-server-side-encryption-aws-kms-key-id': {'type': 'String', 'description': 'KMS key ID'},
            's3:x-amz-storage-class': {'type': 'String', 'description': 'Storage class'},
            's3:VersionId': {'type': 'String', 'description': 'Version ID of object'},
            's3:LocationConstraint': {'type': 'String', 'description': 'Location constraint for bucket'},
            's3:prefix': {'type': 'String', 'description': 'Prefix for listing objects'},
            's3:delimiter': {'type': 'String', 'description': 'Delimiter for listing objects'},
            's3:max-keys': {'type': 'Numeric', 'description': 'Maximum keys to return'},
            's3:ExistingObjectTag/<key>': {'type': 'String', 'description': 'Tag on existing object'},
            's3:RequestObjectTag/<key>': {'type': 'String', 'description': 'Tag in put request'},
            's3:RequestObjectTagKeys': {'type': 'String', 'description': 'Tag keys in request'},
            's3:object-lock-mode': {'type': 'String', 'description': 'Object lock mode'},
            's3:object-lock-retain-until-date': {'type': 'Date', 'description': 'Object lock retention date'},
            's3:object-lock-remaining-retention-days': {'type': 'Numeric', 'description': 'Days until retention expires'},
            's3:object-lock-legal-hold': {'type': 'String', 'description': 'Legal hold status'},
        },

        'iam': {
            'iam:PolicyArn': {'type': 'ARN', 'description': 'ARN of the IAM policy'},
            'iam:PermissionsBoundary': {'type': 'ARN', 'description': 'Permissions boundary ARN'},
            'iam:PassedToService': {'type': 'String', 'description': 'Service the role is passed to'},
            'iam:AssociatedResourceArn': {'type': 'ARN', 'description': 'ARN of associated resource'},
            'iam:ResourceTag/${TagKey}': {'type': 'String', 'description': 'Tag on IAM resource'},
            'iam:RequestTag/${TagKey}': {'type': 'String', 'description': 'Tag in IAM request'},
            'iam:AWSServiceName': {'type': 'String', 'description': 'AWS service name'},
            'iam:OrganizationsPolicyId': {'type': 'String', 'description': 'Organizations policy ID'},
        },

        'ec2': {
            'ec2:InstanceType': {'type': 'String', 'description': 'EC2 instance type'},
            'ec2:Region': {'type': 'String', 'description': 'EC2 region'},
            'ec2:AvailabilityZone': {'type': 'String', 'description': 'Availability zone'},
            'ec2:Vpc': {'type': 'String', 'description': 'VPC ID'},
            'ec2:Subnet': {'type': 'String', 'description': 'Subnet ID'},
            'ec2:InstanceProfile': {'type': 'ARN', 'description': 'Instance profile ARN'},
            'ec2:ResourceTag/${TagKey}': {'type': 'String', 'description': 'Tag on EC2 resource'},
            'ec2:RequestTag/${TagKey}': {'type': 'String', 'description': 'Tag in EC2 request'},
            'ec2:EbsOptimized': {'type': 'Boolean', 'description': 'Whether EBS optimized'},
            'ec2:Encrypted': {'type': 'Boolean', 'description': 'Whether volume is encrypted'},
            'ec2:VolumeSize': {'type': 'Numeric', 'description': 'Size of volume in GB'},
            'ec2:VolumeType': {'type': 'String', 'description': 'Type of EBS volume'},
            'ec2:SnapshotTime': {'type': 'Date', 'description': 'Time snapshot was created'},
            'ec2:Owner': {'type': 'String', 'description': 'Owner of the resource'},
            'ec2:ParentVolume': {'type': 'String', 'description': 'Parent volume ID'},
            'ec2:PlacementGroup': {'type': 'String', 'description': 'Placement group name'},
            'ec2:ProductCode': {'type': 'String', 'description': 'Product code'},
            'ec2:PublicIpAddress': {'type': 'IpAddress', 'description': 'Public IP address'},
            'ec2:RootDeviceType': {'type': 'String', 'description': 'Root device type'},
            'ec2:Tenancy': {'type': 'String', 'description': 'Tenancy of instance'},
        },

        'kms': {
            'kms:EncryptionContext:${EncryptionContextKey}': {'type': 'String', 'description': 'Encryption context'},
            'kms:EncryptionContextKeys': {'type': 'String', 'description': 'Encryption context keys'},
            'kms:CallerAccount': {'type': 'String', 'description': 'Account of caller'},
            'kms:ViaService': {'type': 'String', 'description': 'Service making request via KMS'},
            'kms:GrantIsForAWSResource': {'type': 'Boolean', 'description': 'Whether grant is for AWS resource'},
            'kms:GrantOperations': {'type': 'String', 'description': 'Operations allowed by grant'},
            'kms:GrantConstraintType': {'type': 'String', 'description': 'Type of grant constraint'},
            'kms:KeyOrigin': {'type': 'String', 'description': 'Origin of the key'},
            'kms:KeySpec': {'type': 'String', 'description': 'Key spec'},
            'kms:KeyUsage': {'type': 'String', 'description': 'Key usage'},
            'kms:ResourceAliases': {'type': 'String', 'description': 'Key aliases'},
            'kms:WrappingAlgorithm': {'type': 'String', 'description': 'Wrapping algorithm'},
            'kms:WrappingKeySpec': {'type': 'String', 'description': 'Wrapping key spec'},
        },

        'lambda': {
            'lambda:FunctionArn': {'type': 'ARN', 'description': 'Lambda function ARN'},
            'lambda:Layer': {'type': 'ARN', 'description': 'Lambda layer ARN'},
            'lambda:Principal': {'type': 'String', 'description': 'Principal invoking function'},
            'lambda:EventSourceToken': {'type': 'String', 'description': 'Event source token'},
            'lambda:SourceArn': {'type': 'ARN', 'description': 'ARN of event source'},
        },

        'dynamodb': {
            'dynamodb:LeadingKeys': {'type': 'String', 'description': 'Leading keys in query'},
            'dynamodb:Select': {'type': 'String', 'description': 'Select parameters'},
            'dynamodb:Attributes': {'type': 'String', 'description': 'Attributes to return'},
            'dynamodb:ReturnConsumedCapacity': {'type': 'String', 'description': 'Return consumed capacity'},
            'dynamodb:ReturnValues': {'type': 'String', 'description': 'Return values'},
            'dynamodb:EnclosingOperation': {'type': 'String', 'description': 'Enclosing operation'},
        },

        'rds': {
            'rds:DatabaseName': {'type': 'String', 'description': 'Database name'},
            'rds:DatabaseClass': {'type': 'String', 'description': 'DB instance class'},
            'rds:StorageSize': {'type': 'Numeric', 'description': 'Storage size in GB'},
            'rds:Piops': {'type': 'Numeric', 'description': 'Provisioned IOPS'},
            'rds:Vpc': {'type': 'Boolean', 'description': 'Whether in VPC'},
            'rds:MultiAz': {'type': 'Boolean', 'description': 'Whether Multi-AZ'},
            'rds:StorageEncrypted': {'type': 'Boolean', 'description': 'Whether storage encrypted'},
            'rds:DatabaseEngine': {'type': 'String', 'description': 'Database engine'},
            'rds:DatabaseVersion': {'type': 'String', 'description': 'Database version'},
            'rds:EndpointType': {'type': 'String', 'description': 'Endpoint type'},
            'rds:cluster-tag/${TagKey}': {'type': 'String', 'description': 'Tag on cluster'},
            'rds:db-tag/${TagKey}': {'type': 'String', 'description': 'Tag on DB instance'},
            'rds:req-tag/${TagKey}': {'type': 'String', 'description': 'Tag in request'},
        },

        'sns': {
            'sns:Endpoint': {'type': 'String', 'description': 'Subscription endpoint'},
            'sns:Protocol': {'type': 'String', 'description': 'Subscription protocol'},
        },

        'sqs': {
            'sqs:QueueUrl': {'type': 'String', 'description': 'Queue URL'},
        },

        'cloudwatch': {
            'cloudwatch:namespace': {'type': 'String', 'description': 'CloudWatch namespace'},
        },

        'logs': {
            'logs:LogGroupName': {'type': 'String', 'description': 'Log group name'},
            'logs:LogStreamName': {'type': 'String', 'description': 'Log stream name'},
        },

        'secretsmanager': {
            'secretsmanager:Name': {'type': 'String', 'description': 'Secret name'},
            'secretsmanager:Description': {'type': 'String', 'description': 'Secret description'},
            'secretsmanager:KmsKeyId': {'type': 'String', 'description': 'KMS key ID'},
            'secretsmanager:ResourceTag/tag-key': {'type': 'String', 'description': 'Tag on secret'},
            'secretsmanager:resource/AllowRotationLambdaArn': {'type': 'ARN', 'description': 'Rotation Lambda ARN'},
            'secretsmanager:VersionStage': {'type': 'String', 'description': 'Version stage'},
            'secretsmanager:VersionId': {'type': 'String', 'description': 'Version ID'},
        },

        'organizations': {
            'organizations:PolicyType': {'type': 'String', 'description': 'Type of policy'},
            'organizations:ServicePrincipal': {'type': 'String', 'description': 'Service principal'},
        },

        'sts': {
            'sts:ExternalId': {'type': 'String', 'description': 'External ID for assume role'},
            'sts:RoleSessionName': {'type': 'String', 'description': 'Role session name'},
            'sts:TransitiveTagKeys': {'type': 'String', 'description': 'Transitive tag keys'},
        },
    }

    # Valid condition operators
    CONDITION_OPERATORS = {
        # String conditions
        'StringEquals': 'String',
        'StringNotEquals': 'String',
        'StringEqualsIgnoreCase': 'String',
        'StringNotEqualsIgnoreCase': 'String',
        'StringLike': 'String',
        'StringNotLike': 'String',

        # Numeric conditions
        'NumericEquals': 'Numeric',
        'NumericNotEquals': 'Numeric',
        'NumericLessThan': 'Numeric',
        'NumericLessThanEquals': 'Numeric',
        'NumericGreaterThan': 'Numeric',
        'NumericGreaterThanEquals': 'Numeric',

        # Date conditions
        'DateEquals': 'Date',
        'DateNotEquals': 'Date',
        'DateLessThan': 'Date',
        'DateLessThanEquals': 'Date',
        'DateGreaterThan': 'Date',
        'DateGreaterThanEquals': 'Date',

        # Boolean condition
        'Bool': 'Boolean',

        # IP address conditions
        'IpAddress': 'IpAddress',
        'NotIpAddress': 'IpAddress',

        # ARN conditions
        'ArnEquals': 'ARN',
        'ArnNotEquals': 'ARN',
        'ArnLike': 'ARN',
        'ArnNotLike': 'ARN',

        # Null condition
        'Null': 'Boolean',

        # IfExists modifiers
        'StringEqualsIfExists': 'String',
        'StringNotEqualsIfExists': 'String',
        'StringLikeIfExists': 'String',
        'NumericEqualsIfExists': 'Numeric',
        'NumericLessThanIfExists': 'Numeric',
        'DateEqualsIfExists': 'Date',
        'DateLessThanIfExists': 'Date',
        'BoolIfExists': 'Boolean',
        'IpAddressIfExists': 'IpAddress',
        'ArnEqualsIfExists': 'ARN',
        'ArnLikeIfExists': 'ARN',
    }

    @classmethod
    def get_all_condition_keys(cls, service: Optional[str] = None) -> Dict[str, Dict[str, str]]:
        """
        Get all condition keys, optionally filtered by service.

        Args:
            service: AWS service prefix (e.g., 's3', 'ec2', 'iam'). If None, returns all keys.

        Returns:
            Dictionary of condition keys with their metadata
        """
        if service:
            service_lower = service.lower()
            service_keys = cls.SERVICE_CONDITION_KEYS.get(service_lower, {})
            # Combine with global keys
            return {**cls.GLOBAL_CONDITION_KEYS, **service_keys}
        else:
            # Return all keys from all services
            all_keys = cls.GLOBAL_CONDITION_KEYS.copy()
            for service_keys in cls.SERVICE_CONDITION_KEYS.values():
                all_keys.update(service_keys)
            return all_keys

    @classmethod
    def is_valid_condition_key(cls, condition_key: str, service: Optional[str] = None) -> bool:
        """
        Check if a condition key is valid.

        Args:
            condition_key: The condition key to validate (e.g., 's3:prefix', 'aws:SourceIp')
            service: Optional service to narrow validation scope

        Returns:
            True if the condition key is valid
        """
        # Handle variable placeholders
        # aws:RequestTag/${TagKey} -> check pattern
        if '${' in condition_key:
            # Extract base pattern
            base_pattern = condition_key.split('${')[0] + '${TagKey}'
            all_keys = cls.get_all_condition_keys(service)
            return base_pattern in all_keys

        # Handle dynamic keys like s3:ExistingObjectTag/<key>
        if '/<' in condition_key and '>' in condition_key:
            base_pattern = condition_key.split('/<')[0] + '/<key>'
            all_keys = cls.get_all_condition_keys(service)
            return base_pattern in all_keys

        # Direct lookup
        all_keys = cls.get_all_condition_keys(service)
        return condition_key in all_keys

    @classmethod
    def is_valid_operator(cls, operator: str) -> bool:
        """
        Check if a condition operator is valid.

        Args:
            operator: The condition operator (e.g., 'StringEquals', 'IpAddress')

        Returns:
            True if the operator is valid
        """
        return operator in cls.CONDITION_OPERATORS

    @classmethod
    def get_operator_type(cls, operator: str) -> Optional[str]:
        """
        Get the data type for a condition operator.

        Args:
            operator: The condition operator

        Returns:
            Data type (String, Numeric, Date, Boolean, IpAddress, ARN) or None
        """
        return cls.CONDITION_OPERATORS.get(operator)

    @classmethod
    def validate_operator_for_key(cls, operator: str, condition_key: str) -> bool:
        """
        Validate that an operator is appropriate for a condition key.

        Args:
            operator: The condition operator
            condition_key: The condition key

        Returns:
            True if the operator is valid for the key's data type
        """
        operator_type = cls.get_operator_type(operator)
        if not operator_type:
            return False

        # Get key metadata
        all_keys = cls.get_all_condition_keys()

        # Handle variable keys
        if '${' in condition_key:
            base_pattern = condition_key.split('${')[0] + '${TagKey}'
            key_info = all_keys.get(base_pattern)
        elif '/<' in condition_key:
            base_pattern = condition_key.split('/<')[0] + '/<key>'
            key_info = all_keys.get(base_pattern)
        else:
            key_info = all_keys.get(condition_key)

        if not key_info:
            return False

        key_type = key_info.get('type')

        # Check if operator type matches key type
        return operator_type == key_type

    @classmethod
    def get_service_from_action(cls, action: str) -> Optional[str]:
        """
        Extract service prefix from an action.

        Args:
            action: AWS action (e.g., 's3:GetObject', 'iam:CreateUser')

        Returns:
            Service prefix (e.g., 's3', 'iam') or None
        """
        if ':' in action:
            return action.split(':')[0].lower()
        return None

    @classmethod
    def suggest_condition_keys(cls, service: Optional[str] = None, prefix: str = '') -> List[Dict[str, str]]:
        """
        Suggest condition keys based on service and prefix.

        Args:
            service: AWS service prefix
            prefix: Partial condition key for autocomplete

        Returns:
            List of matching condition keys with descriptions
        """
        all_keys = cls.get_all_condition_keys(service)

        if prefix:
            matching_keys = {
                k: v for k, v in all_keys.items()
                if k.lower().startswith(prefix.lower())
            }
        else:
            matching_keys = all_keys

        return [
            {
                'key': key,
                'type': info['type'],
                'description': info['description']
            }
            for key, info in sorted(matching_keys.items())
        ]
