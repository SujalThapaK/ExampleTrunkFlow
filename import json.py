import json
import boto3
import uuid
import time
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError


def delete_temporary_user(username, rule_name):
    """
    Deletes the temporary IAM user and cleans up resources
    """
    iam = boto3.client('iam')
    events = boto3.client('events')
    lambda_client = boto3.client('lambda')

    try:
        print(f"Deleting temporary IAM user: {username}")

        
        # Clean up EventBridge rule
        events.remove_targets(Rule=rule_name, Ids=['1'])
        events.delete_rule(Name=rule_name)
        print("Deleted IAM Rule.")

        # List and delete access keys
        access_keys = iam.list_access_keys(UserName=username)
        for key in access_keys['AccessKeyMetadata']:
            iam.delete_access_key(UserName=username, AccessKeyId=key['AccessKeyId'])

        # Delete login profile (retry if temporarily unmodifiable)
        for _ in range(6):
            try:
                iam.delete_login_profile(UserName=username)
                print(f"Deleted login profile for {username}")
                break
            except ClientError as e:
                code = e.response['Error']['Code']
                if code == 'EntityTemporarilyUnmodifiable':
                    time.sleep(5)
                elif code == 'NoSuchEntity':
                    break
                else:
                    raise

        # Detach managed policies
        attached_policies = iam.list_attached_user_policies(UserName=username)
        for policy in attached_policies['AttachedPolicies']:
            iam.detach_user_policy(UserName=username, PolicyArn=policy['PolicyArn'])

        # Delete inline policies
        policies = iam.list_user_policies(UserName=username)
        for policy_name in policies['PolicyNames']:
            iam.delete_user_policy(UserName=username, PolicyName=policy_name)

        # Delete the user
        iam.delete_user(UserName=username)


        # Remove Lambda permission
        try:
            lambda_client.remove_permission(
                FunctionName=context.function_name,
                StatementId=f"allow-eventbridge-{rule_name}"
            )
        except ClientError:
            pass

        print(f"Successfully deleted temporary user {username} and cleaned up resources")

    except ClientError as e:
        print(f"Error deleting user {username}: {str(e)}")
        raise


def handle_error(message, status_code):
    """
    Standard error response handler
    """
    print(f"Error: {message}")
    return {
        'statusCode': status_code,
        'body': json.dumps({'error': message})
    }


def create_temporary_user(event, context):
    """
    Creates a temporary IAM user with inline policies and schedules deletion
    """
    iam = boto3.client('iam')
    events = boto3.client('events')
    lambda_client = boto3.client('lambda')

    try:
        username = event['username']
        duration_minutes = event['duration_minutes']
        inline_policies = event.get('inline_policies', [])

        if not username or duration_minutes <= 0:
            raise ValueError("Invalid username or duration")

        print(f"Creating IAM user: {username}")
        iam.create_user(UserName=username)

        temp_password = f"{uuid.uuid4().hex[:12]}Aa!"
        iam.create_login_profile(
            UserName=username,
            Password=temp_password,
            PasswordResetRequired=False
        )

        sts = boto3.client("sts")
        account_id = sts.get_caller_identity()["Account"]
        signin_url = f"https://{account_id}.signin.aws.amazon.com/console"

        for policy in inline_policies:
            policy_name = policy['policy_name']
            policy_document = json.dumps(policy['policy_document'])
            print(f"Attaching policy {policy_name} to user {username}")
            iam.put_user_policy(UserName=username, PolicyName=policy_name, PolicyDocument=policy_document)

        access_key_response = iam.create_access_key(UserName=username)
        access_key_id = access_key_response['AccessKey']['AccessKeyId']
        secret_access_key = access_key_response['AccessKey']['SecretAccessKey']

        # Current UTC time
        now_utc = datetime.now(timezone.utc)

        # Schedule deletion in the future
        deletion_time = now_utc + timedelta(minutes=duration_minutes)
        print(f"[DEBUG] Current UTC time: {now_utc.isoformat()}")
        print(f"[DEBUG] Scheduled deletion UTC time: {deletion_time.isoformat()}")

        # Format cron (UTC)
        schedule_expression = f"cron({deletion_time.minute} {deletion_time.hour} {deletion_time.day} {deletion_time.month} ? {deletion_time.year})"

        rule_name = f"delete-temp-user-{username}-{uuid.uuid4().hex[:8]}"
        events.put_rule(
            Name=rule_name,
            ScheduleExpression=schedule_expression,
            Description=f"Delete temporary IAM user {username}",
            State='ENABLED'
        )

        target_payload = {"action": "delete_user", "username": username, "rule_name": rule_name}
        current_function_arn = context.invoked_function_arn

        events.put_targets(
            Rule=rule_name,
            Targets=[{'Id': '1', 'Arn': current_function_arn, 'Input': json.dumps(target_payload)}]
        )

        try:
            lambda_client.add_permission(
                FunctionName=context.function_name,
                StatementId=f"allow-eventbridge-{rule_name}",
                Action='lambda:InvokeFunction',
                Principal='events.amazonaws.com',
                SourceArn=f"arn:aws:events:{context.invoked_function_arn.split(':')[3]}:{context.invoked_function_arn.split(':')[4]}:rule/{rule_name}"
            )
        except ClientError as e:
            if e.response['Error']['Code'] != 'ResourceConflictException':
                raise

        print(f"[DEBUG] EventBridge rule {rule_name} created to delete user {username} at {deletion_time.isoformat()}")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Temporary IAM user {username} created successfully',
                'username': username,
                'signin_url': signin_url,
                'password': temp_password,
                'access_key_id': access_key_id,
                'secret_access_key': secret_access_key,
                'expires_at': deletion_time.isoformat(),
                'deletion_rule': rule_name
            })
        }

    except KeyError as e:
        return handle_error(f"Missing required parameter: {str(e)}", 400)
    except ClientError as e:
        return handle_error(f"AWS error: {str(e)}", 500)
    except Exception as e:
        return handle_error(f"Unexpected error: {str(e)}", 500)


def lambda_handler(event, context):
    if event.get('action') == 'delete_user':
        delete_temporary_user(event['username'], event['rule_name'])
        return {'statusCode': 200, 'body': json.dumps({'message': f"Temporary user {event['username']} deleted successfully"})}
    return create_temporary_user(event, context)
