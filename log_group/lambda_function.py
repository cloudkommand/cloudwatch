import boto3
import botocore
# import jsonschema
import json
import traceback
import zipfile
import os
import hashlib

from urllib.parse import quote

from botocore.exceptions import ClientError, ParamValidationError

from extutil import remove_none_attributes, account_context, ExtensionHandler, ext, \
    current_epoch_time_usec_num, component_safe_name, lambda_env, random_id, \
    handle_common_errors, create_zip

eh = ExtensionHandler()

logs = boto3.client('logs')

def lambda_handler(event, context):
    try:
        print(f"event = {event}")
        account_number = account_context(context)['number']
        region = account_context(context)['region']
        eh.capture_event(event)

        prev_state = event.get("prev_state") or {}
        project_code = event.get("project_code")
        repo_id = event.get("repo_id")
        cdef = event.get("component_def")
        cname = event.get("component_name")

        name = cdef.get("name") or component_safe_name(
            project_code, repo_id, cname, max_chars=255
        )
        trust_level = cdef.get("trust_level")
        kms_key_id = cdef.get("kms_key_id")
        tags = cdef.get("tags") or {}

        if event.get("pass_back_data"):
            print(f"pass_back_data found")
        elif event.get("op") == "upsert":
            if trust_level == "full":
                eh.add_op("compare_defs")
            else:
                eh.add_op("get_log_group")

        elif event.get("op") == "delete":
            eh.add_op("remove_log_group", {"create_and_remove": False, "name": name})
            
        compare_defs(event)

        get_log_group(name, kms_key_id, prev_state, tags, region, account_number)
        create_log_group(name, kms_key_id, tags, region, account_number)
        add_tags(name)
        remove_tags(name)
        remove_log_group()
            
        return eh.finish()

    except Exception as e:
        msg = traceback.format_exc()
        print(msg)
        eh.add_log("Unexpected Error", {"error": msg}, is_error=True)
        eh.declare_return(200, 0, error_code=str(e))
        return eh.finish()

@ext(handler=eh, op="compare_defs")
def compare_defs(event):
    old_digest = event.get("prev_state", {}).get("props", {}).get("def_hash")
    new_rendef = event.get("component_def")

    trust_level = new_rendef.pop("trust_level", None)

    dhash = hashlib.md5()
    dhash.update(json.dumps(new_rendef, sort_keys=True).encode())
    digest = dhash.hexdigest()
    eh.add_props({"def_hash": digest})

    if old_digest == digest and trust_level == "full":
        eh.add_links(event.get("prev_state", {}).get('links'))
        eh.add_props(event.get("prev_state", {}).get('props'))
        eh.add_log("Full Trust, No Change: Exiting", {"old_hash": old_digest, "new_hash": digest})

    else:
        eh.add_log("Definitions Don't Match, Deploying", {"old": old_digest, "new": digest})

@ext(handler=eh, op="get_log_group")
def get_log_group(name, kms_key_id, prev_state, tags, region, account_number):

    if prev_state and prev_state.get("props") and prev_state.get("props").get("name"):
        prev_name = prev_state.get("props").get("name")
        if name != prev_name:
            eh.add_op("remove_log_group", {"create_and_remove": True, "name": prev_name})
        else:
            # Note this handles None properly
            prev_kms_key_id = prev_state.get("props").get("kms_key_id")
            if prev_kms_key_id != kms_key_id:
                eh.add_log("KMS Key ID Cannot Change", {"old": prev_kms_key_id, "new": kms_key_id}, is_error=True)
                eh.perm_error("KMS Key ID Cannot Change")
                return
    try:
        response = logs.describe_log_groups(logGroupNamePrefix=name)
        if response.get("logGroups"):
            if response.get("logGroups")[0].get("logGroupName") == name:
                eh.add_log("Found Log Group", response.get("logGroups")[0])
                
                response = logs.list_tags_log_group(logGroupName=name)
                current_tags = response.get("tags")
                if tags != current_tags:
                    remove_tags = [k for k in current_tags.keys() if k not in tags]
                    add_tags = {k:v for k,v in tags.items() if (k,v) not in current_tags.items()}
                    print(f"remove_tags = {remove_tags}")
                    print(f"add_tags = {add_tags}")
                    if remove_tags:
                        eh.add_op("remove_tags", remove_tags)
                    if add_tags:
                        eh.add_op("add_tags", add_tags)
                else:
                    eh.add_links({"Log Group": gen_log_group_link(region, name)})
                    eh.add_props({
                        "kms_key_id": kms_key_id,
                        "name": name,
                        "arn": gen_log_group_arn(name, region, account_number),
                        "star_arn": gen_log_group_star_arn(name, region, account_number)
                    })
                    eh.add_log("Log Group Exists: Exiting", {"name": name})
            else:
                eh.add_op("create_log_group")
        else:
            eh.add_op("create_log_group")       
    except ClientError as e:
        handle_common_errors(e, eh, "Get Log Group Failed", 10)
    except ParamValidationError as e:
        eh.add_log("Invalid Parameter", {"error": str(e)}, is_error=True)
        eh.perm_error("Invalid Parameter")

@ext(handler=eh, op="create_log_group")
def create_log_group(name, kms_key_id, tags, region, account_number):
    group_spec = remove_none_attributes({
        "logGroupName": name,
        "kmsKeyId": kms_key_id,
        "tags": tags or None
    })

    try:
        response = logs.create_log_group(**group_spec)
        eh.add_log("Created Log Group", response)
        eh.add_props({
            "kms_key_id": kms_key_id,
            "name": name,
            "arn": gen_log_group_arn(name, region, account_number),
            "star_arn": gen_log_group_star_arn(name, region, account_number)
        })
        eh.add_links({"Log Group": gen_log_group_link(region, name)})
    except ClientError as e:
        handle_common_errors(
            e, eh, "Create Log Group Failed", 20,
            perm_errors=["InvalidParameterException", "AccountLimitExceededException"]
        )

@ext(handler=eh, op="remove_log_group")
def remove_log_group():
    log_group_name = eh.ops['remove_log_group'].get("name")
    car = eh.ops['remove_log_group'].get("create_and_remove")

    try:
        _ = logs.delete_log_group(logGroupName=log_group_name)
        eh.add_log("Deleted Log Group", {"name": log_group_name})
    except botocore.exceptions.ClientError as e:
        if e.response.get("Error").get("Code") == "ResourceNotFoundException":
            eh.add_log("Log Group Does Not Exist", {"name": log_group_name})
        else:
            handle_common_errors(e, eh, "Delete Log Group Failed", 90 if car else 15)

@ext(handler=eh, op="add_tags")
def add_tags(name):
    tags = eh.ops['add_tags']

    try:
        logs.tag_log_group(
            logGroupName=name,
            tags=tags
        )
        eh.add_log("Tags Added", {"tags": tags})

    except ClientError as e:
        handle_common_errors(e, eh, "Add Tags Failed", 70, ['InvalidParameterValueException'])
        
@ext(handler=eh, op="remove_tags")
def remove_tags(name):
    try:
        logs.untag_log_group(
            logGroupName=name,
            tags=eh.ops['remove_tags']
        )
        eh.add_log("Tags Removed", {"tags": eh.ops['remove_tags']})

    except botocore.exceptions.ClientError as e:
        handle_common_errors(e, eh, "Remove Tags Failed", 80, ['InvalidParameterValueException'])

def gen_log_group_arn(log_group_name, region, account_number):
    return f"arn:aws:logs:{region}:{account_number}:log-group/{log_group_name}"

def gen_log_group_star_arn(log_group_name, region, account_number):
    return f"arn:aws:logs:{region}:{account_number}:log-group:{log_group_name}:*"

def gen_log_group_link(region, log_group_name):
    encoded_name = quote(quote(log_group_name, safe=''), safe='').replace("%", "$")
    return f"https://{region}.console.aws.amazon.com/cloudwatch/home?region={region}#logsV2:log-groups/log-group/{encoded_name}"
