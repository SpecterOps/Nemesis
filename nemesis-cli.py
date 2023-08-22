#!/usr/bin/python3

import argparse
import logging
import os
import secrets
import string
import subprocess
import sys

# Setup logging
logger = logging.getLogger("nemesis")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)

formatter = logging.Formatter('[{levelname}] {message}', style='{')
ch.setFormatter(formatter)

logger.addHandler(ch)


# Check dependencies
exit_early = False
try:
    import boto3
except:
    logger.error("Please run `pip3 install boto3`")
    exit_early = True
try:
    from vyper import v
except:
    logger.error("Please run `pip3 install vyper-config`")
    exit_early = True

try:
    from passlib.hash import apr_md5_crypt
except:
    logger.error("Please run `pip3 install passlib`")
    exit_early = True
if exit_early:
    sys.exit(1)


version = "v0.1.0a"


######################################################
#
# Helpers
#
######################################################


def print_logo():
    print(
        f"""
  _   _                          _             _____ _      _____
 | \\ | |                        (_)           / ____| |    |_   _|
 |  \\| | ___ _ __ ___   ___  ___ _ ___ ______| |    | |      | |
 | . ` |/ _ \\ '_ ` _ \\ / _ \\/ __| / __|______| |    | |      | |
 | |\\  |  __/ | | | | |  __/\\__ \\ \\__ \\      | |____| |____ _| |_
 |_| \\_|\\___|_| |_| |_|\\___||___/_|___/       \\_____|______|_____|
  {version}

"""
    )


def get_random_password(length=24):
    """Gets a random password of the specified length."""

    return "".join(secrets.choice(string.ascii_letters + string.digits) for i in range(length))


def run_cmd(cmd, show_error=False):
    """Small helper that returns program output or None if execution fails."""

    exitcode, output = subprocess.getstatusoutput(cmd)
    if "(NotFound)" in output or output.lower() == "none":
        return None
    elif exitcode == 0:
        if output == "<no value>":
            return None
        else:
            return output
    elif exitcode != 0 and show_error:
        logger.error(f"\Exit code '{exitcode}' running command '{cmd}' : {output}")
        return None
    else:
        return None


######################################################
#
# Kubectl functions
#
######################################################


def get_kubectl_value(key):
    """Gets a specific aws configmap/key value that is already set in kubectl."""

    if key == "aws_region":
        return run_cmd("kubectl get configmaps aws-config -o=go-template='{{index .data \"aws-default-region\"}}'")

    elif key == "aws_bucket":
        return run_cmd("kubectl get configmaps aws-config -o=go-template='{{index .data \"aws-bucket\"}}'")

    elif key == "aws_kms_key_alias":
        return run_cmd("kubectl get configmaps aws-config -o=go-template='{{index .data \"aws-kms-key-alias\"}}'")

    elif key == "aws_access_key_id":
        return run_cmd(
            "kubectl get secret aws-creds -o=go-template='{{index .data \"aws_access_key_id\"}}' | base64 -d"
        )

    elif key == "aws_secret_key":
        return run_cmd("kubectl get secret aws-creds -o=go-template='{{index .data \"aws_secret_key\"}}' | base64 -d")

    elif key == "minio_root_user":
        return run_cmd(
            "kubectl get secret minio-creds -o=go-template='{{index .data \"minio_root_user\"}}' | base64 -d"
        )

    elif key == "minio_root_password":
        return run_cmd(
            "kubectl get secret minio-creds -o=go-template='{{index .data \"minio_root_password\"}}' | base64 -d"
        )

    elif key == "minio_storage_size":
        return run_cmd("kubectl get configmaps operation-config -o=go-template='{{index .data \"minio_storage_size\"}}'")

    elif key == "storage_provider":
        return run_cmd("kubectl get configmaps operation-config -o=go-template='{{index .data \"storage_provider\"}}'")

    elif key == "assessment_id":
        return run_cmd("kubectl get configmaps operation-config -o=go-template='{{index .data \"assessment-id\"}}'")

    elif key == "log_level":
        return run_cmd("kubectl get configmaps operation-config -o=go-template='{{index .data \"log-level\"}}'")

    elif key == "data_expiration_days":
        return run_cmd(
            "kubectl get configmaps operation-config -o=go-template='{{index .data \"data-expiration-days\"}}'"
        )

    elif key == "disable_slack_alerting":
        return run_cmd("kubectl get configmaps operation-config -o=go-template='{{index .data \"disable-slack-alerting\"}}'")

    elif key == "nemesis_http_server":
        return run_cmd("kubectl get configmaps operation-config -o=go-template='{{index .data \"nemesis-http-server\"}}'")

    elif key == "slack_channel":
        return run_cmd(
            "kubectl get configmaps operation-config -o=go-template='{{index .data \"slack-alert-channel\"}}'"
        )

    elif key == "slack_webhook":
        return run_cmd(
            "kubectl get secret operation-creds -o=go-template='{{index .data \"slack_web_hook\"}}' | base64 -d"
        )

    elif key == "basic_auth_password":
        return run_cmd(
            "kubectl get secret operation-creds -o=go-template='{{index .data \"basic-auth-password\"}}' | base64 -d"
        )

    elif key == "basic_auth_user":
        return run_cmd(
            "kubectl get secret operation-creds -o=go-template='{{index .data \"basic-auth-user\"}}' | base64 -d"
        )

    elif key == "elasticsearch_password":
        return run_cmd(
            "kubectl get secret elasticsearch-users -o=go-template='{{index .data \"password\"}}' | base64 -d"
        )

    elif key == "elasticsearch_user":
        return run_cmd(
            "kubectl get secret elasticsearch-users -o=go-template='{{index .data \"username\"}}' | base64 -d"
        )

    elif key == "grafana_password":
        return run_cmd(
            "kubectl get secret grafana-creds --namespace=monitoring -o=go-template='{{index .data \"username\"}}' | base64 -d"
        )

    elif key == "grafana_user":
        return run_cmd(
            "kubectl get secret grafana-creds --namespace=monitoring -o=go-template='{{index .data \"password\"}}' | base64 -d"
        )

    elif key == "postgres_user":
        return run_cmd(
            "kubectl get secret postgres-creds -o=go-template='{{index .data \"postgres-user\"}}' | base64 -d"
        )

    elif key == "postgres_password":
        return run_cmd(
            "kubectl get secret postgres-creds -o=go-template='{{index .data \"postgres-password\"}}' | base64 -d"
        )

    elif key == "dashboard_user":
        return run_cmd(
            "kubectl get secret dashboard-creds -o=go-template='{{index .data \"dashboard-user\"}}' | base64 -d"
        )

    elif key == "dashboard_password":
        return run_cmd(
            "kubectl get secret dashboard-creds -o=go-template='{{index .data \"dashboard-password\"}}' | base64 -d"
        )

    elif key == "dashboard_user":
        return run_cmd(
            "kubectl get secret dashboard-creds -o=go-template='{{index .data \"dashboard-user\"}}' | base64 -d"
        )

    elif key == "dashboard_password":
        return run_cmd(
            "kubectl get secret dashboard-creds -o=go-template='{{index .data \"dashboard-password\"}}' | base64 -d"
        )

    elif key == "pgadmin_email":
        return run_cmd(
            "kubectl get secret postgres-creds -o=go-template='{{index .data \"pgadmin-email\"}}' | base64 -d"
        )

    elif key == "pgadmin_password":
        return run_cmd(
            "kubectl get secret postgres-creds -o=go-template='{{index .data \"pgadmin-password\"}}' | base64 -d"
        )

    elif key == "rabbitmq_admin_user":
        return run_cmd(
            "kubectl get secret rabbitmq-creds -o=go-template='{{index .data \"rabbitmq-admin-user\"}}' | base64 -d"
        )

    elif key == "rabbitmq_admin_password":
        return run_cmd(
            "kubectl get secret rabbitmq-creds -o=go-template='{{index .data \"rabbitmq-admin-password\"}}' | base64 -d"
        )

    elif key == "rabbitmq_connectionuri":
        return run_cmd(
            "kubectl get secret rabbitmq-creds -o=go-template='{{index .data \"rabbitmq-connectionuri\"}}' | base64 -d"
        )

    elif key == "rabbitmq_erlang_cookie":
        return run_cmd(
            "kubectl get secret rabbitmq-creds -o=go-template='{{index .data \"rabbitmq-erlang-cookie\"}}' | base64 -d"
        )

    else:
        logger.error(f"Invalid config key: {key}")
        return None


def set_config_values(config_values):
    """Deletes all applicable secret/configmap values and resets them using the new values."""

    if any(v.is_set(config_value) for config_value in config_values):
        logger.info("New configuration:\n")

        for config_value in config_values:
            if v.is_set(config_value):
                logger.info("    {0:25} {1}".format(config_value, v.get(config_value)))

        continue_set_values = False
        if v.get("force"):
            continue_set_values = True
        else:
            prompt_input = input("\n[*] Continue? [Y/n] : ").strip().lower()
            if prompt_input == "y" or prompt_input == "":
                continue_set_values = True
                print()

        if continue_set_values:
            run_cmd("kubectl delete configmap aws-config")
            run_cmd(
                "kubectl create configmap aws-config"
                + f" --from-literal=aws-bucket={v.get('aws_bucket')}"
                + f" --from-literal=aws-default-region={v.get('aws_region')}"
                + f" --from-literal=aws-kms-key-alias={v.get('aws_kms_key_alias')}",
                True,
            )

            run_cmd("kubectl delete secret aws-creds")
            run_cmd(
                "kubectl create secret generic aws-creds"
                + f" --from-literal=aws_access_key_id={v.get('aws_access_key_id')}"
                + f" --from-literal=aws_secret_key={v.get('aws_secret_key')}",
                True,
            )

            run_cmd("kubectl delete secret minio-creds")
            run_cmd(
                "kubectl create secret generic minio-creds"
                + f" --from-literal=minio_root_user={v.get('minio_root_user')}"
                + f" --from-literal=minio_root_password={v.get('minio_root_password')}",
                True,
            )

            run_cmd("kubectl delete configmap operation-config")
            run_cmd(
                "kubectl create configmap operation-config"
                + f" --from-literal=slack-alert-channel={v.get('slack_channel')}"
                + f" --from-literal=disable-slack-alerting={v.get('disable_slack_alerting')}"
                + f" --from-literal=log-level={v.get('log_level')}"
                + f" --from-literal=assessment-id={v.get('assessment_id')}"
                + f" --from-literal=storage_provider={v.get('storage_provider')}"
                + f" --from-literal=minio_storage_size={v.get('minio_storage_size')}"
                + f" --from-literal=nemesis-http-server={v.get('nemesis_http_server')}"
                + f" --from-literal=data-expiration-days={v.get('data_expiration_days')}",
                True,
            )

            run_cmd("kubectl create namespace monitoring")

            run_cmd("kubectl delete configmap operation-config --namespace=monitoring")
            run_cmd(
                "kubectl create configmap operation-config --namespace=monitoring"
                + f" --from-literal=slack-alert-channel={v.get('slack_channel')}"
                + f" --from-literal=log-level={v.get('log_level')}"
                + f" --from-literal=assessment-id={v.get('assessment_id')}"
                + f" --from-literal=storage_provider={v.get('storage_provider')}"
                + f" --from-literal=minio_storage_size={v.get('minio_storage_size')}"
                + f" --from-literal=nemesis-http-server={v.get('nemesis_http_server')}"
                + f" --from-literal=data-expiration-days={v.get('data_expiration_days')}",
                True,
            )

            run_cmd("kubectl delete secret operation-creds")
            run_cmd(
                "kubectl create secret generic operation-creds"
                + f" --from-literal=slack_web_hook={v.get('slack_webhook')}"
                + f" --from-literal=basic-auth-user={v.get('basic_auth_user')}"
                + f" --from-literal=basic-auth-password={v.get('basic_auth_password')}"
            )

            run_cmd("kubectl delete secret basic-auth")
            encrypted = apr_md5_crypt.hash(v.get("basic_auth_password"))
            run_cmd(
                "kubectl create secret generic basic-auth"
                + f" --from-literal=auth='{v.get('basic_auth_user')}:{encrypted}'"
            )
            run_cmd("kubectl delete secret basic-auth -n monitoring")
            run_cmd(
                "kubectl create secret generic basic-auth -n monitoring"
                + f" --from-literal=auth='{v.get('basic_auth_user')}:{encrypted}'"
            )

            run_cmd("kubectl delete secret operation-creds --namespace=monitoring")
            run_cmd(
                "kubectl create secret generic operation-creds --namespace=monitoring"
                + f" --from-literal=slack_web_hook={v.get('slack_webhook')}"
                + f" --from-literal=basic-auth-user={v.get('basic_auth_user')}"
                + f" --from-literal=basic-auth-password={v.get('basic_auth_password')}"
            )

            run_cmd("kubectl delete secret grafana-creds --namespace=monitoring")
            run_cmd(
                "kubectl create secret generic grafana-creds --namespace=monitoring"
                + f" --from-literal=username={v.get('grafana_user')}"
                + f" --from-literal=password={v.get('grafana_password')}"
            )

            run_cmd("kubectl delete secret elasticsearch-users")
            run_cmd(
                "kubectl create secret generic elasticsearch-users"
                + f" --from-literal=username={v.get('elasticsearch_user')}"
                + f" --from-literal=password={v.get('elasticsearch_password')}"
                + f" --from-literal=roles=superuser"
            )

            run_cmd("kubectl delete secret postgres-creds")
            run_cmd(
                "kubectl create secret generic postgres-creds"
                + f" --from-literal=postgres-user={v.get('postgres_user')}"
                + f" --from-literal=postgres-password={v.get('postgres_password')}"
                + f" --from-literal=pgadmin-email={v.get('pgadmin_email')}"
                + f" --from-literal=pgadmin-password={v.get('pgadmin_password')}"
            )

            run_cmd("kubectl delete secret dashboard-creds")
            run_cmd(
                "kubectl create secret generic dashboard-creds"
                + f" --from-literal=dashboard-user={v.get('dashboard_user')}"
                + f" --from-literal=dashboard-password={v.get('dashboard_password')}"
            )

            run_cmd("kubectl delete secret fluentd-creds --namespace=kube-system")
            run_cmd(
                "kubectl create secret generic fluentd-creds --namespace=kube-system"
                + f" --from-literal=elasticsearch_username={v.get('elasticsearch_user')}"
                + f" --from-literal=elasticsearch_password={v.get('elasticsearch_password')}"
                + f" --from-literal=roles=superuser"
            )

            run_cmd("kubectl delete secret rabbitmq-creds")
            run_cmd(
                "kubectl create secret generic rabbitmq-creds"
                + f" --from-literal=rabbitmq-admin-user={v.get('rabbitmq_admin_user')}"
                + f" --from-literal=rabbitmq-admin-password={v.get('rabbitmq_admin_password')}"
                + f" --from-literal=rabbitmq-connectionuri={v.get('rabbitmq_connectionuri')}"
                + f" --from-literal=rabbitmq-erlang-cookie={v.get('rabbitmq_erlang_cookie')}"
            )

            # hack, but application not working through skaffold
            run_cmd(f"kubectl apply --server-side=true -f ./monitoring/grafana-dashboards.yaml")


######################################################
#
# Validation functions
#
######################################################
def ensure_command(command: str):
    logger.info("Checking for command: %s", command)
    exitcode, output = subprocess.getstatusoutput(command)

    if exitcode == 127:
        logger.error(f"'{command}' command not found. Please install 'kubectl' and try again.")
        sys.exit(1)

def validate_kubernetes():
    """Checks if kubernetes is running, and start minikube it if it's not."""

    logger.info("Validating k8s commands are available...")
    ensure_command("kubectl")
    ensure_command("helm")
    ensure_command("openssl version")

    exitcode, output = subprocess.getstatusoutput("kubectl cluster-info")
    if exitcode == 0:
        logger.info("kubectl configured to use existing cluster")
        return
    else:
        logger.info("No Kubernetes cluster found using kubectl, attempting to start Minikube")
        start_minikube()


def start_minikube():
    ensure_command("minikube")

    minikube_running = False
    exitcode, output = subprocess.getstatusoutput("minikube status")

    if "host: Running" in output[1]:
        minikube_running = True

    if not minikube_running:
        logger.info("Starting Minikube...")
        output = subprocess.getstatusoutput("minikube start --network-plugin=cni --cni=calico")
    else:
        logger.info("Minikube is already running")


def validate_config_values(config_keys):
    """
    If a value is not set in Vyper, this will attempt to pull the value
    from kubectl and set that in the Vyper config.

    If values are not set in either, an error message will display and the script
    will exist with code 1, with the exception of:
        - If "basic_auth_user" is not set, it will be set to "nemesis".
        - If "basic_auth_password" is not set, it will be set to 24 random characaters.
        - If "elasticsearch_user" is not set, it will be set to "nemesis".
        - If "elasticsearch_password" is not set, it will be set to 24 random characaters.
        - If "postgres_auth_user" is not set, it will be set to "nemesis".
        - If "postgres_auth_password" is not set, it will be set to 24 random characaters.
        - If "dashboard_auth_user" is not set, it will be set to "nemesis".
        - If "dashboard_auth_password" is not set, it will be set to 24 random characaters.
        - If "data_expiration_days" is not set, it will default to 100.
        - If "minio_root_user" is not set, it will default to "nemesis".
        - If "minio_root_password" is not set, it will be set to 24 random characaters.
        - If "storage_provider" is not set or is set to "minio", aws_* variables will be filled in with "not-applicable"
        - If "minio_storage_size" is not set it will be set to 30Gi.

    The end result should be a Vyper config populated with existing values where explictly supplied
    values are overwritten in the config. This is because we can't modify configmaps/secrets in
    kubectl directly, we first have to delete them, so we want to preserve existing values if possible
    in case we're overwriting just one value.
    """

    # if a storage provider is not set, assume minio
    if not v.get("storage_provider") or v.get("storage_provider") == "<no value>":
        storage_provider = get_kubectl_value("storage_provider")
        if storage_provider:
            v.set("storage_provider", storage_provider)
        else:
            v.set("storage_provider", "minio")

    if v.get("storage_provider") == "minio":
        if not v.get("aws_access_key_id"):
            v.set("aws_access_key_id", "not-applicable")
        if not v.get("aws_bucket"):
            v.set("aws_bucket", "not-applicable")
        if not v.get("aws_kms_key_alias"):
            v.set("aws_kms_key_alias", "not-applicable")
        if not v.get("aws_region"):
            v.set("aws_region", "not-applicable")
        if not v.get("aws_secret_key"):
            v.set("aws_secret_key", "not-applicable")
        if not v.get("minio_storage_size") or v.get("minio_storage_size") == "<no value>":
            v.set("minio_storage_size", "30Gi")
        if not v.get("minio_root_user") or v.get("minio_root_user") == "<no value>":
            minio_root_user = get_kubectl_value("minio_root_user")
            if minio_root_user:
                v.set("minio_root_user", minio_root_user)
            else:
                # set default username if not supplied or already set
                v.set("minio_root_user", "nemesis")
        if not v.get("minio_root_password") or v.get("minio_root_password") == "<no value>":
            minio_root_password = get_kubectl_value("minio_root_password")
            if minio_root_password:
                v.set("minio_root_password", minio_root_password)
            else:
                # set a random password if not supplied or already set
                v.set("minio_root_password", get_random_password(24))
    else:
        if not v.get("minio_root_user"):
            v.set("minio_root_user", "not-applicable")
        if not v.get("minio_root_password"):
            v.set("minio_root_password", "not-applicable")
        if not v.get("minio_storage_size"):
            v.set("minio_storage_size", "30Gi")

    if not v.get("force"):
        for config_key in config_keys:
            not_required_args = ["basic_auth_password", "data_expiration_days", "log_level", "pgadmin_email"]
            if config_key not in not_required_args:
                if not v.get(config_key):
                    # set the value for to config key if it already exists in Kubectl
                    config_value = get_kubectl_value(config_key)
                    if not config_value:
                        # otherwise prompt
                        config_value = input(f"\n[*] Please enter a value for '{config_key}' : ")
                    v.set(config_key, config_value)

    if not v.get("log_level") or v.get("log_level") == "<no value>":
        log_level = get_kubectl_value("log_level")
        if log_level:
            v.set("log_level", log_level)
        else:
            v.set("log_level", "INFO")

    if not v.get("basic_auth_user") or v.get("basic_auth_user") == "<no value>":
        basic_auth_kubectl = get_kubectl_value("basic_auth_user")
        if basic_auth_kubectl:
            v.set("basic_auth_user", basic_auth_kubectl)
        else:
            v.set("basic_auth_user", "nemesis")

    if not v.get("basic_auth_password") or v.get("basic_auth_password") == "<no value>":
        basic_auth_kubectl = get_kubectl_value("basic_auth_password")
        if basic_auth_kubectl:
            v.set("basic_auth_password", basic_auth_kubectl)
        else:
            # set a random basic auth password if not supplied or already set
            v.set("basic_auth_password", get_random_password(24))

    if not v.get("elasticsearch_user") or v.get("elasticsearch_user") == "<no value>":
        elasticsearch_user_kubectl = get_kubectl_value("elasticsearch_user")
        if elasticsearch_user_kubectl:
            v.set("elasticsearch_user", elasticsearch_user_kubectl)
        else:
            v.set("elasticsearch_user", "nemesis")

    if not v.get("elasticsearch_password") or v.get("elasticsearch_password") == "<no value>":
        elasticsearch_password_kubectl = get_kubectl_value("elasticsearch_password")
        if elasticsearch_password_kubectl:
            v.set("elasticsearch_password", elasticsearch_password_kubectl)
        else:
            # set a random elasticsearch password if not supplied or already set
            v.set("elasticsearch_password", get_random_password(24))

    if not v.get("postgres_user") or v.get("postgres_user") == "<no value>":
        postgres_user_kubectl = get_kubectl_value("postgres_user")
        if postgres_user_kubectl:
            v.set("postgres_user", postgres_user_kubectl)
        else:
            v.set("postgres_user", "nemesis")

    if not v.get("postgres_password") or v.get("postgres_password") == "<no value>":
        postgres_password_kubectl = get_kubectl_value("postgres_password")
        if postgres_password_kubectl:
            v.set("postgres_password", postgres_password_kubectl)
        else:
            # set a random password if not supplied or already set
            v.set("postgres_password", get_random_password(24))

    if not v.get("dashboard_user") or v.get("dashboard_user") == "<no value>":
        dashboard_user_kubectl = get_kubectl_value("dashboard_user")
        if dashboard_user_kubectl:
            v.set("dashboard_user", dashboard_user_kubectl)
        else:
            v.set("dashboard_user", "nemesis")

    if not v.get("dashboard_password") or v.get("dashboard_password") == "<no value>":
        dashboard_password_kubectl = get_kubectl_value("dashboard_password")
        if dashboard_password_kubectl:
            v.set("dashboard_password", dashboard_password_kubectl)
        else:
            # set a random password if not supplied or already set
            v.set("dashboard_password", get_random_password(24))

    if not v.get("pgadmin_email") or v.get("pgadmin_email") == "<no value>":
        pgadmin_email_kubectl = get_kubectl_value("pgadmin_email")
        if pgadmin_email_kubectl:
            v.set("pgadmin_email", pgadmin_email_kubectl)
        else:
            v.set("pgadmin_email", "nemesis@nemesis.com")

    if not v.get("pgadmin_password") or v.get("pgadmin_password") == "<no value>":
        pgadmin_password_kubectl = get_kubectl_value("pgadmin_password")
        if pgadmin_password_kubectl:
            v.set("pgadmin_password", pgadmin_password_kubectl)
        else:
            # set a random pgadmin password if not supplied or already set
            v.set("pgadmin_password", get_random_password(24))

    if not v.get("grafana_user") or v.get("grafana_user") == "<no value>":
        grafana_user_kubectl = get_kubectl_value("grafana_user")
        if grafana_user_kubectl:
            v.set("grafana_user", grafana_user_kubectl)
        else:
            v.set("grafana_user", "nemesis")

    if not v.get("grafana_password") or v.get("grafana_password") == "<no value>":
        grafana_password_kubectl = get_kubectl_value("grafana_password")
        if grafana_password_kubectl:
            v.set("grafana_password", grafana_password_kubectl)
        else:
            # set a random password if not supplied or already set
            v.set("grafana_password", get_random_password(24))

    if not v.get("data_expiration_days") or v.get("data_expiration_days") == "<no value>":
        data_expiration_days_kubectl = get_kubectl_value("data_expiration_days")
        if data_expiration_days_kubectl:
            v.set("data_expiration_days", data_expiration_days_kubectl)
        else:
            v.set("data_expiration_days", "100")

    if not v.get("rabbitmq_admin_user") or v.get("rabbitmq_admin_user") == "<no value>":
        rabbitmq_admin_user_kubectl = get_kubectl_value("rabbitmq_admin_user")
        if rabbitmq_admin_user_kubectl:
            v.set("rabbitmq_admin_user", rabbitmq_admin_user_kubectl)
        else:
            v.set("rabbitmq_admin_user", "nemesis")

    if not v.get("rabbitmq_admin_password") or v.get("rabbitmq_admin_password") == "<no value>":
        rabbitmq_admin_password_kubectl = get_kubectl_value("rabbitmq_admin_password")
        if rabbitmq_admin_password_kubectl:
            v.set("rabbitmq_admin_password", rabbitmq_admin_password_kubectl)
        else:
            # set a random password if not supplied or already set
            v.set("rabbitmq_admin_password", get_random_password(24))

    if not v.get("rabbitmq_connectionuri") or v.get("rabbitmq_connectionuri") == "<no value>":
        rabbitmq_connectionuri_kubectl = get_kubectl_value("rabbitmq_connectionuri")
        if rabbitmq_connectionuri_kubectl:
            v.set("rabbitmq_connectionuri", rabbitmq_connectionuri_kubectl)
        else:
            # set a uri from provided user/pass
            rabbitmq_user = v.get("rabbitmq_admin_user")
            rabbitmq_password = v.get("rabbitmq_admin_password")
            v.set("rabbitmq_connectionuri", f"amqp://{rabbitmq_user}:{rabbitmq_password}@nemesis-rabbitmq-svc:5672/")

    if not v.get("rabbitmq_erlang_cookie") or v.get("rabbitmq_erlang_cookie") == "<no value>":
        rabbitmq_erlang_cookie_kubectl = get_kubectl_value("rabbitmq_erlang_cookie")
        if rabbitmq_erlang_cookie_kubectl:
            v.set("rabbitmq_erlang_cookie", rabbitmq_erlang_cookie_kubectl)
        else:
            # set a random password if not supplied or already set
            v.set("rabbitmq_erlang_cookie", get_random_password(24))

    if not v.get("disable_slack_alerting") or v.get("disable_slack_alerting") == "<no value>":
        disable_slack_alerting = get_kubectl_value("disable_slack_alerting")
        if disable_slack_alerting:
            disable_slack_alerting = bool(disable_slack_alerting)
            v.set("disable_slack_alerting", disable_slack_alerting)
        else:
            v.set("disable_slack_alerting", "True")
    disable_slack_alerting = str(v.get("disable_slack_alerting"))
    if disable_slack_alerting.lower() not in ["true", "false"]:
        logger.error(f"The disable_slack_alerting argument must be either 'True' or 'False'. Supplied value: {disable_slack_alerting}")
        sys.exit(1)
    disable_slack_alerting = disable_slack_alerting.lower() == "true"

    if not v.get("slack_channel") or v.get("slack_channel") == "<no value>":
        slack_channel_kubectl = get_kubectl_value("slack_channel")
        if slack_channel_kubectl:
            v.set("slack_channel", slack_channel_kubectl)
        else:
            v.set("slack_channel", None)

    slack_channel = v.get("slack_channel")
    if not disable_slack_alerting:
        if slack_channel:
            if slack_channel[0] != "#":
                logger.error(f"The slack_channel argument must start with a '#'. Supplied value: {slack_channel}")
                sys.exit(1)
        else:
            logger.error(f"The slack_channel argument must be set if slack alerting is enabled.")
            sys.exit(1)

    if not v.get("slack_webhook") or v.get("slack_webhook") == "<no value>":
        slack_webhook_kubectl = get_kubectl_value("slack_webhook")
        if slack_webhook_kubectl:
            v.set("slack_webhook", slack_webhook_kubectl)
        else:
            v.set("slack_webhook", None)

    slack_webhook = v.get("slack_webhook")
    if not disable_slack_alerting and slack_webhook and slack_webhook[0:8] != "https://":
        logger.error(f"The slack_webhook argument must start with a 'https://'. Supplied value: {slack_webhook}")
        sys.exit(1)

    # make sure we have everything set
    all_values_set = True
    for config_key in config_keys:
        if not v.get(config_key) and not get_kubectl_value(config_key):
            if config_key == "slack_webhook" or config_key == "slack_channel":
                continue

            logger.error(f"\nRequired configuration key value '{config_key}' not supplied and not already present!\n")
            all_values_set = True

    if not all_values_set:
        sys.exit(1)


def validate_aws_resources():
    """Checks for the presence of the proper AWS resources, creating them if they're not present."""

    aws_access_key_id = v.get("aws_access_key_id")
    if not aws_access_key_id:
        logger.error("aws_access_key_id not set, aws validation can't proceed\n")
        sys.exit(1)

    aws_secret_key = v.get("aws_secret_key")
    if not aws_secret_key:
        logger.error("aws_secret_key not set, aws validation can't proceed\n")
        sys.exit(1)

    aws_region = v.get("aws_region")
    if not aws_region:
        logger.error("aws_region not set, aws validation can't proceed\n")
        sys.exit(1)

    aws_bucket = v.get("aws_bucket")
    if not aws_bucket:
        logger.error("aws_bucket not set, aws validation can't proceed\n")
        sys.exit(1)

    aws_kms_key_alias = v.get("aws_kms_key_alias")
    if not aws_kms_key_alias:
        logger.error("aws_kms_key_alias not set, aws validation can't proceed\n")
        sys.exit(1)

    assessment_id = v.get("assessment_id")
    if not assessment_id:
        logger.error("assessment_id not set, aws validation can't proceed\n")
        sys.exit(1)

    kms_client = boto3.client(
        "kms",
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_key,
        region_name=aws_region,
    )

    s3_client = boto3.client(
        "s3",
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_key,
        region_name=aws_region,
    )

    try:
        s3_client.head_bucket(Bucket=aws_bucket)
        logger.info(f"S3 bucket '{aws_bucket}' exists")
    except:
        if not v.get("force"):
            output = input(f"\n[*] S3 bucket '{aws_bucket}' does not exist, do you want to create it? [Y/n] ")

        if v.get("force") or output == "" or output.lower() == "y":
            # create the bucket with a 'private' ACL
            try:
                response = s3_client.create_bucket(
                    ACL="private",
                    Bucket=aws_bucket,
                )
            except Exception as e:
                logger.error(f"Error creating S3 bucket '{aws_bucket}' (bucket name is likely already taken) : {e}\n")
                sys.exit(1)

            # ensure the bucket/objects can't be public
            response = s3_client.put_public_access_block(
                Bucket=aws_bucket,
                PublicAccessBlockConfiguration={
                    "IgnorePublicAcls": True,
                },
            )
            # BlockPublicAcls / BlockPublicPolicy / RestrictPublicBuckets ?

            # ensure server side bucket encyption is enabled
            response = s3_client.put_bucket_encryption(
                Bucket=aws_bucket,
                ServerSideEncryptionConfiguration={
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256",
                            },
                        },
                    ]
                },
            )

            logger.info(f"S3 bucket key '{aws_bucket}' created!\n")

        else:
            logger.error(f"S3 bucket '{aws_bucket}' doesn't exist, file storage will not work!\n")
            sys.exit(1)

    # check if the KMS key already exists
    aws_kms_key_exists = False
    try:
        output = kms_client.describe_key(KeyId=f"alias/{aws_kms_key_alias}")
        aws_kms_key_state = output["KeyMetadata"]["KeyState"]
        aws_kms_key_exists = True
        logger.info(f"KMS key '{aws_kms_key_alias}' exists")
    except:
        pass

    if not aws_kms_key_exists:
        if not v.get("force"):
            output = input(f"\n[*] KMS key '{aws_kms_key_alias}' does not exist, do you want to create it? [Y/n] ")

        if v.get("force") or output == "" or output.lower() == "y":
            response = kms_client.create_key(Description=f"key for {assessment_id}")
            keyId = response["KeyMetadata"]["KeyId"]
            kms_client.create_alias(AliasName=f"alias/{aws_kms_key_alias}", TargetKeyId=keyId)
            logger.info(f"KMS key '{aws_kms_key_alias}' (ID {keyId}) created!\n")
        else:
            logger.error(f"KMS key '{aws_kms_key_alias}' doesn't exist, file encryption will not work!\n")
            sys.exit(1)
    elif aws_kms_key_state != "Enabled":
        logger.error(f"Key state for KMS key '{aws_kms_key_alias}' is '{aws_kms_key_state}', encryption will not work!")
        sys.exit(1)


def create_ingress_controller():

    # Some jank to check if the nginx controller is installed in Kubernetes
    exitcode, output = subprocess.getstatusoutput("kubectl get --raw /apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations  | grep 'validate.nginx.ingress.kubernetes.io'")
    if exitcode == 0:
        logger.info("Ingress controller already installed, skipping")
        return

    # create local self-signed certs and store them as a secret for ingress auth
    logger.info("Creating self-signed SSL certificates")
    run_cmd(
        'openssl req -x509 -newkey rsa:4096 -sha256 -nodes -keyout /tmp/tls.key -out /tmp/tls.crt -subj "/CN=nemesis.local" -days 365 -addext "subjectAltName = DNS:nemesis.local"',
        show_error=True,
    )
    run_cmd("kubectl create secret tls nemesis-ingress-tls --cert=/tmp/tls.crt --key=/tmp/tls.key")
    run_cmd("kubectl create secret tls nemesis-ingress-tls --cert=/tmp/tls.crt --key=/tmp/tls.key -n monitoring")

    logger.info(f"Installing ingress-nginx controller using helm")
    run_cmd(
        "helm upgrade --install ingress-nginx ingress-nginx"
        " --repo https://kubernetes.github.io/ingress-nginx"
        " --namespace ingress-nginx"
        " --create-namespace"
        " --set prometheus.create=true"
        " --set prometheus.port=9113"
        f" --set tcp.5044=\"default/nemesis-ls-beats:5044\"",
        show_error=True,
    )


def create_minio():
    # check if the chart is already installed
    exitcode, output = subprocess.getstatusoutput("helm status minio")
    if exitcode == 0:
        logger.info("Minio chart already installed, skipping")
        return

    logger.info("Installing the Minio operator using helm")
    run_cmd("helm repo add elastic https://helm.elastic.co")

    # minio_storage_size = v.get("minio_storage_size")
    minio_root_user = v.get("minio_root_user")
    minio_root_password = v.get("minio_root_password")
    minio_storage_size = v.get("minio_storage_size")
    # nemesis_http_server = v.get("nemesis_http_server").rstrip("/")

    run_cmd("helm repo add bitnami https://charts.bitnami.com/bitnami")
    run_cmd("helm repo update")
    run_cmd(
        "helm install minio bitnami/minio "
        "--set 'extraEnvVars[0].name=MINIO_BROWSER_LOGIN_ANIMATION' --set 'extraEnvVars[0].value=\"off\"' "
        f"--set persistence.size={minio_storage_size} "
        f"--set auth.rootUser={minio_root_user} "
        f"--set auth.rootPassword='{minio_root_password}' ")
        # "--set 'extraEnvVars[0].name=MINIO_CONSOLE_SUBPATH' --set 'extraEnvVars[0].value=\"/minio/\"' "
        # f"--set 'extraEnvVars[1].name=MINIO_BROWSER_REDIRECT_URL' --set 'extraEnvVars[1].value=\"{nemesis_http_server}/minio/\"'",)

def create_elastic_operator():
    # Check if the elastic operator is already installed
    exitcode, output = subprocess.getstatusoutput("kubectl get crds | grep 'k8s.elastic.co'")
    if exitcode == 0:
        logger.info("ECK operator already installed, skipping")
        return

    logger.info("Installing the ECK operator using helm")
    run_cmd("helm repo add elastic https://helm.elastic.co")
    run_cmd("helm repo update")

    run_cmd(
        "helm install elastic-operator elastic/eck-operator"
        " --namespace elastic-system"
        " --create-namespace"
        " --set managedNamespaces='{default}'"
    )


def create_metrics_server():
    exitcode, output = subprocess.getstatusoutput("kubectl get pods -A | grep 'metrics-server'")
    if exitcode == 0:
        logger.info("Metrics Server already installed, skipping")
        return

    # create local self-signed certs and store them as a secret for ingress auth
    logger.info("Creating metrics server")
    dir = os.path.realpath(os.path.dirname(__file__))
    run_cmd(f"kubectl apply -f '{dir}/kubernetes/metrics-server/metrics-server.yaml'")


if __name__ == "__main__":
    print_logo()

    # 1. parse any environment variables first
    config_values = [
        "aws_region",
        "aws_bucket",
        "aws_kms_key_alias",
        "aws_access_key_id",
        "aws_secret_key",
        "minio_root_user",
        "minio_root_password",
        "minio_storage_size",
        "storage_provider",
        "assessment_id",
        "nemesis_http_server",
        "data_expiration_days",
        "log_level",
        "disable_slack_alerting",
        "slack_channel",
        "slack_webhook",
        "basic_auth_password",
        "basic_auth_user",
        "elasticsearch_password",
        "elasticsearch_user",
        "postgres_user",
        "postgres_password",
        "dashboard_user",
        "dashboard_password",
        "pgadmin_email",
        "pgadmin_password",
        "grafana_password",
        "grafana_user",
        "rabbitmq_admin_user",
        "rabbitmq_admin_password",
        "rabbitmq_erlang_cookie",
    ]

    extra_settings = ["nemesis_config", "force"]

    env_vars = config_values + extra_settings

    for env_var in env_vars:
        v.bind_env(env_var)
    v.automatic_env()

    parser = argparse.ArgumentParser(description="Nemesis settings")

    # args specific to this program
    parser.add_argument(
        "--config", "-c", default="nemesis.config", type=str, help="Nemesis config (default: nemesis.config)"
    )
    parser.add_argument("--force", "-f", action=argparse.BooleanOptionalAction, help="Don't prompt for any input")

    # aws configs
    parser.add_argument("--aws_region", "--aws-region", "--region", type=str, help="AWS region (default: us-east-1)")
    parser.add_argument("--aws_bucket", "--aws-bucket", "--bucket", type=str, help="AWS S3 bucket name")
    parser.add_argument("--aws_kms_key_alias", "--aws-kms-key-alias", "--kms", type=str, help="AWS KMS key alias")
    parser.add_argument(
        "--aws_access_key_id", "--aws-access-key-id", "--key_id", "--key-id", type=str, help="AWS access key ID"
    )
    parser.add_argument(
        "--aws_secret_key", "--aws-secret-key", "--secret_key", "--secret-key", type=str, help="AWS secret key value"
    )

    # minio configs
    parser.add_argument("--minio_root_user", "--minio-root-user", type=str, help="Minio root user")
    parser.add_argument("--minio_root_password", "--minio-root-password", type=str, help="Minio root password")
    parser.add_argument("--minio_storage_size", "--minio-storage-size", type=str, help="Size of Minio persistent storage")
    parser.add_argument("--storage_provider", "--storage-provider", type=str, choices=["s3", "mimio"], help="Storage provider to use")

    # operation configs
    parser.add_argument("--assessment_id", "--assessment-id", type=str, help="Asessment ID")
    parser.add_argument("--nemesis_http_server", "--ip", type=str, help="Nemesis frontend HTTP server endpoint. Format: http://<SERVER>:<PORT>")
    parser.add_argument(
        "--data_expiration_days", "--exp", type=int, help="Days after ingestion to set data to expire (default: 100)"
    )
    parser.add_argument("--log_level", "--log", type=str, help="Level of logging (default: info)")
    parser.add_argument("--disable_slack_alerting", type=str, help="Should slack alerting be disabled? Values: True/False", required=False)
    parser.add_argument("--slack_channel", "--channel", type=str, help="Slack channel name for alerting.", required=False)
    parser.add_argument("--slack_webhook", "--webhook", type=str, help="Slack https://... webhook for alerting.", required=False)
    parser.add_argument("--basic_auth_user", "--user", type=str, help="User to use for basic auth to the web-api")
    parser.add_argument(
        "--basic_auth_password", "--password", type=str, help="Password to use for basic auth to the web-api"
    )
    parser.add_argument("--elasticsearch_user", "--es_user", type=str, help="Username for Elasticsearch/Kibana")
    parser.add_argument("--elasticsearch_password", "--es_password", type=str, help="Password for Elasticsearch/Kibana")
    parser.add_argument("--postgres_user", "--pg_user", type=str, help="Username for Postgres")
    parser.add_argument("--postgres_password", "--pg_password", type=str, help="Password for Postgres")
    parser.add_argument("--dashboard_user", type=str, help="Username for the Nemesis dashboard")
    parser.add_argument("--dashboard_password", type=str, help="Password for the Nemesis dashboard")
    parser.add_argument("--pgadmin_email", "--pgemail", type=str, help="Email (username) for pgAdmin")
    parser.add_argument("--pgadmin_password", "--pgpassword", type=str, help="Password for pgAdmin")
    parser.add_argument("--grafana_user", "--guser", type=str, help="Username for Grafana")
    parser.add_argument("--grafana_password", "--gpassword", type=str, help="Password for Grafana")
    parser.add_argument("--rabbitmq_admin_user", "--ruser", type=str, help="Admin username for RabbitMQ")
    parser.add_argument("--rabbitmq_admin_password", "--rpassword", type=str, help="Admin password for RabbitMQ")
    parser.add_argument("--rabbitmq_erlang_cookie", "--rcookie", type=str, help="Erlang cookie for RabbitMQ clusters")

    args = parser.parse_args()

    # 2. next parse values from a local yaml config (if present and non-empty)
    #   the config location can be set with --config=X, -c=X, or the NEMESIS_CONFIG env variable
    nemesis_config = v.get("nemesis_config") if v.get("nemesis_config") else args.config
    if os.path.exists(nemesis_config) and os.path.getsize(nemesis_config) > 0:
        v.set_config_type("yaml")
        with open(nemesis_config) as f:
            try:
                v.read_config(f.read())
                logger.info(f"Parsed config file: {nemesis_config}")
            except Exception as e:
                logger.error(f"Excepting parsing config '{nemesis_config}' : {e}\n")
                sys.exit(1)

    # 3. parse cli arguments override and have them take precedence
    v.bind_args(parser)

    # make sure kubernetes is running
    validate_kubernetes()
    validate_config_values(config_values)
    set_config_values(config_values)
    if v.get("storage_provider") == "s3":
        validate_aws_resources()
        # ensure minio is removed
        run_cmd("helm uninstall minio")
    elif v.get("storage_provider") == "minio":
        create_minio()
    create_ingress_controller()
    create_elastic_operator()
    create_metrics_server()

    logger.info("Configuration set")

    logger.info(
        f"Nemesis basic auth credentials: `{get_kubectl_value('basic_auth_user')}:{get_kubectl_value('basic_auth_password')}`"
    )

    logger.info("If settings were changed, you may need to restart minikube with: `minikube stop && minikube start`")
    logger.info(
        "You can start the backend infrastructure in development mode with `./scripts/infra_start.sh`"
    )
    logger.info(
        "You can start the main processing services in development mode with `./scripts/services_start.sh`"
    )
    logger.info(
        "For non-development execution, run `skaffold run --port-forward`\n"
    )
