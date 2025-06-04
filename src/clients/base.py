from abc import ABC
import logging
import warnings
from typing import Dict, Optional, Tuple

import boto3
from botocore.exceptions import ProfileNotFound, NoCredentialsError, PartialCredentialsError
from elasticsearch import Elasticsearch
import httpx
from opensearchpy import OpenSearch
import botocore.auth
import botocore.awsrequest
import botocore.credentials
from urllib.parse import urlparse, urlsplit
import requests.auth

logger = logging.getLogger(__name__)

def _get_sigv4_details(config: Dict) -> Optional[Dict]:
    aws_access_key_id = config.get("aws_access_key_id")
    aws_secret_access_key = config.get("aws_secret_access_key")
    aws_session_token = config.get("aws_session_token")
    region_name = config.get("region_name")
    aws_profile_name = config.get("aws_profile_name")
    aws_service_name = config.get("aws_service_name", "es")

    source_log_msg = ""

    if aws_access_key_id and aws_secret_access_key:
        if not region_name:
            logger.error("SigV4: Direct AWS keys provided but 'region_name' is missing.")
            return None
        source_log_msg = "direct keys"
        return {
            "access_key": aws_access_key_id,
            "secret_key": aws_secret_access_key,
            "token": aws_session_token,
            "region": region_name,
            "service": aws_service_name,
            "source_log_msg": source_log_msg
        }

    if aws_profile_name:
        source_log_msg = f"AWS profile '{aws_profile_name}'"
        logger.info(f"SigV4: Attempting to use {source_log_msg}.")
        try:
            session = boto3.Session(profile_name=aws_profile_name)
            boto_credentials = session.get_credentials()
            if boto_credentials:
                frozen_creds = boto_credentials.get_frozen_credentials()
                final_region = region_name or session.region_name
                if not final_region:
                    logger.error(f"SigV4: Using {source_log_msg}, but region could not be determined (config or profile).")
                    return None
                return {
                    "access_key": frozen_creds.access_key,
                    "secret_key": frozen_creds.secret_key,
                    "token": frozen_creds.token,
                    "region": final_region,
                    "service": aws_service_name,
                    "source_log_msg": source_log_msg
                }
            else:
                logger.warning(f"SigV4: Profile '{aws_profile_name}' did not yield credentials.")
        except ProfileNotFound:
            logger.warning(f"SigV4: Profile '{aws_profile_name}' not found.")
        except (NoCredentialsError, PartialCredentialsError) as e:
            logger.warning(f"SigV4: Error getting credentials from profile '{aws_profile_name}': {e}")

    current_attempt_source_msg = "default Boto3 chain (environment/EC2 role/etc.)"
    if aws_profile_name:
        logger.info(f"SigV4: Profile '{aws_profile_name}' did not yield credentials or failed, attempting fallback to {current_attempt_source_msg}.")
    else:
        logger.info(f"SigV4: Attempting to use {current_attempt_source_msg}.")

    source_log_msg = current_attempt_source_msg
    try:
        session = boto3.Session()
        boto_credentials = session.get_credentials()
        if boto_credentials:
            frozen_creds = boto_credentials.get_frozen_credentials()
            final_region = region_name or session.region_name
            if not final_region:
                logger.error(f"SigV4: Using {source_log_msg}, but region could not be determined (config or default session).")
                return None
            return {
                "access_key": frozen_creds.access_key,
                "secret_key": frozen_creds.secret_key,
                "token": frozen_creds.token,
                "region": final_region,
                "service": aws_service_name,
                "source_log_msg": source_log_msg
            }
        else:
             logger.warning(f"SigV4: {source_log_msg} did not yield credentials.")
    except (NoCredentialsError, PartialCredentialsError) as e:
        logger.warning(f"SigV4: Error getting credentials from {source_log_msg}: {e}")
    except Exception as e:
        logger.error(f"SigV4: Unexpected error initializing Boto3 session for {source_log_msg}: {e}")
    return None

class BotocoreSigV4Auth(requests.auth.AuthBase):
    def __init__(self, access_key: str, secret_key: str, session_token: Optional[str], region: str, service: str):
        self.credentials = botocore.credentials.Credentials(
            access_key=access_key, secret_key=secret_key, token=session_token)
        self.region = region
        self.service = service
        self.sigv4 = botocore.auth.SigV4Auth(self.credentials, self.service, self.region)

    def __call__(self, r: requests.PreparedRequest):
        aws_request = botocore.awsrequest.AWSRequest(
            method=r.method.upper(), url=r.url, data=r.body, headers=dict(r.headers))
        self.sigv4.add_auth(aws_request)
        r.headers.update(aws_request.headers)
        return r

class SearchClientBase(ABC):
    def __init__(self, config: Dict, engine_type: str):
        self.logger = logger
        self.config = config
        self.engine_type = engine_type
        
        hosts = config.get("hosts")
        username = config.get("username")
        password = config.get("password")
        verify_certs = config.get("verify_certs", False)
        
        sigv4_details = _get_sigv4_details(config)

        if not verify_certs:
            warnings.filterwarnings("ignore", message=".*verify_certs=False is insecure.*")
            warnings.filterwarnings("ignore", message=".*Unverified HTTPS request is being made to host.*")
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except ImportError:
                pass
        
        auth_instance = None
        log_message_suffix = ""
        if sigv4_details:
            auth_instance = BotocoreSigV4Auth(
                access_key=sigv4_details["access_key"], secret_key=sigv4_details["secret_key"],
                session_token=sigv4_details["token"], region=sigv4_details["region"],
                service=sigv4_details["service"])
            log_message_suffix = f"using SigV4 ({sigv4_details['source_log_msg']}) for service {sigv4_details['service']} in region {sigv4_details['region']}"

        if engine_type == "elasticsearch":
            if auth_instance:
                self.client = Elasticsearch(
                    hosts=hosts, http_auth=auth_instance, verify_certs=verify_certs, use_ssl=True)
                self.logger.info(f"Elasticsearch client initialized {log_message_suffix} for hosts: {hosts}")
            elif username and password:
                self.client = Elasticsearch(
                    hosts=hosts, basic_auth=(username, password), verify_certs=verify_certs)
                self.logger.info(f"Elasticsearch client initialized with basic auth for hosts: {hosts}")
            else:
                self.client = Elasticsearch(hosts=hosts, verify_certs=verify_certs)
                self.logger.info(f"Elasticsearch client initialized with no auth for hosts: {hosts}")
        elif engine_type == "opensearch":
            if auth_instance:
                self.client = OpenSearch(
                    hosts=hosts, http_auth=auth_instance, use_ssl=True, verify_certs=verify_certs)
                self.logger.info(f"OpenSearch client initialized {log_message_suffix} for hosts: {hosts}")
            elif username and password:
                self.client = OpenSearch(
                    hosts=hosts, http_auth=(username, password), verify_certs=verify_certs)
                self.logger.info(f"OpenSearch client initialized with basic auth for hosts: {hosts}")
            else:
                self.client = OpenSearch(hosts=hosts, verify_certs=verify_certs)
                self.logger.info(f"OpenSearch client initialized with no auth for hosts: {hosts}")
        else:
            raise ValueError(f"Unsupported engine type: {engine_type}")

        base_url = hosts[0] if isinstance(hosts, list) else hosts
        self.general_client = GeneralRestClient(base_url=base_url, config=config, verify_certs=verify_certs)

class SigV4Auth(httpx.Auth):
    def __init__(self, access_key: str, secret_key: str, session_token: Optional[str], region: str, service: str):
        self.credentials = botocore.credentials.Credentials(
            access_key=access_key, secret_key=secret_key, token=session_token)
        self.region = region
        self.service = service
        self.sigv4_auth_object = botocore.auth.SigV4Auth(self.credentials, self.service, self.region)

    def auth_flow(self, request: httpx.Request):
        aws_request = botocore.awsrequest.AWSRequest(
            method=request.method, url=str(request.url), data=request.content, headers=dict(request.headers))
        self.sigv4_auth_object.add_auth(aws_request)
        request.headers.update(aws_request.headers)
        yield request

class GeneralRestClient:
    def __init__(self, base_url: str, config: Dict, verify_certs: bool = True):
        self.logger = logger
        self.base_url = base_url.rstrip("/")
        self.verify_certs = verify_certs
        self.auth = None

        sigv4_details = _get_sigv4_details(config)

        if sigv4_details:
            self.auth = SigV4Auth(
                access_key=sigv4_details["access_key"], secret_key=sigv4_details["secret_key"],
                session_token=sigv4_details["token"], region=sigv4_details["region"],
                service=sigv4_details["service"])
            self.logger.info(f"GeneralRestClient initialized with SigV4 ({sigv4_details['source_log_msg']}) for service {sigv4_details['service']} in region {sigv4_details['region']} for base_url: {self.base_url}")
        else:
            username = config.get("username")
            password = config.get("password")
            if username and password:
                self.auth = httpx.BasicAuth(username, password)
                self.logger.info(f"GeneralRestClient initialized with Basic Auth for base_url: {self.base_url}")
            else:
                self.logger.info(f"GeneralRestClient initialized with no auth for base_url: {self.base_url}")

    def request(self, method, path, params=None, body=None):
        url = f"{self.base_url}/{path.lstrip('/')}"
        with httpx.Client(verify=self.verify_certs, auth=self.auth) as client:
            resp = client.request(method=method.upper(), url=url, params=params, json=body)
            resp.raise_for_status()
            ct = resp.headers.get("content-type", "")
            if ct.startswith("application/json"):
                return resp.json()
            return resp.text
