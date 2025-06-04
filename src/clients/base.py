from abc import ABC
import logging
import warnings
from typing import Dict, Optional

from elasticsearch import Elasticsearch
import httpx
from opensearchpy import OpenSearch
import botocore.auth
import botocore.awsrequest
import botocore.credentials
from urllib.parse import urlsplit
import requests.auth

logger = logging.getLogger(__name__)

class BotocoreSigV4Auth(requests.auth.AuthBase):
    def __init__(self, access_key: str, secret_key: str, session_token: Optional[str], region: str, service: str):
        self.credentials = botocore.credentials.Credentials(
            access_key=access_key,
            secret_key=secret_key,
            token=session_token
        )
        self.region = region
        self.service = service
        self.sigv4 = botocore.auth.SigV4Auth(self.credentials, self.service, self.region)

    def __call__(self, r: requests.PreparedRequest):
        parsed_url = urlsplit(r.url)
        # path = parsed_url.path if parsed_url.path else '/' # Not strictly needed by AWSRequest
        aws_request = botocore.awsrequest.AWSRequest(
            method=r.method.upper(),
            url=r.url,
            data=r.body,
            headers=dict(r.headers)
        )
        self.sigv4.add_auth(aws_request)
        r.headers.update(aws_request.headers)
        return r

class SigV4Auth(httpx.Auth): # For GeneralRestClient (httpx)
    def __init__(self, access_key: str, secret_key: str, session_token: Optional[str], region: str, service: str):
        self.credentials = botocore.credentials.Credentials(
            access_key=access_key,
            secret_key=secret_key,
            token=session_token
        )
        self.region = region
        self.service = service
        # Store the SigV4Auth object, not just credentials
        self.sigv4_auth_object = botocore.auth.SigV4Auth(self.credentials, self.service, self.region)


    def auth_flow(self, request: httpx.Request):
        aws_request = botocore.awsrequest.AWSRequest(
            method=request.method,
            url=str(request.url),
            data=request.content,
            headers=dict(request.headers)
        )
        self.sigv4_auth_object.add_auth(aws_request) # Use the stored object
        request.headers.update(aws_request.headers)
        yield request

class SearchClientBase(ABC):
    def __init__(self, config: Dict, engine_type: str):
        self.logger = logger
        self.config = config
        self.engine_type = engine_type
        
        hosts = config.get("hosts")
        username = config.get("username")
        password = config.get("password")
        verify_certs = config.get("verify_certs", False)

        aws_access_key_id = config.get("aws_access_key_id")
        aws_secret_access_key = config.get("aws_secret_access_key")
        aws_session_token = config.get("aws_session_token")
        region_name = config.get("region_name")
        aws_service_name = config.get("aws_service_name", "es")

        auth_instance = None
        log_message_suffix = ""

        if aws_access_key_id and aws_secret_access_key and region_name:
            auth_instance = BotocoreSigV4Auth(
                access_key=aws_access_key_id,
                secret_key=aws_secret_access_key,
                session_token=aws_session_token,
                region=region_name,
                service=aws_service_name
            )
            log_message_suffix = f"using SigV4 (direct keys) for service {aws_service_name} in region {region_name}"
        
        if not verify_certs:
            warnings.filterwarnings("ignore", message=".*verify_certs=False is insecure.*")
            warnings.filterwarnings("ignore", message=".*Unverified HTTPS request is being made to host.*")
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except ImportError:
                pass
        
        if engine_type == "elasticsearch":
            if auth_instance:
                self.client = Elasticsearch(
                    hosts=hosts, http_auth=auth_instance,
                    verify_certs=verify_certs, use_ssl=True)
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
                    hosts=hosts, http_auth=auth_instance,
                    use_ssl=True, verify_certs=verify_certs)
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
        # Pass individual credential components to GeneralRestClient for this stage
        self.general_client = GeneralRestClient(
            base_url=base_url,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            region_name=region_name,
            aws_service_name=aws_service_name,
            username=username,
            password=password,
            verify_certs=verify_certs
        )

class GeneralRestClient:
    def __init__(self, base_url: str,
                 aws_access_key_id: Optional[str] = None,
                 aws_secret_access_key: Optional[str] = None,
                 aws_session_token: Optional[str] = None,
                 region_name: Optional[str] = None,
                 aws_service_name: str = "es",
                 username: Optional[str] = None,
                 password: Optional[str] = None,
                 verify_certs: bool = True):
        self.logger = logger
        self.base_url = base_url.rstrip("/")
        self.verify_certs = verify_certs
        self.auth = None

        if aws_access_key_id and aws_secret_access_key and region_name:
            self.auth = SigV4Auth( # HttpxSigV4Auth
                access_key=aws_access_key_id,
                secret_key=aws_secret_access_key,
                session_token=aws_session_token,
                region=region_name,
                service=aws_service_name
            )
            self.logger.info(f"GeneralRestClient initialized with AWS SigV4 Auth (direct keys) for service {aws_service_name} in region {region_name} for base_url: {self.base_url}")
        elif username and password:
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
