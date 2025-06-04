import unittest
from unittest.mock import patch, MagicMock, ANY
import sys

# Import the functions and classes to be tested
from src.clients.base import (
    SearchClientBase,
    GeneralRestClient,
    ElasticsearchSigV4Auth,
    OpenSearchSigV4Auth,
    HttpSigV4Auth as HttpxSigV4Auth,
    _get_sigv4_details
)

# Import necessary for mocking and type checking
import requests
import httpx
import boto3
from botocore.exceptions import ProfileNotFound, NoCredentialsError, PartialCredentialsError
import botocore.awsrequest
import botocore.auth
import botocore.credentials

_ORIGINAL_BOTO3_SESSION = boto3.Session

class TestGetSigV4Details(unittest.TestCase):
    def setUp(self):
        self.base_aws_config = {
            "aws_access_key_id": "direct_ak", "aws_secret_access_key": "direct_sk",
            "aws_session_token": "direct_tk", "region_name": "direct_region",
            "aws_service_name": "es",
        }

    @patch('src.clients.base.boto3.Session')
    def test_direct_keys_used(self, MockBotoSession):
        details = _get_sigv4_details(self.base_aws_config)
        self.assertIsNotNone(details)
        self.assertEqual(details["access_key"], "direct_ak")
        self.assertEqual(details["source_log_msg"], "direct keys")
        MockBotoSession.assert_not_called()

    @patch('src.clients.base.boto3.Session')
    def test_direct_keys_no_region_fails(self, MockBotoSession):
        config = {k: v for k, v in self.base_aws_config.items() if k != "region_name"}
        details = _get_sigv4_details(config)
        self.assertIsNone(details)

    @patch('src.clients.base.boto3.Session')
    def test_profile_used_and_region_from_profile(self, MockBotoSession):
        mock_session_instance = MagicMock()
        mock_session_instance.region_name = 'profile_region'
        mock_credentials = MagicMock()
        mock_frozen_credentials = MagicMock(access_key='profile_ak', secret_key='profile_sk', token='profile_tk')
        mock_credentials.get_frozen_credentials.return_value = mock_frozen_credentials
        mock_session_instance.get_credentials.return_value = mock_credentials
        MockBotoSession.return_value = mock_session_instance
        config = {"aws_profile_name": "test_profile", "aws_service_name": "aoss"}
        details = _get_sigv4_details(config)
        self.assertIsNotNone(details)
        MockBotoSession.assert_called_once_with(profile_name="test_profile")
        self.assertEqual(details["access_key"], "profile_ak")
        self.assertEqual(details["region"], "profile_region")
        self.assertEqual(details["service"], "aoss")
        self.assertEqual(details["source_log_msg"], "AWS profile 'test_profile'")

    @patch('src.clients.base.boto3.Session')
    def test_profile_with_config_region_override(self, MockBotoSession):
        mock_session_instance = MagicMock()
        mock_session_instance.region_name = 'profile_region_ignored'
        mock_credentials = MagicMock(); mock_frozen_credentials = MagicMock(access_key='pk', secret_key='ps', token='pt')
        mock_credentials.get_frozen_credentials.return_value = mock_frozen_credentials
        mock_session_instance.get_credentials.return_value = mock_credentials
        MockBotoSession.return_value = mock_session_instance
        config = {"aws_profile_name": "test_profile", "region_name": "config_region_override"}
        details = _get_sigv4_details(config)
        self.assertEqual(details["region"], "config_region_override")

    @patch('src.clients.base.boto3.Session')
    def test_profile_not_found_falls_back_to_default_chain(self, MockBotoSession):
        mock_default_session = MagicMock(); mock_default_session.region_name = 'default_r'
        mock_default_creds = MagicMock(); mock_default_frozen = MagicMock(access_key='dk', secret_key='ds', token='dt')
        mock_default_creds.get_frozen_credentials.return_value = mock_default_frozen
        mock_default_session.get_credentials.return_value = mock_default_creds
        MockBotoSession.side_effect = [ProfileNotFound(profile="test_profile"), mock_default_session]
        config = {"aws_profile_name": "test_profile"}
        details = _get_sigv4_details(config)
        self.assertIsNotNone(details)
        self.assertEqual(details["access_key"], "dk")
        self.assertEqual(details["source_log_msg"], "default Boto3 chain (environment/EC2 role/etc.)")

    @patch('src.clients.base.boto3.Session')
    def test_default_chain_used(self, MockBotoSession):
        mock_session_instance = MagicMock(); mock_session_instance.region_name = 'default_r'
        mock_creds = MagicMock(); mock_frozen = MagicMock(access_key='dk', secret_key='ds', token='dt')
        mock_creds.get_frozen_credentials.return_value = mock_frozen
        mock_session_instance.get_credentials.return_value = mock_creds
        MockBotoSession.return_value = mock_session_instance
        details = _get_sigv4_details({})
        self.assertIsNotNone(details)
        self.assertEqual(details["access_key"], "dk")

    @patch('src.clients.base.boto3.Session')
    def test_default_chain_no_region_fails(self, MockBotoSession):
        mock_session_instance = MagicMock(); mock_session_instance.region_name = None
        mock_creds = MagicMock(); mock_frozen = MagicMock(access_key='dk', secret_key='ds', token='dt')
        mock_creds.get_frozen_credentials.return_value = mock_frozen
        mock_session_instance.get_credentials.return_value = mock_creds
        MockBotoSession.return_value = mock_session_instance
        details = _get_sigv4_details({})
        self.assertIsNone(details)

    @patch('src.clients.base.boto3.Session')
    def test_no_credentials_anywhere_returns_none(self, MockBotoSession):
        mock_session_instance = MagicMock()
        mock_session_instance.get_credentials.return_value = None
        mock_session_instance.region_name = 'some-region'
        MockBotoSession.return_value = mock_session_instance
        details = _get_sigv4_details({})
        self.assertIsNone(details)

class TestClientInitialization(unittest.TestCase):
    def setUp(self):
        self.base_config = {"hosts": ["http://localhost:9200"], "verify_certs": False}
        self.basic_auth_creds = {"username": "user", "password": "password"}
        self.sample_sigv4_details_from_helper = {
            "access_key": "mock_ak", "secret_key": "mock_sk", "token": "mock_tk",
            "region": "mock_region", "service": "es", "source_log_msg": "mock_source"
        }
        self.expected_auth_constructor_args = {
            "access_key": "mock_ak", "secret_key": "mock_sk", "session_token": "mock_tk",
            "region": "mock_region", "service": "es"
        }

    @patch('src.clients.base.ElasticsearchSigV4Auth')
    @patch('src.clients.base.Elasticsearch')
    @patch('src.clients.base._get_sigv4_details')
    def test_scb_elasticsearch_uses_sigv4_from_helper(self, mock_get_details, MockElasticsearch, MockElasticsearchAuth):
        mock_get_details.return_value = self.sample_sigv4_details_from_helper
        mock_auth_instance = MockElasticsearchAuth.return_value
        client = SearchClientBase(self.base_config, engine_type="elasticsearch")
        self.assertEqual(mock_get_details.call_count, 2)
        MockElasticsearchAuth.assert_called_once_with(**self.expected_auth_constructor_args)
        MockElasticsearch.assert_called_once_with(
            hosts=['http://localhost:9200'],
            http_auth=mock_auth_instance,
            verify_certs=False
        )

    @patch('src.clients.base.OpenSearchSigV4Auth')
    @patch('src.clients.base.OpenSearch')
    @patch('src.clients.base._get_sigv4_details')
    def test_scb_opensearch_uses_sigv4_from_helper(self, mock_get_details, MockOpenSearch, MockOpenSearchAuth):
        mock_get_details.return_value = self.sample_sigv4_details_from_helper
        mock_auth_instance = MockOpenSearchAuth.return_value
        client = SearchClientBase(self.base_config, engine_type="opensearch")
        self.assertEqual(mock_get_details.call_count, 2)
        MockOpenSearchAuth.assert_called_once_with(**self.expected_auth_constructor_args)
        MockOpenSearch.assert_called_once_with(
            hosts=['http://localhost:9200'],
            http_auth=mock_auth_instance,
            use_ssl=True,
            verify_certs=False
        )

    @patch('src.clients.base.OpenSearch')
    @patch('src.clients.base._get_sigv4_details')
    def test_scb_opensearch_fallback_to_basic_auth_if_helper_returns_none(self, mock_get_details, MockOpenSearch):
        mock_get_details.return_value = None
        config = {**self.base_config, **self.basic_auth_creds}
        client = SearchClientBase(config, engine_type="opensearch")
        MockOpenSearch.assert_called_once_with(
            hosts=ANY, http_auth=(self.basic_auth_creds["username"], self.basic_auth_creds["password"]), verify_certs=ANY)

    @patch('src.clients.base.HttpSigV4Auth')
    @patch('src.clients.base._get_sigv4_details')
    def test_grc_uses_sigv4_from_helper(self, mock_get_details, MockHttpxAuth):
        mock_get_details.return_value = self.sample_sigv4_details_from_helper
        mock_auth_instance = MockHttpxAuth.return_value
        client = GeneralRestClient(base_url="http://l", config=self.base_config, verify_certs=False)
        mock_get_details.assert_called_once_with(self.base_config)
        MockHttpxAuth.assert_called_once_with(**self.expected_auth_constructor_args)
        self.assertEqual(client.auth, mock_auth_instance)

    @patch('src.clients.base._get_sigv4_details')
    def test_grc_fallback_to_basic_auth_if_helper_returns_none(self, mock_get_details):
        mock_get_details.return_value = None
        config = {**self.basic_auth_creds}
        client = GeneralRestClient(base_url="http://l", config=config, verify_certs=False)
        self.assertIsInstance(client.auth, httpx.BasicAuth)

    def test_elasticsearch_sigv4_auth(self):
        """Test ElasticsearchSigV4Auth works with requests.PreparedRequest"""
        auth = ElasticsearchSigV4Auth("key", "secret", None, "us-east-1", "es")

        # Create a mock PreparedRequest
        mock_request = MagicMock()
        mock_request.method = "GET"
        mock_request.url = "https://example.com/index"
        mock_request.body = None
        mock_request.headers = {}

        # This should work without raising an exception
        result = auth(mock_request)
        self.assertEqual(result, mock_request)  # Should return the same request object

    def test_opensearch_sigv4_auth(self):
        """Test OpenSearchSigV4Auth works with OpenSearch signature (4 arguments)"""
        auth = OpenSearchSigV4Auth("key", "secret", None, "us-east-1", "es")

        # This should work without raising an exception
        result = auth("GET", "https://example.com/index", "", None)
        self.assertIsInstance(result, dict)

class TestAuthClassesFull(unittest.TestCase):
    @patch('src.clients.base.botocore.auth.SigV4Auth')
    @patch('src.clients.base.botocore.awsrequest.AWSRequest')
    def test_elasticsearch_sigv4_auth_call_full(self, MockAWSRequest, MockBotocoreSigV4Internal):
        mock_botocore_sigv4_instance = MockBotocoreSigV4Internal.return_value
        mock_aws_request_instance = MockAWSRequest.return_value; mock_aws_request_instance.headers = {}

        # Create a mock PreparedRequest
        mock_request = MagicMock()
        mock_request.method = "POST"
        mock_request.url = "https://example.com"
        mock_request.body = b'{"test": "data"}'
        mock_request.headers = {}

        auth_handler = ElasticsearchSigV4Auth("k", "s", "t", "r", "svc")
        auth_handler.sigv4 = mock_botocore_sigv4_instance
        # Elasticsearch auth takes PreparedRequest
        result = auth_handler(mock_request)
        MockAWSRequest.assert_called_once()
        mock_botocore_sigv4_instance.add_auth.assert_called_once()
        self.assertEqual(result, mock_request)  # Should return the same request object

    @patch('src.clients.base.botocore.auth.SigV4Auth')
    @patch('src.clients.base.botocore.awsrequest.AWSRequest')
    def test_opensearch_sigv4_auth_call_full(self, MockAWSRequest, MockBotocoreSigV4Internal):
        mock_botocore_sigv4_instance = MockBotocoreSigV4Internal.return_value
        mock_aws_request_instance = MockAWSRequest.return_value; mock_aws_request_instance.headers = {}
        auth_handler = OpenSearchSigV4Auth("k", "s", "t", "r", "svc")
        auth_handler.sigv4 = mock_botocore_sigv4_instance
        # OpenSearch auth takes 4 arguments instead of PreparedRequest
        result = auth_handler("POST", "https://example.com", "q=test", b'{"test": "data"}')
        MockAWSRequest.assert_called_once()
        mock_botocore_sigv4_instance.add_auth.assert_called_once()
        self.assertIsInstance(result, dict)

    @patch('src.clients.base.botocore.auth.SigV4Auth')
    @patch('src.clients.base.botocore.awsrequest.AWSRequest')
    def test_httpx_sigv4_auth_auth_flow_full(self, MockAWSRequest, MockBotocoreSigV4Internal):
        mock_botocore_sigv4_instance = MockBotocoreSigV4Internal.return_value
        mock_aws_request_instance = MockAWSRequest.return_value; mock_aws_request_instance.headers = {}
        auth_handler = HttpxSigV4Auth("k", "s", "t", "r", "svc")
        auth_handler.sigv4_auth_object = mock_botocore_sigv4_instance # Corrected to use the renamed attribute
        mock_req = MagicMock(spec=httpx.Request); mock_req.method="P"; mock_req.url=httpx.URL("u"); mock_req.headers={}; mock_req.content=b""
        next(auth_handler.auth_flow(mock_req))
        MockAWSRequest.assert_called_once()
        mock_botocore_sigv4_instance.add_auth.assert_called_once()

if __name__ == '__main__':
    unittest.main()
