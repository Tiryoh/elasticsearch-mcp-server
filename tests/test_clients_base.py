import unittest
from unittest.mock import patch, MagicMock, ANY

from src.clients.base import (
    SearchClientBase,
    GeneralRestClient,
    BotocoreSigV4Auth as RequestsBotocoreSigV4Auth,
    SigV4Auth as HttpxSigV4Auth
)

import requests
import httpx
import botocore.awsrequest
import botocore.auth
import botocore.credentials

class TestClientInitializationCommit1(unittest.TestCase):
    def setUp(self):
        self.base_config = {"hosts": ["http://localhost:9200"], "verify_certs": False}
        self.direct_sigv4_creds = {
            "aws_access_key_id": "direct_ak",
            "aws_secret_access_key": "direct_sk",
            "aws_session_token": "direct_tk",
            "region_name": "direct_region",
            "aws_service_name": "es"
        }
        self.basic_auth_creds = {"username": "user", "password": "password"}

    @patch('src.clients.base.RequestsBotocoreSigV4Auth')
    @patch('src.clients.base.OpenSearch')
    @patch('src.clients.base.GeneralRestClient')
    def test_scb_opensearch_uses_direct_sigv4(self, MockGeneralRestClient, MockOpenSearch, MockReqBotocoreSigV4Auth):
        mock_auth_instance = MockReqBotocoreSigV4Auth.return_value
        config = {**self.base_config, **self.direct_sigv4_creds}

        client = SearchClientBase(config, engine_type="opensearch")

        MockReqBotocoreSigV4Auth.assert_called_once_with(
            access_key="direct_ak", secret_key="direct_sk", session_token="direct_tk",
            region="direct_region", service="es"
        )
        MockOpenSearch.assert_called_once_with(
            hosts=self.base_config["hosts"],
            http_auth=mock_auth_instance,
            use_ssl=True,
            verify_certs=self.base_config["verify_certs"]
        )
        MockGeneralRestClient.assert_called_once_with(
            base_url=self.base_config["hosts"][0],
            verify_certs=self.base_config["verify_certs"],
            username=None,
            password=None,
            aws_access_key_id="direct_ak",
            aws_secret_access_key="direct_sk",
            aws_session_token="direct_tk",
            region_name="direct_region",
            aws_service_name="es"
        )

    @patch('src.clients.base.OpenSearch')
    def test_scb_opensearch_basic_auth(self, MockOpenSearch):
        config = {**self.base_config, **self.basic_auth_creds}
        client = SearchClientBase(config, engine_type="opensearch")
        MockOpenSearch.assert_called_once_with(
            hosts=config["hosts"],
            http_auth=(self.basic_auth_creds["username"], self.basic_auth_creds["password"]),
            verify_certs=config["verify_certs"]
        )

    @patch('src.clients.base.RequestsBotocoreSigV4Auth')
    @patch('src.clients.base.Elasticsearch')
    def test_scb_elasticsearch_uses_direct_sigv4(self, MockElasticsearch, MockReqBotocoreSigV4Auth):
        config = {**self.base_config, **self.direct_sigv4_creds}
        mock_auth_instance = MockReqBotocoreSigV4Auth.return_value
        client = SearchClientBase(config, engine_type="elasticsearch")
        MockReqBotocoreSigV4Auth.assert_called_once_with(
            access_key="direct_ak", secret_key="direct_sk", session_token="direct_tk",
            region="direct_region", service="es"
        )
        MockElasticsearch.assert_called_once_with(
            hosts=self.base_config["hosts"], http_auth=mock_auth_instance, use_ssl=True,
            verify_certs=self.base_config["verify_certs"]
        )

    @patch('src.clients.base.Elasticsearch')
    def test_scb_elasticsearch_basic_auth(self, MockElasticsearch):
        config = {**self.base_config, **self.basic_auth_creds}
        client = SearchClientBase(config, engine_type="elasticsearch")
        MockElasticsearch.assert_called_once_with(
            hosts=config["hosts"],
            basic_auth=(self.basic_auth_creds["username"], self.basic_auth_creds["password"]),
            verify_certs=config["verify_certs"]
        )

    @patch('src.clients.base.HttpxSigV4Auth')
    def test_grc_uses_direct_sigv4(self, MockHttpxSigV4Auth):
        mock_auth_instance = MockHttpxSigV4Auth.return_value
        client = GeneralRestClient(
            base_url="http://localhost", verify_certs=False,
            aws_access_key_id="direct_ak", aws_secret_access_key="direct_sk",
            aws_session_token="direct_tk", region_name="direct_region", aws_service_name="custom_svc"
        )
        MockHttpxSigV4Auth.assert_called_once_with(
            access_key="direct_ak", secret_key="direct_sk", session_token="direct_tk",
            region="direct_region", service="custom_svc"
        )
        self.assertEqual(client.auth, mock_auth_instance)

    def test_grc_uses_basic_auth(self): # Corrected method name
        client = GeneralRestClient(
            base_url="http://localhost",
            username="user",
            password="password",
            verify_certs=False
        )
        self.assertIsInstance(client.auth, httpx.BasicAuth)


class TestAuthClassesCommit1(unittest.TestCase): # Renamed class
    @patch('src.clients.base.botocore.auth.SigV4Auth')
    @patch('src.clients.base.botocore.awsrequest.AWSRequest')
    def test_requests_botocore_sigv4_auth_call(self, MockAWSRequest, MockBotocoreSigV4Internal):
        mock_botocore_sigv4_instance = MockBotocoreSigV4Internal.return_value
        mock_aws_request_instance = MockAWSRequest.return_value
        mock_aws_request_instance.headers = {}

        auth_handler = RequestsBotocoreSigV4Auth(
            access_key="test_key", secret_key="test_secret", session_token="test_token",
            region="test_region", service="test_service"
        )
        auth_handler.sigv4 = mock_botocore_sigv4_instance

        mock_prepared_request = MagicMock(spec=requests.PreparedRequest)
        mock_prepared_request.method = "GET"
        mock_prepared_request.url = "https://example.com/path"
        mock_prepared_request.headers = {'User-Agent': 'test-agent'}
        mock_prepared_request.body = b"test_body"

        returned_request = auth_handler(mock_prepared_request)

        MockAWSRequest.assert_called_once_with(
            method="GET", url="https://example.com/path", data=b"test_body", headers={'User-Agent': 'test-agent'}
        )
        mock_botocore_sigv4_instance.add_auth.assert_called_once_with(mock_aws_request_instance)
        self.assertEqual(returned_request, mock_prepared_request)

    @patch('src.clients.base.botocore.auth.SigV4Auth')
    @patch('src.clients.base.botocore.awsrequest.AWSRequest')
    def test_httpx_sigv4_auth_auth_flow(self, MockAWSRequest, MockBotocoreSigV4Internal):
        mock_botocore_sigv4_instance = MockBotocoreSigV4Internal.return_value
        mock_aws_request_instance = MockAWSRequest.return_value
        mock_aws_request_instance.headers = {}

        auth_handler = HttpxSigV4Auth(
            access_key="test_key", secret_key="test_secret", session_token="test_token",
            region="test_region", service="test_service"
        )
        # The HttpxSigV4Auth class creates the botocore.auth.SigV4Auth object in its __init__
        # and stores it as self.sigv4_auth_object. We need to replace that specific instance.
        auth_handler.sigv4_auth_object = mock_botocore_sigv4_instance

        mock_httpx_request = MagicMock(spec=httpx.Request)
        mock_httpx_request.method = "POST"
        mock_httpx_request.url = httpx.URL("https://example.com/resource")
        mock_httpx_request.headers = {'X-Custom': 'value'}
        mock_httpx_request.content = b'{"key":"value"}'

        returned_request_generator = auth_handler.auth_flow(mock_httpx_request)
        returned_request = next(returned_request_generator)

        MockAWSRequest.assert_called_once_with(
            method="POST", url="https://example.com/resource", data=b'{"key":"value"}', headers={'X-Custom': 'value'}
        )
        # This assertion should be on the mock_botocore_sigv4_instance that was injected
        mock_botocore_sigv4_instance.add_auth.assert_called_once_with(mock_aws_request_instance)
        self.assertEqual(returned_request, mock_httpx_request)

if __name__ == '__main__':
    unittest.main()
