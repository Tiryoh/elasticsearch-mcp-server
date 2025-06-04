import os

from dotenv import load_dotenv

from src.clients.common.client import SearchClient
from src.clients.exceptions import handle_search_exceptions

def create_search_client(engine_type: str) -> SearchClient:
    """
    Create a search client for the specified engine type.

    Args:
        engine_type: Type of search engine to use ("elasticsearch" or "opensearch")

    Returns:
        A search client instance
    """
    # Load configuration from environment variables
    load_dotenv()

    # Get configuration from environment variables
    prefix = engine_type.upper()
    hosts_str = os.environ.get(f"{prefix}_HOSTS", "https://localhost:9200")
    hosts = [host.strip() for host in hosts_str.split(",")]
    username = os.environ.get(f"{prefix}_USERNAME")
    password = os.environ.get(f"{prefix}_PASSWORD")
    verify_certs = os.environ.get(f"{prefix}_VERIFY_CERTS", "false").lower() == "true"

    # AWS SigV4 authentication parameters
    aws_access_key_id = os.environ.get(f"{prefix}_AWS_ACCESS_KEY_ID") or os.environ.get("AWS_ACCESS_KEY_ID")
    aws_secret_access_key = os.environ.get(f"{prefix}_AWS_SECRET_ACCESS_KEY") or os.environ.get("AWS_SECRET_ACCESS_KEY")
    aws_session_token = os.environ.get(f"{prefix}_AWS_SESSION_TOKEN") or os.environ.get("AWS_SESSION_TOKEN")
    aws_profile_name = os.environ.get(f"{prefix}_AWS_PROFILE_NAME") or os.environ.get("AWS_PROFILE_NAME")
    region_name = os.environ.get(f"{prefix}_AWS_REGION_NAME") or os.environ.get("AWS_REGION_NAME") or os.environ.get("AWS_DEFAULT_REGION")
    aws_service_name = os.environ.get(f"{prefix}_AWS_SERVICE_NAME", "es")

    config = {
        "hosts": hosts,
        "username": username,
        "password": password,
        "verify_certs": verify_certs
    }

    # Add AWS SigV4 parameters if any are provided
    if aws_access_key_id or aws_secret_access_key or aws_profile_name or region_name:
        if aws_access_key_id:
            config["aws_access_key_id"] = aws_access_key_id
        if aws_secret_access_key:
            config["aws_secret_access_key"] = aws_secret_access_key
        if aws_session_token:
            config["aws_session_token"] = aws_session_token
        if aws_profile_name:
            config["aws_profile_name"] = aws_profile_name
        if region_name:
            config["region_name"] = region_name
        if aws_service_name:
            config["aws_service_name"] = aws_service_name

    return SearchClient(config, engine_type)

__all__ = [
    'create_search_client',
    'handle_search_exceptions',
    'SearchClient',
]
