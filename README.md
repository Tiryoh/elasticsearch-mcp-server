# Elasticsearch/OpenSearch MCP Server

## Overview
A Model Context Protocol (MCP) server implementation that provides Elasticsearch and OpenSearch interaction. This server enables searching documents, analyzing indices, and managing cluster through a set of tools.

## Features
### General Operations
- `general_api_request`: Perform a general HTTP API request.
### Index Operations
- `list_indices`: List all indices.
- `get_index`: Returns information about one or more indices.
- `create_index`: Create a new index.
- `delete_index`: Delete an index.
### Document Operations
- `search_documents`: Search for documents.
- `index_document`: Creates or updates a document in the index.
- `get_document`: Get a document by ID.
- `delete_document`: Delete a document by ID.
- `delete_by_query`: Deletes documents matching the provided query.
### Cluster Operations
- `get_cluster_health`: Returns basic information about the health of the cluster.
- `get_cluster_stats`: Returns high-level overview of cluster statistics.
### Alias Operations
- `list_aliases`: List all aliases.
- `get_alias`: Get alias information for a specific index.
- `put_alias`: Create or update an alias for a specific index.
- `delete_alias`: Delete an alias for a specific index.

## Authentication

The MCP server supports multiple methods for authenticating with your Elasticsearch or OpenSearch cluster.

### Basic Authentication (Username/Password)
You can configure the server to use basic authentication by providing a username and password.

### AWS SigV4 Authentication

The server can also authenticate using AWS IAM credentials via Signature Version 4 (SigV4).
The client implementation uses `botocore` (from the AWS SDK, typically included via the `boto3` library) directly to handle SigV4 signing.

Client configuration keys for SigV4:
-   `aws_access_key_id` (Optional): Your AWS access key ID.
-   `aws_secret_access_key` (Optional): Your AWS secret access key.
-   `aws_session_token` (Optional): Your AWS session token.
-   `aws_profile_name` (Optional): AWS profile name from `~/.aws/credentials` or `~/.aws/config`.
-   `region_name` (Recommended): The AWS region (e.g., "us-east-1").
-   `aws_service_name` (Optional): Defaults to "es". Use "aoss" for OpenSearch Serverless.

### Credential and Region Priority for SigV4:

1.  **Direct Keys:** Uses `aws_access_key_id`, `aws_secret_access_key`, `aws_session_token` if provided. `region_name` from config is mandatory.
2.  **AWS Profile Name:** If direct keys not fully provided and `aws_profile_name` is set, credentials are from this profile. Region is from `config.region_name` or the profile.
3.  **Default Boto3 Chain:** Otherwise, uses default Boto3 chain (env vars, shared files, IAM roles). Region is from `config.region_name` or the default session.

A valid region must be determined. SigV4 (if configured) takes priority over Basic Auth.

**Example Configurations:**
```python
# Direct SigV4 keys
config_direct_sigv4 = {
    "hosts": ["https://domain.region.es.amazonaws.com:443"],
    "aws_access_key_id": "YOUR_AKID", "aws_secret_access_key": "YOUR_SK",
    "region_name": "your-region-1", "verify_certs": True
}
# AWS Profile
config_profile_sigv4 = {
    "hosts": ["https://domain.region.es.amazonaws.com:443"],
    "aws_profile_name": "my_profile", "region_name": "us-west-2", # Optional region override
    "verify_certs": True
}
# Default Boto3 chain (e.g., EC2 instance role)
config_default_chain_sigv4 = {
    "hosts": ["https://domain.region.es.amazonaws.com:443"],
    "region_name": "ap-southeast-2", # Optional region override
    "verify_certs": True
}
```

## Configure Environment Variables
Copy the `.env.example` file to `.env` and update the values accordingly.

## Start Elasticsearch/OpenSearch Cluster
Start the Elasticsearch/OpenSearch cluster using Docker Compose:
```bash
# For Elasticsearch
docker-compose -f docker-compose-elasticsearch.yml up -d
# For OpenSearch
docker-compose -f docker-compose-opensearch.yml up -d
```
Default Elasticsearch: `elastic`/`test123`. OpenSearch: `admin`/`admin`.
Kibana/Dashboards: http://localhost:5601.

## Usage with Claude Desktop
### Option 1: Installing via Smithery
```bash
npx -y @smithery/cli install elasticsearch-mcp-server --client claude
```
### Option 2: Using uvx
(Example config for Elasticsearch)
```json
{
  "mcpServers": {
    "elasticsearch-mcp-server": {
      "command": "uvx", "args": ["elasticsearch-mcp-server"],
      "env": {
        "ELASTICSEARCH_HOSTS": "https://localhost:9200",
        "ELASTICSEARCH_USERNAME": "elastic", "ELASTICSEARCH_PASSWORD": "test123"
      }
    }
  }
}
```
### Option 3: Using uv with local development
(Example config for Elasticsearch)
```json
{
  "mcpServers": {
    "elasticsearch-mcp-server": {
      "command": "uv", "args": ["--directory", "path/to/repo", "run", "elasticsearch-mcp-server"],
      "env": {
        "ELASTICSEARCH_HOSTS": "https://localhost:9200",
        "ELASTICSEARCH_USERNAME": "elastic", "ELASTICSEARCH_PASSWORD": "test123"
      }
    }
  }
}
```
Claude Desktop config file:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%/Claude/claude_desktop_config.json`

Restart Claude Desktop to load.
Interact with commands like: "List all indices", "How old is student Bob?", "Cluster health status".

## Usage with Anthropic MCP Client
```python
uv run mcp_client/client.py src/server.py
```

## License
Apache License Version 2.0 - see [LICENSE](LICENSE) file.
