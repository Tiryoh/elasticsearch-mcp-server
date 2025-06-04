# Elasticsearch/OpenSearch MCP Server

[![smithery badge](https://smithery.ai/badge/elasticsearch-mcp-server)](https://smithery.ai/server/elasticsearch-mcp-server)

[![MseeP.ai Security Assessment Badge](https://mseep.net/pr/cr7258-elasticsearch-mcp-server-badge.png)](https://mseep.ai/app/cr7258-elasticsearch-mcp-server)

## Overview

A Model Context Protocol (MCP) server implementation that provides Elasticsearch and OpenSearch interaction. This server enables searching documents, analyzing indices, and managing cluster through a set of tools.

<a href="https://glama.ai/mcp/servers/b3po3delex"><img width="380" height="200" src="https://glama.ai/mcp/servers/b3po3delex/badge" alt="Elasticsearch MCP Server" /></a>

## Demo

https://github.com/user-attachments/assets/f7409e31-fac4-4321-9c94-b0ff2ea7ff15

## Features

### General Operations
- `general_api_request`: Perform a general HTTP API request. Use this tool for any Elasticsearch/OpenSearch API that does not have a dedicated tool.

### Index Operations
- `list_indices`: List all indices.
- `get_index`: Returns information (mappings, settings, aliases) about one or more indices.
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
You can configure the server to use basic authentication by providing a username and password. This is typically done via environment variables.

-   **For Elasticsearch:**
    -   `ELASTICSEARCH_USERNAME`: The username for Elasticsearch.
    -   `ELASTICSEARCH_PASSWORD`: The password for Elasticsearch.
-   **For OpenSearch:**
    -   `OPENSEARCH_USERNAME`: The username for OpenSearch.
    -   `OPENSEARCH_PASSWORD`: The password for OpenSearch.

These are often set in your `.env` file or directly in the `env` block of your MCP client configuration (e.g., for Claude Desktop), which are then translated by the server application into the required configuration for the search client.

### AWS SigV4 Authentication

The server can also authenticate using AWS IAM credentials via Signature Version 4 (SigV4). This is common when connecting to AWS OpenSearch Service (formerly Elasticsearch Service) or OpenSearch Serverless.

The client implementation uses `botocore` (from the AWS SDK, typically included via the `boto3` library) directly to handle SigV4 signing. This means no additional third-party SigV4 helper libraries are required for the `elasticsearch-py` or `opensearch-py` clients themselves.

To use SigV4 authentication with direct keys, the client needs to be configured with:
-   `aws_access_key_id`: Your AWS access key ID.
-   `aws_secret_access_key`: Your AWS secret access key.
-   `aws_session_token` (Optional): Your AWS session token (if using temporary credentials).
-   `region_name`: The AWS region where your service is hosted (e.g., "us-east-1"). This is **required** for SigV4 with direct keys.
-   `aws_service_name` (Optional): The AWS service name to use for signing. Defaults to "es". For OpenSearch Serverless, this should typically be set to "aoss".

**Priority:** If AWS SigV4 credentials (direct keys) and `region_name` are provided in the client configuration, AWS SigV4 authentication will be used. Otherwise, the client will fall back to Basic Authentication if username/password are provided.

**Example: Client Configuration Dictionary (Direct SigV4 Keys)**
```python
config_direct_sigv4 = {
    "hosts": ["https://your-opensearch-domain.region.es.amazonaws.com:443"], # Use HTTPS
    "aws_access_key_id": "YOUR_ACCESS_KEY_ID",
    "aws_secret_access_key": "YOUR_SECRET_ACCESS_KEY",
    "aws_session_token": "YOUR_SESSION_TOKEN", # If applicable
    "region_name": "your-region-1", # Required with direct keys
    "aws_service_name": "es", # or "aoss" for OpenSearch Serverless
    "verify_certs": True # Recommended for AWS endpoints
}

# Configuration for Basic Auth (for comparison)
config_basic_auth = {
    "hosts": ["http://localhost:9200"], # Or HTTPS if configured
    "username": "elastic", # or "admin" for OpenSearch default
    "password": "yourpassword",
    "verify_certs": False # Often false for local dev with self-signed certs
}
```

**Note on Environment Variables for Server Application:**
When running the MCP server application (e.g., `src/server.py`), it needs to be able to read these AWS credentials from environment variables and construct the appropriate configuration dictionary for the search client. For example, you might define environment variables like:
- `MCP_AWS_ACCESS_KEY_ID`
- `MCP_AWS_SECRET_ACCESS_KEY`
- etc.
The server script (`src/server.py`) would then need to be updated to read these environment variables and pass them into the `config` dictionary. This part of the README describes the client library's direct config.

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

The default Elasticsearch username is `elastic` and password is `test123`. The default OpenSearch username is `admin` and password is `admin`.

You can access Kibana/OpenSearch Dashboards from http://localhost:5601.

## Usage with Claude Desktop

### Option 1: Installing via Smithery

To install Elasticsearch Server for Claude Desktop automatically via [Smithery](https://smithery.ai/server/elasticsearch-mcp-server):

```bash
npx -y @smithery/cli install elasticsearch-mcp-server --client claude
```

### Option 2: Using uvx

Using `uvx` will automatically install the package from PyPI, no need to clone the repository locally. Add the following configuration to Claude Desktop's config file `claude_desktop_config.json`.

```json
// For Elasticsearch
{
  "mcpServers": {
    "elasticsearch-mcp-server": {
      "command": "uvx",
      "args": [
        "elasticsearch-mcp-server"
      ],
      "env": {
        "ELASTICSEARCH_HOSTS": "https://localhost:9200",
        "ELASTICSEARCH_USERNAME": "elastic",
        "ELASTICSEARCH_PASSWORD": "test123"
      }
    }
  }
}

// For OpenSearch
{
  "mcpServers": {
    "opensearch-mcp-server": {
      "command": "uvx",
      "args": [
        "opensearch-mcp-server"
      ],
      "env": {
        "OPENSEARCH_HOSTS": "https://localhost:9200",
        "OPENSEARCH_USERNAME": "admin",
        "OPENSEARCH_PASSWORD": "admin"
      }
    }
  }
}
```

### Option 3: Using uv with local development

Using `uv` requires cloning the repository locally and specifying the path to the source code. Add the following configuration to Claude Desktop's config file `claude_desktop_config.json`.

```json
// For Elasticsearch
{
  "mcpServers": {
    "elasticsearch-mcp-server": {
      "command": "uv",
      "args": [
        "--directory",
        "path/to/src/elasticsearch_mcp_server",
        "run",
        "elasticsearch-mcp-server"
      ],
      "env": {
        "ELASTICSEARCH_HOSTS": "https://localhost:9200",
        "ELASTICSEARCH_USERNAME": "elastic",
        "ELASTICSEARCH_PASSWORD": "test123"
      }
    }
  }
}

// For OpenSearch
{
  "mcpServers": {
    "opensearch-mcp-server": {
      "command": "uv",
      "args": [
        "--directory",
        "path/to/src/elasticsearch_mcp_server",
        "run",
        "opensearch-mcp-server"
      ],
      "env": {
        "OPENSEARCH_HOSTS": "https://localhost:9200",
        "OPENSEARCH_USERNAME": "admin",
        "OPENSEARCH_PASSWORD": "admin"
      }
    }
  }
}
```

- On macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- On Windows: `%APPDATA%/Claude/claude_desktop_config.json`

Restart Claude Desktop to load the new MCP server.

Now you can interact with your Elasticsearch/OpenSearch cluster through Claude using natural language commands like:
- "List all indices in the cluster"
- "How old is the student Bob?"
- "Show me the cluster health status"

## Usage with Anthropic MCP Client

```python
uv run mcp_client/client.py src/server.py
```

## License

This project is licensed under the Apache License Version 2.0 - see the [LICENSE](LICENSE) file for details.
