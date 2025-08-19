import argparse
import logging
import sys

from fastmcp import FastMCP

from src.clients import create_search_client
from src.tools.alias import AliasTools
from src.tools.cluster import ClusterTools
from src.tools.document import DocumentTools
from src.tools.general import GeneralTools
from src.tools.index import IndexTools
from src.tools.register import ToolsRegister
from src.version import __version__ as VERSION

class SearchMCPServer:
    def __init__(self, engine_type, read_only=False):
        # Set engine type
        self.engine_type = engine_type
        self.read_only = read_only
        self.name = f"{self.engine_type}_mcp_server"
        self.mcp = FastMCP(self.name)
        self.logger = logging.getLogger()
        self.logger.info(f"Initializing {self.name}, Version: {VERSION}, Read-only: {read_only}")

        # Create the corresponding search client
        self.search_client = create_search_client(self.engine_type)

        # Initialize tools
        self._register_tools()

    def _register_tools(self):
        """Register all MCP tools."""
        # Create a tools register
        register = ToolsRegister(self.logger, self.search_client, self.mcp, self.read_only)

        # Define all tool classes to register
        tool_classes = [
            IndexTools,
            DocumentTools,
            ClusterTools,
            AliasTools,
            GeneralTools,
        ]
        # Register all tools
        register.register_all_tools(tool_classes)

    def run(self):
        """Run the MCP server."""
        self.mcp.run()

def run_search_server(engine_type, read_only=False):
    """Run search server with specified engine type."""
    server = SearchMCPServer(engine_type=engine_type, read_only=read_only)
    server.run()

def elasticsearch_mcp_server():
    """Entry point for Elasticsearch MCP server."""
    parser = argparse.ArgumentParser(description='Elasticsearch MCP Server')
    parser.add_argument('--read-only', action='store_true',
                       help='Enable read-only mode (disable write operations)')
    args = parser.parse_args()

    run_search_server(engine_type="elasticsearch", read_only=args.read_only)

def opensearch_mcp_server():
    """Entry point for OpenSearch MCP server."""
    parser = argparse.ArgumentParser(description='OpenSearch MCP Server')
    parser.add_argument('--read-only', action='store_true',
                       help='Enable read-only mode (disable write operations)')
    args = parser.parse_args()

    run_search_server(engine_type="opensearch", read_only=args.read_only)

if __name__ == "__main__":
    # Default to Elasticsearch
    engine_type = "elasticsearch"

    # If command line arguments are provided, use the first argument as the engine type
    if len(sys.argv) > 1:
        engine_type = sys.argv[1].lower()

    if engine_type == "opensearch":
        opensearch_mcp_server()
    else:
        elasticsearch_mcp_server()
