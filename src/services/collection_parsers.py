"""
DevPulse - Multi-Format Collection Parsers
Support for Postman, Bruno, and OpenAPI/Swagger formats
"""

import json
import yaml
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


class BrunoParser:
    """Parse Bruno collection format"""
    
    def parse_collection(self, collection_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Bruno collection"""
        try:
            requests = []
            
            # Bruno format: collection -> folders -> requests
            if "folders" in collection_data:
                for folder in collection_data.get("folders", []):
                    requests.extend(self._parse_folder(folder))
            
            # Top-level requests
            for req in collection_data.get("requests", []):
                requests.append(self._parse_request(req))
            
            return {
                "name": collection_data.get("name", "Bruno Collection"),
                "description": collection_data.get("description", ""),
                "requests": requests,
                "total_requests": len(requests),
                "format": "bruno"
            }
        except Exception as e:
            logger.error(f"Failed to parse Bruno collection: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _parse_folder(self, folder: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse Bruno folder"""
        requests = []
        
        # Recursive folder parsing
        for subfolder in folder.get("folders", []):
            requests.extend(self._parse_folder(subfolder))
        
        # Requests in folder
        for req in folder.get("requests", []):
            requests.append(self._parse_request(req))
        
        return requests
    
    def _parse_request(self, req: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Bruno request"""
        return {
            "name": req.get("name", "Unnamed"),
            "method": req.get("method", "GET"),
            "url": req.get("url", ""),
            "description": req.get("description", ""),
            "headers": req.get("headers", {}),
            "body": req.get("body", ""),
            "params": req.get("params", {}),
            "auth": req.get("auth", {})
        }


class OpenAPIParser:
    """Parse OpenAPI/Swagger format"""
    
    def parse_collection(self, spec_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse OpenAPI specification"""
        try:
            requests = []
            
            # OpenAPI format: paths -> methods -> operations
            paths = spec_data.get("paths", {})
            for path, methods in paths.items():
                for method, operation in methods.items():
                    if method.lower() in ["get", "post", "put", "delete", "patch", "options", "head"]:
                        requests.append(self._parse_operation(path, method, operation))
            
            return {
                "name": spec_data.get("info", {}).get("title", "OpenAPI Collection"),
                "description": spec_data.get("info", {}).get("description", ""),
                "version": spec_data.get("info", {}).get("version", "1.0.0"),
                "requests": requests,
                "total_requests": len(requests),
                "format": "openapi",
                "base_url": self._get_base_url(spec_data)
            }
        except Exception as e:
            logger.error(f"Failed to parse OpenAPI spec: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _parse_operation(self, path: str, method: str, operation: Dict[str, Any]) -> Dict[str, Any]:
        """Parse OpenAPI operation"""
        return {
            "name": operation.get("summary", f"{method.upper()} {path}"),
            "method": method.upper(),
            "url": path,
            "description": operation.get("description", ""),
            "parameters": operation.get("parameters", []),
            "request_body": operation.get("requestBody", {}),
            "responses": operation.get("responses", {}),
            "security": operation.get("security", []),
            "tags": operation.get("tags", [])
        }
    
    def _get_base_url(self, spec_data: Dict[str, Any]) -> str:
        """Extract base URL from OpenAPI spec"""
        servers = spec_data.get("servers", [])
        if servers:
            return servers[0].get("url", "")
        return ""


class CollectionParserFactory:
    """Factory for parsing different collection formats"""
    
    def __init__(self):
        self.bruno_parser = BrunoParser()
        self.openapi_parser = OpenAPIParser()
    
    def detect_format(self, data: Dict[str, Any]) -> str:
        """Detect collection format"""
        if "postman_id" in data or ("info" in data and "item" in data):
            return "postman"
        elif "swagger" in data or "openapi" in data:
            return "openapi"
        elif "folders" in data or "requests" in data:
            return "bruno"
        else:
            return "unknown"
    
    def parse(self, data: Dict[str, Any], format: Optional[str] = None) -> Dict[str, Any]:
        """Parse collection in any supported format"""
        if not format:
            format = self.detect_format(data)
        
        if format == "postman":
            from .postman_parser import PostmanParser
            parser = PostmanParser()
            return parser.parse_collection_data(data)
        elif format == "bruno":
            return self.bruno_parser.parse_collection(data)
        elif format == "openapi":
            return self.openapi_parser.parse_collection(data)
        else:
            return {"success": False, "error": f"Unknown format: {format}"}


# Global parser factory instance
parser_factory = CollectionParserFactory()
