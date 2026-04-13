"""
DevPulse - Postman Collection Parser
Parses Postman .json collections and converts to internal DevPulse schema
"""

import json
import uuid
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class PostmanRequest:
    """Internal representation of a parsed Postman request"""
    id: str
    name: str
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str]
    auth: Optional[Dict[str, Any]]
    tests: Optional[str]
    pre_request_script: Optional[str]
    description: Optional[str]
    created_at: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


class PostmanParser:
    """Parse Postman collections and extract requests"""
    
    def __init__(self):
        self.requests: List[PostmanRequest] = []
        self.collection_info: Dict[str, Any] = {}
    
    def parse_collection(self, file_path: str) -> Dict[str, Any]:
        """
        Parse a Postman collection file
        
        Args:
            file_path: Path to .json collection file
            
        Returns:
            Parsed collection with requests and metadata
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                collection_data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            return {"error": f"Failed to parse collection: {str(e)}"}
        
        # Extract collection info
        self.collection_info = {
            "name": collection_data.get("info", {}).get("name", "Unknown"),
            "description": collection_data.get("info", {}).get("description", ""),
            "version": collection_data.get("info", {}).get("version", "1.0"),
            "schema": collection_data.get("info", {}).get("schema", ""),
        }
        
        # Parse requests
        items = collection_data.get("item", [])
        self._parse_items(items)
        
        return {
            "success": True,
            "collection_info": self.collection_info,
            "total_requests": len(self.requests),
            "requests": [r.to_dict() for r in self.requests]
        }
    
    def _parse_items(self, items: List[Dict], parent_folder: str = ""):
        """
        Recursively parse collection items (handles nested folders)
        
        Args:
            items: List of items from collection
            parent_folder: Parent folder name for organization
        """
        for item in items:
            # Handle folders (nested items)
            if "item" in item and isinstance(item["item"], list):
                folder_name = item.get("name", "")
                self._parse_items(item["item"], parent_folder=folder_name)
            
            # Handle requests
            elif "request" in item:
                request_data = item["request"]
                parsed_request = self._parse_request(request_data, item.get("name", "Unknown"))
                if parsed_request:
                    self.requests.append(parsed_request)
    
    def _parse_request(self, request_data: Dict, name: str) -> Optional[PostmanRequest]:
        """
        Parse individual Postman request
        
        Args:
            request_data: Request object from Postman
            name: Request name
            
        Returns:
            PostmanRequest object or None if invalid
        """
        try:
            # Extract URL
            url_obj = request_data.get("url", {})
            if isinstance(url_obj, str):
                url = url_obj
            elif isinstance(url_obj, dict):
                url = url_obj.get("raw", "")
            else:
                url = ""
            
            if not url:
                return None
            
            # Extract method
            method = request_data.get("method", "GET").upper()
            
            # Extract headers
            headers = {}
            header_list = request_data.get("header", [])
            for header in header_list:
                if isinstance(header, dict):
                    key = header.get("key", "")
                    value = header.get("value", "")
                    if key:
                        headers[key] = value
            
            # Extract body
            body = None
            body_obj = request_data.get("body", {})
            if isinstance(body_obj, dict):
                if body_obj.get("mode") == "raw":
                    body = body_obj.get("raw", "")
                elif body_obj.get("mode") == "formdata":
                    body = json.dumps(body_obj.get("formdata", []))
                elif body_obj.get("mode") == "urlencoded":
                    body = json.dumps(body_obj.get("urlencoded", []))
            
            # Extract auth
            auth = request_data.get("auth", {})
            
            # Extract tests
            tests = request_data.get("tests", None)
            
            # Extract pre-request script
            pre_request_script = request_data.get("pre_request_script", None)
            
            # Extract description
            description = request_data.get("description", "")
            
            # Create request object
            request = PostmanRequest(
                id=str(uuid.uuid4()),
                name=name,
                method=method,
                url=url,
                headers=headers,
                body=body,
                auth=auth if auth else None,
                tests=tests,
                pre_request_script=pre_request_script,
                description=description,
                created_at=datetime.utcnow().isoformat()
            )
            
            return request
            
        except Exception as e:
            print(f"Error parsing request {name}: {str(e)}")
            return None
    
    def parse_collection_data(self, collection_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse a Postman collection from an already-loaded dict

        Args:
            collection_data: Parsed JSON dict of the Postman collection

        Returns:
            Parsed collection with requests, metadata, and statistics
        """
        # Reset state for a fresh parse
        self.requests = []
        self.collection_info = {}

        # Extract collection info
        self.collection_info = {
            "name": collection_data.get("info", {}).get("name", "Unknown"),
            "description": collection_data.get("info", {}).get("description", ""),
            "version": collection_data.get("info", {}).get("version", "1.0"),
            "schema": collection_data.get("info", {}).get("schema", ""),
        }

        # Parse requests
        items = collection_data.get("item", [])
        self._parse_items(items)

        statistics = self.get_statistics()

        return {
            "success": True,
            "name": self.collection_info.get("name", "Unknown"),
            "format": "postman",
            "collection_info": self.collection_info,
            "total_requests": len(self.requests),
            "requests": [r.to_dict() for r in self.requests],
            "statistics": statistics,
        }

    def get_requests_by_method(self, method: str) -> List[PostmanRequest]:
        """Filter requests by HTTP method"""
        return [r for r in self.requests if r.method == method.upper()]
    
    def get_requests_by_url_pattern(self, pattern: str) -> List[PostmanRequest]:
        """Filter requests by URL pattern"""
        return [r for r in self.requests if pattern.lower() in r.url.lower()]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get collection statistics"""
        methods = {}
        for req in self.requests:
            methods[req.method] = methods.get(req.method, 0) + 1
        
        return {
            "total_requests": len(self.requests),
            "methods": methods,
            "requests_with_auth": sum(1 for r in self.requests if r.auth),
            "requests_with_body": sum(1 for r in self.requests if r.body),
            "requests_with_tests": sum(1 for r in self.requests if r.tests),
        }


def parse_postman_collection(file_path: str) -> Dict[str, Any]:
    """
    Convenience function to parse Postman collection
    
    Usage:
        result = parse_postman_collection("collection.json")
        if result.get("success"):
            requests = result["requests"]
            print(f"Parsed {len(requests)} requests")
    """
    parser = PostmanParser()
    return parser.parse_collection(file_path)


# Example usage
if __name__ == "__main__":
    # Test with sample collection
    sample_collection = {
        "info": {
            "name": "Sample API",
            "description": "Sample API collection",
            "version": "1.0"
        },
        "item": [
            {
                "name": "Get Users",
                "request": {
                    "method": "GET",
                    "url": "https://api.example.com/users",
                    "header": [
                        {"key": "Authorization", "value": "Bearer token123"},
                        {"key": "Content-Type", "value": "application/json"}
                    ]
                }
            },
            {
                "name": "Create User",
                "request": {
                    "method": "POST",
                    "url": "https://api.example.com/users",
                    "header": [
                        {"key": "Content-Type", "value": "application/json"}
                    ],
                    "body": {
                        "mode": "raw",
                        "raw": '{"name": "John", "email": "john@example.com"}'
                    }
                }
            }
        ]
    }
    
    # Save sample collection
    with open("/tmp/sample_collection.json", "w") as f:
        json.dump(sample_collection, f)
    
    # Parse it
    parser = PostmanParser()
    result = parser.parse_collection("/tmp/sample_collection.json")
    
    print("Collection Info:", result["collection_info"])
    print("Total Requests:", result["total_requests"])
    print("Statistics:", parser.get_statistics())
    print("\nRequests:")
    for req in parser.requests:
        print(f"  {req.method} {req.url} - {req.name}")
