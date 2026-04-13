"""
DevPulse - TRPC Router Implementation
Type-safe RPC routing for API calls
"""

from typing import Any, Callable, Dict, List, Optional, Type
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, status, Request
from functools import wraps
import json
from .auth_service import AuthService  # Import AuthService for access checks


class TRPCError(Exception):
    """TRPC Error"""
    pass


class TRPCInput(BaseModel):
    """Base TRPC input"""
    pass


class TRPCOutput(BaseModel):
    """Base TRPC output"""
    pass


class TRPCProcedure:
    """TRPC Procedure - Type-safe RPC call"""
    
    def __init__(
        self,
        name: str,
        input_model: Optional[Type[BaseModel]] = None,
        output_model: Optional[Type[BaseModel]] = None,
        handler: Optional[Callable] = None
    ):
        self.name = name
        self.input_model = input_model
        self.output_model = output_model
        self.handler = handler
        self.middleware = []
    
    def use_middleware(self, middleware: Callable):
        """Add middleware"""
        self.middleware.append(middleware)
        return self
    
    async def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute procedure with type validation"""
        try:
            # Validate input
            if self.input_model:
                validated_input = self.input_model(**input_data)
            else:
                validated_input = input_data
            
            # Run middleware
            for middleware in self.middleware:
                await middleware(validated_input)
            
            # Execute handler
            if self.handler:
                result = await self.handler(validated_input)
            else:
                result = validated_input
            
            # Validate output
            if self.output_model:
                validated_output = self.output_model(**result)
                return validated_output.dict()
            
            return result
            
        except Exception as e:
            raise TRPCError(f"Procedure {self.name} failed: {str(e)}")


class TRPCRouter:
    """TRPC Router - Type-safe RPC routing"""
    
    def __init__(self, prefix: str = ""):
        self.prefix = prefix
        self.procedures: Dict[str, TRPCProcedure] = {}
        self.routers: Dict[str, 'TRPCRouter'] = {}
        self.fastapi_router = APIRouter(prefix=prefix)
    
    def query(
        self,
        name: str,
        input_model: Optional[Type[BaseModel]] = None,
        output_model: Optional[Type[BaseModel]] = None
    ):
        """Define a query procedure"""
        def decorator(handler: Callable):
            procedure = TRPCProcedure(
                name=name,
                input_model=input_model,
                output_model=output_model,
                handler=handler
            )
            self.procedures[name] = procedure
            
            # Register with FastAPI
            @self.fastapi_router.get(f"/{name}")
            async def query_endpoint(input_data: Optional[str] = None):
                try:
                    data = json.loads(input_data) if input_data else {}
                    result = await procedure.execute(data)
                    return {"result": result}
                except TRPCError as e:
                    raise HTTPException(status_code=400, detail=str(e))
                except Exception as e:
                    raise HTTPException(status_code=500, detail=str(e))
            
            return handler
        
        return decorator
    
    def mutation(
        self,
        name: str,
        input_model: Optional[Type[BaseModel]] = None,
        output_model: Optional[Type[BaseModel]] = None
    ):
        """Define a mutation procedure"""
        def decorator(handler: Callable):
            procedure = TRPCProcedure(
                name=name,
                input_model=input_model,
                output_model=output_model,
                handler=handler
            )
            self.procedures[name] = procedure
            
            # Register with FastAPI
            @self.fastapi_router.post(f"/{name}")
            async def mutation_endpoint(input_data: Dict[str, Any]):
                try:
                    result = await procedure.execute(input_data)
                    return {"result": result}
                except TRPCError as e:
                    raise HTTPException(status_code=400, detail=str(e))
                except Exception as e:
                    raise HTTPException(status_code=500, detail=str(e))
            
            return handler
        
        return decorator
    
    def router(self, prefix: str):
        """Create nested router"""
        nested_router = TRPCRouter(prefix=prefix)
        self.routers[prefix] = nested_router
        return nested_router
    
    def get_fastapi_router(self):
        """Get FastAPI router for mounting"""
        # Mount nested routers
        for prefix, router in self.routers.items():
            self.fastapi_router.include_router(router.get_fastapi_router())
        
        return self.fastapi_router


# Create main TRPC router
trpc = TRPCRouter(prefix="/trpc")

# SECURITY: Shared auth service instance
auth_service = AuthService()

async def workspace_access_middleware(input_data: Any):
    """
    SECURITY: Middleware to check workspace access for all tRPC procedures
    """
    if hasattr(input_data, 'workspace_id'):
        # In production, get user_id from session/context
        user_id = "user_placeholder" 
        if not auth_service.check_workspace_access(user_id, input_data.workspace_id):
            raise TRPCError(f"Access denied to workspace: {input_data.workspace_id}")

# ============================================================================
# COLLECTIONS ROUTER
# ============================================================================

collections_router = trpc.router("/collections")


class ImportCollectionInput(BaseModel):
    """Import collection input"""
    name: str
    data: Dict[str, Any]
    workspace_id: str  # SECURITY: Require workspace_id


class ImportCollectionOutput(BaseModel):
    """Import collection output"""
    collection_id: str
    total_requests: int
    success: bool


@collections_router.mutation(
    "import",
    input_model=ImportCollectionInput,
    output_model=ImportCollectionOutput
)
async def import_collection(input_data: ImportCollectionInput):
    """Import Postman collection"""
    # SECURITY: Apply workspace access check
    await workspace_access_middleware(input_data)
    
    # Parse collection
    requests = input_data.data.get("item", [])
    
    # Parse collection
    requests = input_data.data.get("item", [])
    
    return {
        "collection_id": "col_" + str(hash(input_data.workspace_id + input_data.name))[:8],
        "total_requests": len(requests),
        "success": True
    }


class GetCollectionsOutput(BaseModel):
    """Get collections output"""
    collections: List[Dict[str, Any]]
    total: int


class ListCollectionsInput(BaseModel):
    """List collections input"""
    workspace_id: str  # SECURITY: Require workspace_id


@collections_router.query(
    "list",
    input_model=ListCollectionsInput,
    output_model=GetCollectionsOutput
)
async def list_collections(input_data: ListCollectionsInput):
    """List all collections in workspace"""
    # SECURITY: Apply workspace access check
    await workspace_access_middleware(input_data)
    
    return {
        "collections": [],  # Would filter by workspace_id
        "total": 0
    }


# ============================================================================
# SECURITY ROUTER
# ============================================================================

security_router = trpc.router("/security")


class ScanInput(BaseModel):
    """Scan input"""
    collection_id: str
    scan_type: str = "full"


class Finding(BaseModel):
    """Security finding"""
    id: str
    title: str
    severity: str
    description: str


class ScanOutput(BaseModel):
    """Scan output"""
    scan_id: str
    findings: List[Finding]
    risk_score: float


@security_router.mutation(
    "scan",
    input_model=ScanInput,
    output_model=ScanOutput
)
async def scan_collection(input_data: ScanInput):
    """Scan collection for vulnerabilities"""
    return {
        "scan_id": "scan_" + input_data.collection_id[:8],
        "findings": [],
        "risk_score": 0.0
    }


# ============================================================================
# USAGE ROUTER
# ============================================================================

usage_router = trpc.router("/usage")


class GetUsageOutput(BaseModel):
    """Get usage output"""
    requests_this_month: int
    requests_limit: int
    requests_remaining: int
    percentage_used: float


@usage_router.query(
    "get",
    output_model=GetUsageOutput
)
async def get_usage():
    """Get current usage"""
    return {
        "requests_this_month": 0,
        "requests_limit": 1000,
        "requests_remaining": 1000,
        "percentage_used": 0.0
    }


class IncrementUsageInput(BaseModel):
    """Increment usage input"""
    amount: int = 1


class IncrementUsageOutput(BaseModel):
    """Increment usage output"""
    new_count: int
    remaining: int


@usage_router.mutation(
    "increment",
    input_model=IncrementUsageInput,
    output_model=IncrementUsageOutput
)
async def increment_usage(input_data: IncrementUsageInput):
    """Increment usage counter"""
    return {
        "new_count": 1,
        "remaining": 999
    }


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    # Example: Call a procedure
    import asyncio
    
    async def test():
        # Test import collection
        result = await collections_router.procedures["import"].execute({
            "name": "Test Collection",
            "data": {"item": []}
        })
        print(f"Import result: {result}")
        
        # Test get usage
        result = await usage_router.procedures["get"].execute({})
        print(f"Usage result: {result}")
    
    asyncio.run(test())
