"""FastAPI web application for OpenGov-Grants."""

from contextlib import asynccontextmanager
from typing import List

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from ..core.config import get_settings
from ..core.database import DatabaseManager
from ..services.agent_service import AgentService
from ..storage.item_storage import ItemStorage


# Pydantic models
class ItemCreate(BaseModel):
    name: str
    description: str

class Item(ItemCreate):
    id: str
    created_at: str
    updated_at: str

class AnalysisRequest(BaseModel):
    prompt: str
    model: str = "ollama"

class AnalysisResponse(BaseModel):
    result: dict
    provider: str
    model: str


# FastAPI app
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    print("Starting OpenGrants FastAPI application...")
    yield
    # Shutdown
    print("Shutting down OpenGrants FastAPI application...")

app = FastAPI(
    title="OpenGov-Grants API",
    description="Comprehensive grants management and fiscal administration API",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependencies
def get_db_manager():
    return DatabaseManager()

def get_item_storage():
    return ItemStorage()

def get_agent_service():
    return AgentService()


# Routes

@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "OpenGov-Grants",
        "version": "1.0.0",
        "description": "Comprehensive grants management and fiscal administration API",
        "docs": "/docs",
        "health": "/health"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "OpenGov-Grants",
        "version": "1.0.0"
    }

@app.get("/api/items", response_model=List[Item])
async def list_items(
    limit: int = Query(10, ge=1, le=100, description="Number of items to return"),
    offset: int = Query(0, ge=0, description="Number of items to skip"),
    storage: ItemStorage = Depends(get_item_storage)
):
    """List items with pagination."""
    try:
        # Ensure schema exists for tests
        from ..core.database import DatabaseManager
        DatabaseManager().initialize(drop_existing=False)
        items = storage.list_items(limit=limit, offset=offset)
        return items
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/items", response_model=Item)
async def create_item(
    item: ItemCreate,
    storage: ItemStorage = Depends(get_item_storage)
):
    """Create a new item."""
    try:
        from ..core.database import DatabaseManager
        DatabaseManager().initialize(drop_existing=False)
        created_item = storage.create_item(
            ItemCreate(name=item.name, description=item.description)
        )
        return created_item
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/items/{item_id}", response_model=Item)
async def get_item(
    item_id: str,
    storage: ItemStorage = Depends(get_item_storage)
):
    """Get a specific item by ID."""
    try:
        item = storage.get_item(item_id)
        if not item:
            raise HTTPException(status_code=404, detail="Item not found")
        return item
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/items/{item_id}", response_model=Item)
async def update_item(
    item_id: str,
    item_update: ItemCreate,
    storage: ItemStorage = Depends(get_item_storage)
):
    """Update an existing item."""
    try:
        updates = {
            "name": item_update.name,
            "description": item_update.description,
            "updated_at": "2024-01-15T10:00:00"
        }
        updated = storage.update_item(item_id, updates)
        if not updated:
            raise HTTPException(status_code=404, detail="Item not found")
        return storage.get_item(item_id)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/items/{item_id}")
async def delete_item(
    item_id: str,
    storage: ItemStorage = Depends(get_item_storage)
):
    """Delete an item."""
    try:
        deleted = storage.delete_item(item_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Item not found")
        return {"message": "Item deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/analysis", response_model=AnalysisResponse)
async def run_analysis(
    request: AnalysisRequest,
    agent_service: AgentService = Depends(get_agent_service)
):
    """Run AI analysis on given prompt."""
    try:
        import asyncio
        result = await agent_service.run_analysis(
            request.prompt,
            model=request.model
        )
        return AnalysisResponse(
            result=result,
            provider=result.get("provider", "unknown"),
            model=result.get("model", request.model)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/stats")
async def get_stats(
    db_manager: DatabaseManager = Depends(get_db_manager)
):
    """Get database and system statistics."""
    try:
        # This would need to be implemented based on specific domain
        return {
            "service": "OpenGov-Grants",
            "version": "1.0.0",
            "items_count": 0,
            "last_updated": "2024-01-15T10:00:00"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Development server
if __name__ == "__main__":
    settings = get_settings()
    uvicorn.run(
        "app:app",
        host=settings.datasette_host,
        port=settings.datasette_port + 1,  # Use next port
        reload=True,
        log_level="info"
    )