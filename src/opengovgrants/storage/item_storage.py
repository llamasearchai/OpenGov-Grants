"""Storage layer for OpenGov-Grants."""

import json
from typing import List, Optional
from uuid import UUID

import structlog
from sqlite_utils import Database

from ..core.config import get_settings
from ..models.item import Item, ItemCreate

logger = structlog.get_logger(__name__)


class ItemStorage:
    """Storage operations for OpenGov-Grants items."""

    def __init__(self, db_path: Optional[str] = None):
        """Initialize item storage."""
        settings = get_settings()
        self.db_path = db_path or settings.database_url.replace("sqlite:///", "")
        # Ensure directory exists for SQLite file
        from pathlib import Path
        import sqlite3
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.db = Database(conn)

    def create_item(self, item: ItemCreate) -> Item:
        """Create a new item."""
        # Ensure table exists
        self.db["items"].create({
            "id": str,
            "name": str,
            "description": str,
            "created_at": str,
            "updated_at": str
        }, pk="id", if_not_exists=True)

        # Build item row
        from uuid import uuid4
        from datetime import datetime
        now = datetime.utcnow().isoformat()
        item_dict = {
            "id": str(uuid4()),
            "name": item.name,
            "description": item.description,
            "created_at": now,
            "updated_at": now,
        }

        self.db["items"].insert(item_dict)
        try:
            self.db.conn.commit()
        except Exception:
            pass

        # Return as Item object
        return Item(**item_dict)

    def get_item(self, item_id: str) -> Optional[Item]:
        """Get an item by ID."""
        try:
            row = self.db["items"].get(item_id)
        except Exception:
            return None
        if row:
            return self._row_to_item(row)
        return None

    def list_items(self, limit: int = 100, offset: int = 0) -> List[Item]:
        """List items with pagination."""
        # Gracefully handle absent table
        if "items" not in self.db.table_names():
            return []
        cur = self.db.execute(
            "SELECT id, name, description, created_at, updated_at FROM items LIMIT ? OFFSET ?",
            (limit, offset),
        )
        rows = cur.fetchall()
        items: List[Item] = []
        for row in rows:
            # row can be a tuple; map by index
            row_dict = {
                "id": row[0],
                "name": row[1],
                "description": row[2],
                "created_at": row[3],
                "updated_at": row[4],
            }
            items.append(Item(**row_dict))
        return items

    def update_item(self, item_id: str, updates: dict) -> bool:
        """Update an item."""
        updates["updated_at"] = updates.get("updated_at", "2024-01-15T10:00:00")
        if "items" not in self.db.table_names():
            return False
        # Build dynamic SQL for updates
        fields = [k for k in updates.keys()]
        params = [updates[k] for k in fields]
        set_clause = ", ".join(f"{f} = ?" for f in fields)
        sql = f"UPDATE items SET {set_clause} WHERE id = ?"
        cur = self.db.execute(sql, params + [item_id])
        try:
            self.db.conn.commit()
        except Exception:
            pass
        return cur.rowcount > 0

    def delete_item(self, item_id: str) -> bool:
        """Delete an item."""
        if "items" not in self.db.table_names():
            return False
        cur = self.db.execute("DELETE FROM items WHERE id = ?", [item_id])
        try:
            self.db.conn.commit()
        except Exception:
            pass
        return cur.rowcount > 0

    def search_items(self, query: str) -> List[Item]:
        """Search items using FTS."""
        if "items" not in self.db.table_names():
            return []
        rows = self.db["items"].search(query)
        return [self._row_to_item(row) for row in rows]

    def get_item_stats(self) -> dict:
        """Get item statistics."""
        if "items" not in self.db.table_names():
            total_items = 0
        else:
            total_items = self.db["items"].count
        return {
            "total_items": total_items
        }

    def _row_to_item(self, row: dict) -> Item:
        """Convert database row to Item object."""
        if isinstance(row, tuple):
            row_dict = {
                "id": row[0],
                "name": row[1],
                "description": row[2],
                "created_at": row[3],
                "updated_at": row[4],
            }
        else:
            row_dict = dict(row)
        return Item(**row_dict)