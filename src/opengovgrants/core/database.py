"""Database management for OpenGov-Grants."""

import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlite_utils import Database

from ..core.config import get_settings


class DatabaseManager:
    """Manages SQLite database operations for OpenGov-Grants."""

    def __init__(self, db_path: Optional[str] = None):
        """Initialize database manager."""
        settings = get_settings()
        self.db_path = db_path or settings.database_url.replace("sqlite:///", "")
        # Ensure directory exists for SQLite file and open thread-safe connection
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.db = Database(conn)

    def initialize(self, drop_existing: bool = False) -> None:
        """Initialize the database with schema."""
        if drop_existing and Path(self.db_path).exists():
            Path(self.db_path).unlink()

        # Create main table
        self.db["items"].create({
            "id": str,
            "name": str,
            "description": str,
            "created_at": str,
            "updated_at": str
        }, pk="id", if_not_exists=True)

        print(f"Database initialized at {self.db_path}")

    def seed_sample_data(self) -> None:
        """Seed database with sample data."""
        # Add sample data
        self.db["items"].insert([
            {"id": "1", "name": "Sample Item 1", "description": "First sample item"},
            {"id": "2", "name": "Sample Item 2", "description": "Second sample item"}
        ])

        print("Sample data seeded")

    def migrate(self) -> None:
        """Run database migrations."""
        # Add new columns if needed
        try:
            self.db["items"].add_column("status", str, default="active")
            print("Database migrations completed")
        except Exception as e:
            print(f"Migration note: {e}")