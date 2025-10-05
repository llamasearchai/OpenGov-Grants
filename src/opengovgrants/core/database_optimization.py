"""Database query optimization and indexing utilities."""

from typing import Dict, Any, List, Optional, Type, Union
from datetime import datetime, timedelta
import structlog

from sqlalchemy import text, Index, Column, String, DateTime, Integer, Boolean, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

from .exceptions import DatabaseError

logger = structlog.get_logger(__name__)


class QueryOptimizer:
    """Database query optimization utilities."""

    def __init__(self, session: AsyncSession):
        """Initialize query optimizer."""
        self.session = session

    async def analyze_query_performance(self, query: Select) -> Dict[str, Any]:
        """Analyze query performance and suggest optimizations."""
        try:
            # Get query explanation
            explanation = await self._explain_query(query)

            # Analyze indexes
            index_analysis = await self._analyze_indexes(query)

            # Check for common performance issues
            issues = await self._check_performance_issues(query)

            return {
                "query_plan": explanation,
                "index_analysis": index_analysis,
                "performance_issues": issues,
                "optimization_suggestions": self._generate_suggestions(issues, index_analysis)
            }

        except Exception as e:
            logger.error("Query performance analysis failed", error=str(e))
            raise DatabaseError(f"Query performance analysis failed: {str(e)}")

    async def _explain_query(self, query: Select) -> Dict[str, Any]:
        """Get query execution plan."""
        try:
            # Convert query to SQL
            compiled = query.compile(compile_kwargs={"literal_binds": True})

            # Get explanation (PostgreSQL specific)
            explain_query = text(f"EXPLAIN (ANALYZE, BUFFERS) {compiled.string}")
            result = await self.session.execute(explain_query)

            return {
                "plan": [row[0] for row in result.fetchall()],
                "sql": compiled.string
            }

        except Exception as e:
            # Fallback for databases that don't support EXPLAIN ANALYZE
            return {
                "plan": ["Query plan analysis not available for this database"],
                "sql": str(query)
            }

    async def _analyze_indexes(self, query: Select) -> Dict[str, Any]:
        """Analyze index usage for the query."""
        try:
            # This would need to be implemented based on the specific database
            # For now, return basic analysis
            return {
                "suggested_indexes": [],
                "unused_indexes": [],
                "missing_indexes": []
            }

        except Exception as e:
            logger.error("Index analysis failed", error=str(e))
            return {"error": str(e)}

    async def _check_performance_issues(self, query: Select) -> List[str]:
        """Check for common performance issues."""
        issues = []

        # Check for missing WHERE clauses
        if not self._has_where_clause(query):
            issues.append("Query without WHERE clause may scan entire table")

        # Check for SELECT * usage
        if self._uses_select_all(query):
            issues.append("Using SELECT * may return unnecessary columns")

        # Check for missing LIMIT
        if not self._has_limit(query):
            issues.append("Query without LIMIT may return too many rows")

        # Check for potential N+1 queries
        if self._has_joins(query):
            issues.append("Consider using eager loading for joined relationships")

        return issues

    def _has_where_clause(self, query: Select) -> bool:
        """Check if query has WHERE clause."""
        return len(query.whereclause.columns) > 0 if query.whereclause else False

    def _uses_select_all(self, query: Select) -> bool:
        """Check if query uses SELECT *."""
        # This is a simplified check
        return "*" in str(query.selected_columns)

    def _has_limit(self, query: Select) -> bool:
        """Check if query has LIMIT clause."""
        return query._limit is not None

    def _has_joins(self, query: Select) -> bool:
        """Check if query has JOINs."""
        return len(query.column_descriptions) > 1

    def _generate_suggestions(self, issues: List[str], index_analysis: Dict[str, Any]) -> List[str]:
        """Generate optimization suggestions."""
        suggestions = []

        for issue in issues:
            if "WHERE clause" in issue:
                suggestions.append("Add appropriate WHERE conditions to filter data")
            elif "SELECT *" in issue:
                suggestions.append("Specify only the columns you need")
            elif "LIMIT" in issue:
                suggestions.append("Add LIMIT clause to restrict result size")
            elif "eager loading" in issue:
                suggestions.append("Use joinedload() or selectinload() for relationships")

        return suggestions

    async def optimize_query(self, query: Select) -> Select:
        """Apply automatic query optimizations."""
        optimized_query = query

        # Add LIMIT if missing and query might be expensive
        if not self._has_limit(query) and self._might_be_expensive(query):
            optimized_query = optimized_query.limit(1000)

        # Add indexes if needed (this would be a more complex implementation)
        # For now, just return the query as-is

        return optimized_query

    def _might_be_expensive(self, query: Select) -> bool:
        """Check if query might be expensive to execute."""
        # Simple heuristic: queries without WHERE or with many joins
        return not self._has_where_clause(query) or self._has_joins(query)


class IndexManager:
    """Database index management utilities."""

    def __init__(self, session: AsyncSession):
        """Initialize index manager."""
        self.session = session

    async def create_index(
        self,
        table_name: str,
        column_names: List[str],
        index_name: Optional[str] = None,
        unique: bool = False
    ) -> str:
        """Create a database index."""
        try:
            if not index_name:
                index_name = f"ix_{table_name}_{'_'.join(column_names)}"

            # Create index SQL
            columns_str = ", ".join(column_names)
            unique_str = "UNIQUE" if unique else ""
            sql = f"CREATE {unique_str} INDEX IF NOT EXISTS {index_name} ON {table_name} ({columns_str})"

            await self.session.execute(text(sql))
            await self.session.commit()

            logger.info(
                "Index created",
                table=table_name,
                columns=column_names,
                index_name=index_name,
                unique=unique
            )

            return index_name

        except Exception as e:
            await self.session.rollback()
            logger.error("Failed to create index", error=str(e))
            raise DatabaseError(f"Failed to create index: {str(e)}")

    async def drop_index(self, index_name: str) -> bool:
        """Drop a database index."""
        try:
            sql = f"DROP INDEX IF EXISTS {index_name}"
            await self.session.execute(text(sql))
            await self.session.commit()

            logger.info("Index dropped", index_name=index_name)
            return True

        except Exception as e:
            await self.session.rollback()
            logger.error("Failed to drop index", error=str(e))
            raise DatabaseError(f"Failed to drop index: {str(e)}")

    async def get_index_usage(self) -> Dict[str, Any]:
        """Get index usage statistics."""
        try:
            # This is database-specific
            # PostgreSQL example
            if self.session.bind.url.drivername.startswith("postgresql"):
                result = await self.session.execute(text("""
                    SELECT
                        schemaname,
                        tablename,
                        indexname,
                        idx_scan as scans,
                        idx_tup_read as tuples_read,
                        idx_tup_fetch as tuples_fetched
                    FROM pg_stat_user_indexes
                    ORDER BY idx_scan DESC
                """))

                indexes = []
                for row in result.fetchall():
                    indexes.append({
                        "schema": row[0],
                        "table": row[1],
                        "index": row[2],
                        "scans": row[3],
                        "tuples_read": row[4],
                        "tuples_fetched": row[5]
                    })

                return {"indexes": indexes}

            return {"message": "Index usage statistics not available for this database"}

        except Exception as e:
            logger.error("Failed to get index usage", error=str(e))
            raise DatabaseError(f"Failed to get index usage: {str(e)}")

    async def suggest_indexes(self, table_name: str) -> List[Dict[str, Any]]:
        """Suggest indexes for a table based on query patterns."""
        try:
            # This would analyze query logs and suggest indexes
            # For now, return common suggestions
            suggestions = [
                {
                    "table": table_name,
                    "columns": ["created_at"],
                    "reason": "Commonly used for sorting and filtering",
                    "type": "btree"
                },
                {
                    "table": table_name,
                    "columns": ["updated_at"],
                    "reason": "Commonly used for sorting",
                    "type": "btree"
                },
                {
                    "table": table_name,
                    "columns": ["status"],
                    "reason": "Commonly used for filtering",
                    "type": "btree"
                }
            ]

            return suggestions

        except Exception as e:
            logger.error("Failed to suggest indexes", error=str(e))
            raise DatabaseError(f"Failed to suggest indexes: {str(e)}")


class DatabaseMaintenance:
    """Database maintenance utilities."""

    def __init__(self, session: AsyncSession):
        """Initialize database maintenance."""
        self.session = session

    async def vacuum_database(self) -> Dict[str, Any]:
        """Perform database vacuum operation."""
        try:
            start_time = datetime.utcnow()

            # SQLite
            if self.session.bind.url.drivername.startswith("sqlite"):
                await self.session.execute(text("VACUUM"))
                await self.session.execute(text("ANALYZE"))

            # PostgreSQL
            elif self.session.bind.url.drivername.startswith("postgresql"):
                await self.session.execute(text("VACUUM ANALYZE"))

            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()

            return {
                "operation": "vacuum",
                "status": "completed",
                "duration_seconds": duration,
                "timestamp": end_time.isoformat()
            }

        except Exception as e:
            logger.error("Database vacuum failed", error=str(e))
            raise DatabaseError(f"Database vacuum failed: {str(e)}")

    async def reindex_database(self) -> Dict[str, Any]:
        """Reindex database tables."""
        try:
            start_time = datetime.utcnow()

            # SQLite
            if self.session.bind.url.drivername.startswith("sqlite"):
                await self.session.execute(text("REINDEX"))

            # PostgreSQL
            elif self.session.bind.url.drivername.startswith("postgresql"):
                await self.session.execute(text("REINDEX DATABASE CONCURRENTLY opengovgrants"))

            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()

            return {
                "operation": "reindex",
                "status": "completed",
                "duration_seconds": duration,
                "timestamp": end_time.isoformat()
            }

        except Exception as e:
            logger.error("Database reindex failed", error=str(e))
            raise DatabaseError(f"Database reindex failed: {str(e)}")

    async def get_table_statistics(self) -> Dict[str, Any]:
        """Get database table statistics."""
        try:
            # SQLite
            if self.session.bind.url.drivername.startswith("sqlite"):
                result = await self.session.execute(text("""
                    SELECT
                        name as table_name,
                        COUNT(*) as row_count
                    FROM sqlite_master
                    WHERE type='table'
                    GROUP BY name
                """))

                tables = []
                for row in result.fetchall():
                    tables.append({
                        "name": row[0],
                        "row_count": row[1]
                    })

                return {"tables": tables}

            # PostgreSQL
            elif self.session.bind.url.drivername.startswith("postgresql"):
                result = await self.session.execute(text("""
                    SELECT
                        schemaname,
                        tablename,
                        n_tup_ins as inserts,
                        n_tup_upd as updates,
                        n_tup_del as deletes,
                        n_live_tup as live_tuples,
                        n_dead_tup as dead_tuples
                    FROM pg_stat_user_tables
                    WHERE schemaname = 'public'
                    ORDER BY n_live_tup DESC
                """))

                tables = []
                for row in result.fetchall():
                    tables.append({
                        "schema": row[0],
                        "name": row[1],
                        "inserts": row[2],
                        "updates": row[3],
                        "deletes": row[4],
                        "live_tuples": row[5],
                        "dead_tuples": row[6]
                    })

                return {"tables": tables}

            return {"message": "Table statistics not available for this database"}

        except Exception as e:
            logger.error("Failed to get table statistics", error=str(e))
            raise DatabaseError(f"Failed to get table statistics: {str(e)}")

    async def cleanup_dead_tuples(self) -> Dict[str, Any]:
        """Clean up dead tuples and perform maintenance."""
        try:
            start_time = datetime.utcnow()

            # PostgreSQL specific cleanup
            if self.session.bind.url.drivername.startswith("postgresql"):
                # Clean up dead tuples
                await self.session.execute(text("VACUUM"))

                # Update table statistics
                await self.session.execute(text("ANALYZE"))

                # Clean up old prepared statements
                await self.session.execute(text("DISCARD ALL"))

            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()

            return {
                "operation": "cleanup",
                "status": "completed",
                "duration_seconds": duration,
                "timestamp": end_time.isoformat()
            }

        except Exception as e:
            logger.error("Database cleanup failed", error=str(e))
            raise DatabaseError(f"Database cleanup failed: {str(e)}")