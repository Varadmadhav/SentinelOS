"""
db/dependencies.py
------------------
FastAPI-compatible dependency injection helpers.

Provides a single shared FraudDB instance across the entire application
lifetime — initialised once, injected everywhere via `Depends(get_db)`.

Usage in a route
----------------
    from fastapi import Depends
    from db import get_db, FraudDB

    @router.get("/check-number")
    async def check_number(number: str, db: FraudDB = Depends(get_db)):
        result = await db.lookup_phone(number)
        ...
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from db.fraud_db import FraudDB, JsonFileAdapter

# Module-level singleton — set by init_db() at app startup
_db_instance: Optional[FraudDB] = None

# Default data path (relative to backend root)
_DEFAULT_DATA_PATH = Path(__file__).parent.parent / "data" / "fraud_data.json"


async def init_db(data_path: Path = _DEFAULT_DATA_PATH) -> FraudDB:
    """
    Create and initialise the shared FraudDB singleton.
    Call this once inside FastAPI's `lifespan` startup handler.

    Example
    -------
        from contextlib import asynccontextmanager
        from fastapi import FastAPI
        from db import init_db

        @asynccontextmanager
        async def lifespan(app: FastAPI):
            await init_db()
            yield

        app = FastAPI(lifespan=lifespan)
    """
    global _db_instance
    adapter = JsonFileAdapter(path=data_path)
    _db_instance = FraudDB(adapter=adapter)
    await _db_instance.initialise()
    return _db_instance


async def get_db() -> FraudDB:
    """
    FastAPI dependency.  Returns the live FraudDB instance.
    Raises RuntimeError if init_db() was never called.
    """
    if _db_instance is None:
        raise RuntimeError(
            "Database not initialised. Ensure `await init_db()` is called "
            "inside your app lifespan startup."
        )
    return _db_instance