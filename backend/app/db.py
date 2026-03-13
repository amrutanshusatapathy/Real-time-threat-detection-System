from __future__ import annotations

import os
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from .config import settings


def _sqlite_url() -> str:
    # Create parent folder if needed
    path = settings.sqlite_path
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    return f"sqlite:///{path}"


def _db_url() -> str:
    return settings.database_url or _sqlite_url()


db_url = _db_url()

connect_args = None
if db_url.startswith("sqlite:///"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    db_url,
    connect_args=connect_args or {},
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@contextmanager
def db_session() -> Session:
    session: Session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
