from __future__ import annotations

from datetime import datetime

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from .models import Alert, BlockedIp, Incident
from .schemas import AlertCreate


def create_alert(session: Session, alert: AlertCreate, blocked: bool) -> Alert:
    db_alert = Alert(
        ts=alert.ts,
        src_ip=alert.src_ip,
        dst_ip=alert.dst_ip,
        dst_port=alert.dst_port,
        attack_type=alert.attack_type,
        severity=alert.severity,
        blocked=blocked,
        anomaly_score=alert.anomaly_score,
        details=alert.details,
    )
    session.add(db_alert)
    session.commit()
    session.refresh(db_alert)
    return db_alert


def list_alerts(session: Session, limit: int = 200) -> list[Alert]:
    stmt = select(Alert).order_by(desc(Alert.ts)).limit(limit)
    return list(session.execute(stmt).scalars())


def upsert_blocked_ip(session: Session, ip: str, reason: str | None) -> BlockedIp:
    existing = session.execute(select(BlockedIp).where(BlockedIp.ip == ip)).scalar_one_or_none()
    if existing:
        return existing
    obj = BlockedIp(ip=ip, blocked_at=datetime.utcnow(), reason=reason)
    session.add(obj)
    session.commit()
    session.refresh(obj)
    return obj


def list_blocked_ips(session: Session, limit: int = 500) -> list[BlockedIp]:
    stmt = select(BlockedIp).order_by(desc(BlockedIp.blocked_at)).limit(limit)
    return list(session.execute(stmt).scalars())


def create_incident(session: Session, src_ip: str, severity: str, summary: str, context: dict) -> Incident:
    obj = Incident(src_ip=src_ip, severity=severity, summary=summary, context=context)
    session.add(obj)
    session.commit()
    session.refresh(obj)
    return obj
