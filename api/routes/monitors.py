"""Owner-scoped database monitors. Legacy YAML is a read-only import."""
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from api.auth import CurrentUser, get_current_user, require_password_not_reset_pending
from db.models import Monitor, MonitorAlert
from db.session import get_session
from monitor.migration import import_legacy_watches

_scheduler = None


def set_scheduler(scheduler):
    global _scheduler
    _scheduler = scheduler


def _owned(session, name, user_id):
    row = session.query(Monitor).filter_by(name=name, user_id=user_id, deleted=False).first()
    if row is None:
        raise HTTPException(404, "Monitor not found")
    return row


async def require_owned_monitor(request: Request, current: CurrentUser = Depends(get_current_user)):
    name = request.path_params.get("monitor_name") or request.path_params.get("watch_name")
    if name:
        with get_session() as session:
            import_legacy_watches(session)
            _owned(session, name, current.user.id)


router = APIRouter(dependencies=[Depends(require_owned_monitor)])


class AcknowledgeAlertsBody(BaseModel):
    alert_ids: list[int] | None = None


class CreateMonitorRequest(BaseModel):
    name: str
    type: str
    query: Optional[str] = None
    url: Optional[str] = None
    interval_hours: float = 48.0
    alert_on: str = "new_results"
    webhook_url: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    email: Optional[str] = None
    enabled: bool = True


@router.get("")
async def list_monitors(current: CurrentUser = Depends(get_current_user)):
    with get_session() as session:
        import_legacy_watches(session)
        return [dict(m.config, name=m.name, enabled=m.enabled) for m in
                session.query(Monitor).filter_by(user_id=current.user.id, deleted=False).all()]


@router.get("/alerts/count")
async def get_alert_count(current: CurrentUser = Depends(get_current_user)):
    with get_session() as session:
        alerts = session.query(MonitorAlert).filter_by(user_id=current.user.id, acknowledged=False).all()
        counts = {}
        for alert in alerts:
            counts[alert.monitor_name] = counts.get(alert.monitor_name, 0) + 1
        return {"total_unacknowledged": len(alerts), "by_monitor": counts}


@router.get("/status")
async def monitors_status(current: CurrentUser = Depends(get_current_user)):
    with get_session() as session:
        rows = session.query(Monitor).filter_by(user_id=current.user.id, deleted=False).all()
        result = []
        for row in rows:
            job = _scheduler.get_job(str(row.id)) if _scheduler else None
            next_run = getattr(job, "next_run_time", None)
            result.append({"name": row.name, "next_run_time": next_run.isoformat() if next_run else None,
                           "last_run_time": None})
        return result


@router.get("/{monitor_name}/alerts")
async def get_monitor_alerts(monitor_name: str, limit: int = Query(20, ge=1, le=200),
                             include_acknowledged: bool = True, current: CurrentUser = Depends(get_current_user)):
    with get_session() as session:
        _owned(session, monitor_name, current.user.id)
        query = session.query(MonitorAlert).filter_by(monitor_name=monitor_name, user_id=current.user.id)
        if not include_acknowledged:
            query = query.filter_by(acknowledged=False)
        rows = query.order_by(MonitorAlert.triggered_at.desc()).limit(limit).all()
        alerts = [{c.name: getattr(a, c.name) for c in MonitorAlert.__table__.columns if c.name != "user_id"} for a in rows]
        return {"monitor_name": monitor_name, "alerts": alerts, "total": len(alerts)}


@router.post("/{monitor_name}/alerts/acknowledge")
async def acknowledge_monitor_alerts(monitor_name: str, body: AcknowledgeAlertsBody | None = None,
                                    current: CurrentUser = Depends(get_current_user)):
    with get_session() as session:
        _owned(session, monitor_name, current.user.id)
        query = session.query(MonitorAlert).filter_by(monitor_name=monitor_name, user_id=current.user.id, acknowledged=False)
        if body and body.alert_ids is not None:
            query = query.filter(MonitorAlert.id.in_(body.alert_ids))
        count = query.update({MonitorAlert.acknowledged: True, MonitorAlert.acknowledged_at: datetime.now(timezone.utc)})
        return {"acknowledged": count}


@router.post("")
async def create_monitor(req: CreateMonitorRequest, current: CurrentUser = Depends(require_password_not_reset_pending)):
    if (req.type not in ("keyword", "url") or not req.name.strip() or req.interval_hours < 0.5
        or req.alert_on not in {"new_results", "any_change", "any_appearance"}
        or (req.type == "keyword" and not req.query) or (req.type == "url" and not req.url)):
        raise HTTPException(422, "Invalid monitor configuration")
    with get_session() as session:
        import_legacy_watches(session)
        name = req.name.strip()
        if session.query(Monitor).filter_by(name=name, user_id=current.user.id).first():
            raise HTTPException(409, "Monitor already exists")
        row = Monitor(user_id=current.user.id, name=name, config=req.model_dump(), enabled=req.enabled)
        session.add(row)
        session.flush()
        scheduler_id = str(row.id)
        watch = dict(row.config, name=name, user_id=current.user.id, scheduler_id=scheduler_id)
    if _scheduler and req.enabled:
        from monitor.scheduler import _wrap_keyword, _wrap_url
        func = _wrap_keyword(watch, None) if req.type == "keyword" else _wrap_url(watch, None)
        _scheduler.add_job(func, "interval", hours=req.interval_hours, id=scheduler_id, replace_existing=True)
    return {"created": True, "name": name}


@router.delete("/{watch_name}")
async def delete_monitor(watch_name: str, current: CurrentUser = Depends(get_current_user)):
    with get_session() as session:
        row = _owned(session, watch_name, current.user.id)
        scheduler_id = str(row.id)
        row.deleted = True
        row.enabled = False
    if _scheduler and _scheduler.get_job(scheduler_id):
        _scheduler.remove_job(scheduler_id)
    return {"deleted": True, "name": watch_name}


@router.post("/{watch_name}/trigger")
async def trigger_monitor(watch_name: str, current: CurrentUser = Depends(get_current_user)):
    with get_session() as session:
        row = _owned(session, watch_name, current.user.id)
        scheduler_id = str(row.id)
    from monitor.scheduler import trigger_job_now
    return {"triggered": trigger_job_now(_scheduler, scheduler_id), "watch_name": watch_name}
