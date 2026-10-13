"""Database monitor operations preserve YAML and isolate owners."""
import asyncio
from types import SimpleNamespace
import pytest
from sqlalchemy.orm import Session
from db.models import User, Monitor
from api.routes.monitors import CreateMonitorRequest, create_monitor


@pytest.mark.asyncio
async def test_concurrent_creates_preserve_yaml(db_engine, tmp_path, monkeypatch):
    path = tmp_path / 'monitors.yaml'
    path.write_text('watches: []\n')
    monkeypatch.setenv('MONITORS_CONFIG_PATH', str(path))
    with Session(db_engine) as session:
        user = User(email='monitor@test', hashed_password='unused', role='admin')
        session.add(user);session.commit();owner=user.id
    current=SimpleNamespace(user=SimpleNamespace(id=owner))
    requests=[CreateMonitorRequest(name=name,type='keyword',query=name) for name in ('one','two')]
    result=await asyncio.gather(*(create_monitor(req,current=current) for req in requests))
    assert all(r['created'] for r in result)
    assert path.read_text()=='watches: []\n'
    with Session(db_engine) as session:
        assert session.query(Monitor).filter_by(user_id=owner).count()==2
