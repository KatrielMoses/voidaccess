"""Upgrade the unchanged main schema and retain legacy owned data (Postgres)."""
import os
import uuid
import json
from pathlib import Path
import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session
from alembic import command
from alembic.config import Config


@pytest.mark.skipif(not os.getenv('VOIDACCESS_E2_UPGRADE_URL'), reason='requires isolated Postgres upgrade database')
def test_main_schema_upgrade_retains_annotations_monitors_vectors(tmp_path, monkeypatch):
    url=os.environ['VOIDACCESS_E2_UPGRADE_URL']
    assert url.endswith('/voidaccess_e2_upgrade')
    engine=sa.create_engine(url)
    cfg=Config(str(Path(__file__).resolve().parents[1]/'alembic.ini'))
    cfg.set_main_option('script_location',str(Path(__file__).resolve().parents[1]/'db/migrations'))
    cfg.set_main_option('sqlalchemy.url',url)
    # The baseline is the last main revision; older migration files are unchanged.
    command.upgrade(cfg,'0035_add_ges_contributor')
    with engine.begin() as conn:
        assert 'role' not in {c['name'] for c in sa.inspect(conn).get_columns('users')}
        owner=conn.execute(sa.text('SELECT MIN(id) FROM users')).scalar()
        actor_id=uuid.uuid4();alias_id=uuid.uuid4()
        conn.execute(sa.text("INSERT INTO actor_profiles (id,canonical_handle,notes,created_at,updated_at) VALUES (:id,'legacy-actor','legacy note',NOW(),NOW())"), {'id':actor_id})
        conn.execute(sa.text("INSERT INTO actor_aliases (id,actor_id,alias_value) VALUES (:id,:actor,'legacy alias')"), {'id':alias_id,'actor':actor_id})
    command.upgrade(cfg,'head')
    command.upgrade(cfg,'head')  # Schema migration idempotence.
    import db.session as db_session
    monkeypatch.setenv('DATABASE_URL',url)
    monkeypatch.setattr(db_session,'DATABASE_URL',url)
    db_session._get_engine_cached.cache_clear()
    yaml=tmp_path/'monitors.yaml'
    yaml.write_text('watches:\n  - name: legacy watch\n    type: keyword\n    query: legacy\n    interval_hours: 1\n    alert_on: new_results\n    webhook_url: https://legacy.test/private\n')
    monkeypatch.setenv('MONITORS_CONFIG_PATH',str(yaml))
    before=yaml.read_bytes()
    from monitor.migration import import_legacy_watches
    from db.models import User,ActorAlias,ActorNote,Monitor
    with Session(engine) as session:
        assert session.get(User,owner).role=='admin'
        assert session.get(ActorAlias,alias_id).user_id==owner
        note=session.query(ActorNote).filter_by(actor_id=actor_id).one()
        assert note.user_id==owner and note.text=='legacy note'
        assert import_legacy_watches(session)==1
        assert import_legacy_watches(session)==0
        watch=session.query(Monitor).filter_by(name='legacy watch').one()
        assert watch.user_id==owner
        session.commit()
    assert yaml.read_bytes()==before
    # Frozen metadata-store mock: upgrade must preserve vector IDs and content.
    class Collection:
        data={'legacy-vector': {'url':'https://legacy.test/private'}}
        def get(self,limit=500,offset=0,include=None):
            keys=list(self.data)[offset:offset+limit]
            return {'ids':keys,'metadatas':[self.data[k] for k in keys]}
        def update(self,ids,metadatas):
            for k,v in zip(ids,metadatas):self.data[k]=v
    from vector import store
    col=Collection()
    monkeypatch.setattr(store,'get_collection',lambda:col)
    monkeypatch.setattr(store,'get_actor_collection',lambda:None)
    assert store.backfill_owners(owner)==1
    assert store.backfill_owners(owner)==0
    assert col.data['legacy-vector']['user_id']==str(owner)
    assert col.data['legacy-vector']['url']=='https://legacy.test/private'
    engine.dispose()
