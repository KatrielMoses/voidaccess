"""E2 regression tests. Set VOIDACCESS_E2_POSTGRES_URL for Postgres coverage."""
import os
import uuid
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from fastapi.testclient import TestClient
from fastapi.routing import APIRoute
from api.main import app
from api.auth import create_access_token, get_current_user
from api.ownership import require_resource_owner
from api.routes.monitors import require_owned_monitor
from api.routes.actors import require_owned_actor
from api.auth import require_admin
from db.models import Base, User, Investigation, Entity, Page, InvestigationEntityLink, ActorProfile, ActorAlias, ActorNote, Monitor, MonitorAlert


def dependencies(dep):
    return {dep.call} | set().union(*(dependencies(d) for d in dep.dependencies)) if dep.dependencies else {dep.call}


# These names identify settings within the authenticated user's own key namespace.
PUBLIC_OR_ADMIN_ALLOWLIST = {
    '/settings/api-keys/{key_name}': 'Handler queries by authenticated user_id and key_name; no global object ID.',
    '/admin/circuit-breakers/{engine_name}/reset': 'Global administrative operation; require_admin dependency.',
    '/admin/seeds/validate/{job_id}': 'Global administrative job; require_admin dependency.',
}


def test_object_route_enumeration():
    inspected = []
    for route in app.routes:
        if not isinstance(route, APIRoute) or not route.path_format or '{' not in route.path_format:
            continue
        inspected.append(route.path_format)
        deps = dependencies(route.dependant)
        if route.path_format in PUBLIC_OR_ADMIN_ALLOWLIST:
            if route.path_format.startswith('/admin/'):
                assert require_admin in deps
            continue
        assert deps & {require_resource_owner, require_owned_monitor, require_owned_actor}, route.path_format
    assert inspected


@pytest.fixture(scope='module')
def security_engine(tmp_path_factory):
    url = os.getenv('VOIDACCESS_E2_POSTGRES_URL')
    if url:
        assert url.endswith('/voidaccess_e2_test'), 'Use only the throwaway E2 database'
    else:
        url = f"sqlite:///{tmp_path_factory.mktemp('security') / 'test.db'}"
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def two_users(security_engine, monkeypatch):
    import db.session as db_session
    url = str(security_engine.url)
    monkeypatch.setenv('DATABASE_URL', url)
    monkeypatch.setattr(db_session, 'DATABASE_URL', url)
    db_session._get_engine_cached.cache_clear()
    app.dependency_overrides.clear()
    with Session(security_engine) as s:
        a = User(email=f'a-{uuid.uuid4()}@test', hashed_password='unused', role='admin')
        b = User(email=f'b-{uuid.uuid4()}@test', hashed_password='unused', role='user')
        s.add_all([a,b]);s.flush()
        inv_a=Investigation(query='A private investigation', user_id=a.id, graph_status='complete')
        inv_b=Investigation(query='B private investigation', user_id=b.id, graph_status='complete')
        s.add_all([inv_a,inv_b]);s.flush()
        page_a=Page(investigation_id=inv_a.id,url='https://a.test/secret', cleaned_text='A private evidence '*100)
        page_b=Page(investigation_id=inv_b.id,url='https://b.test/evidence', cleaned_text='B own evidence '*100)
        s.add_all([page_a,page_b]);s.flush()
        shared_value=f'shared-{uuid.uuid4()}.test'
        e=Entity(page_id=page_a.id, investigation_id=inv_a.id, entity_type='DOMAIN', value=shared_value, canonical_value=shared_value, confidence=.99, context_snippet='A secret snippet')
        foreign=Entity(page_id=page_a.id, investigation_id=inv_a.id, entity_type='DOMAIN', value='a-only.test', confidence=.9)
        s.add_all([e,foreign]);s.flush()
        s.add_all([InvestigationEntityLink(entity_id=e.id, investigation_id=inv_a.id, context_snippet='A secret snippet', confidence=.99,page_id=page_a.id), InvestigationEntityLink(entity_id=e.id,investigation_id=inv_b.id,context_snippet='B own snippet',confidence=.5,page_id=page_b.id)])
        actor=ActorProfile(canonical_handle=f'actor-{uuid.uuid4()}', notes='A legacy secret')
        s.add(actor);s.flush()
        s.add_all([ActorAlias(actor_id=actor.id, alias_value=actor.canonical_handle, user_id=a.id, source_investigation_id=inv_a.id),ActorNote(actor_id=actor.id,user_id=a.id,text='A analyst secret')])
        monitor=Monitor(name=f'A-monitor-{uuid.uuid4()}',user_id=a.id,config={'type':'keyword','query':'A secret','webhook_url':'https://a.test/webhook'},enabled=True)
        s.add(monitor);s.flush()
        s.add(MonitorAlert(monitor_name=monitor.name,user_id=a.id,change_type='new',summary='A secret alert'))
        ids=SimpleNamespace(a=a.id,b=b.id,inv_a=str(inv_a.id),inv_b=str(inv_b.id),shared=str(e.id),foreign=str(foreign.id),actor=actor.canonical_handle,monitor=monitor.name)
        s.commit()
    token,_=create_access_token(ids.b,'b@test')
    client=TestClient(app,headers={'Authorization':f'Bearer {token}'})
    yield client,ids
    app.dependency_overrides.clear()


OBJECT_ROUTES = [(r.path_format, next(iter(r.methods))) for r in app.routes if isinstance(r, APIRoute) and '{' in r.path_format and not r.path_format.startswith(('/admin/','/settings/'))]


@pytest.mark.parametrize('path,method',OBJECT_ROUTES)
def test_foreign_object_is_404(two_users,path,method):
    client,ids=two_users
    path=path.replace('{investigation_id}',ids.inv_a).replace('{entity_id}',ids.foreign).replace('{handle}',ids.actor).replace('{node_id}','private-node').replace('{monitor_name}',ids.monitor).replace('{watch_name}',ids.monitor)
    response=client.request(method,path,params={'investigation_id':ids.inv_a},json={} if method in ('POST','PUT') else None)
    assert response.status_code == 404, (method,path,response.text)
    assert 'A secret' not in response.text


@pytest.mark.parametrize('path',['/entities/{shared}','/entities/{shared}/related','/entities/{shared}/neighbors','/entities/{shared}/analysis/opsec','/entities/{shared}/analysis/stylometry','/entities/{shared}/export/json','/entities','/monitors','/monitors/alerts/count','/actors'])
def test_responses_do_not_include_foreign_context(two_users,path):
    client,ids=two_users
    response=client.get(path.format(shared=ids.shared))
    assert response.status_code == 200, response.text
    for secret in ('A secret','https://a.test/','a-only.test','A analyst secret','A legacy secret',ids.inv_a,ids.actor,ids.monitor):
        assert secret not in response.text, (path,secret,response.text)


def test_shared_entity_view_uses_own_link(two_users):
    client,ids=two_users
    response=client.get(f'/entities/{ids.shared}')
    assert response.status_code==200,response.text
    data=response.json()
    assert data['confidence']==.5
    assert data['context']=='B own snippet'
    assert data['source_url']=='https://b.test/evidence'


def test_user_cannot_use_admin_routes(two_users):
    client,_=two_users
    for route in app.routes:
        if isinstance(route,APIRoute) and route.path_format.startswith('/admin/'):
            path=route.path_format.replace('{engine_name}','x').replace('{job_id}','x')
            response=client.request(next(iter(route.methods)),path,json={})
            assert response.status_code==403,(path,response.text)


def test_forged_forwarding_header(monkeypatch):
    from ratelimit.limiter import client_key
    monkeypatch.delenv('VOIDACCESS_TRUSTED_PROXIES',raising=False)
    request=SimpleNamespace(client=SimpleNamespace(host='192.0.2.5'),headers={'x-forwarded-for':'1.1.1.1'})
    assert client_key(request)=='192.0.2.5'
    monkeypatch.setenv('VOIDACCESS_TRUSTED_PROXIES','1')
    request.headers['x-forwarded-for']='1.1.1.1, 198.51.100.5'
    assert client_key(request)=='198.51.100.5'
    monkeypatch.setenv('VOIDACCESS_TRUSTED_PROXIES','192.0.2.0/24')
    assert client_key(request)=='198.51.100.5'


def test_logout_revokes_jti(two_users):
    client,_=two_users
    assert client.post('/auth/logout').status_code==200
    assert client.get('/auth/me').status_code==401


@pytest.mark.asyncio
async def test_rss_snippet_only_never_fetches_article(monkeypatch):
    from sources.rss_scraper import RSSFeedScraper
    from unittest.mock import AsyncMock
    monkeypatch.setenv('VOIDACCESS_RSS_SNIPPET_ONLY','1')
    scraper=RSSFeedScraper()
    scraper._cache=Mock()
    scraper._cache.get.return_value=[{'title':'Security headline','url':'https://example.test/item','summary':'Feed own summary','published':''}]
    scraper._score_article=Mock(return_value=10)
    scraper._fetch_article_content=AsyncMock(side_effect=AssertionError('Must not fetch article'))
    result=await scraper._fetch_feed_inner({'url':'https://example.test/feed','name':'test'},['security'])
    assert result[0]['text_content']=='Feed own summary'
    scraper._fetch_article_content.assert_not_called()


def test_extraction_cannot_replace_other_users_context(two_users,security_engine):
    client,ids=two_users
    before=client.get(f'/entities/{ids.shared}').json()
    from db.queries import upsert_entity_canonical
    with Session(security_engine) as session:
        entity=session.get(Entity,uuid.UUID(ids.shared))
        page=session.query(Page).filter_by(investigation_id=uuid.UUID(ids.inv_a)).first()
        updated,created=upsert_entity_canonical(session,uuid.UUID(ids.inv_a),'DOMAIN',entity.value,1.0,page.id,'A replaced secret')
        assert not created and str(updated.id)==ids.shared
        session.commit()
    after=client.get(f'/entities/{ids.shared}').json()
    for key in ('confidence','context','source_url','page_id','investigation_id'):
        assert after.get(key)==before.get(key)


def test_shared_actor_annotations_are_private(two_users,security_engine):
    client,ids=two_users
    with Session(security_engine) as session:
        actor=session.query(ActorProfile).filter_by(canonical_handle=ids.actor).one()
        session.add(ActorAlias(actor_id=actor.id,user_id=ids.b,source_investigation_id=uuid.UUID(ids.inv_b),alias_value='B own alias',confidence=.9))
        session.commit()
    response=client.post(f'/actors/{ids.actor}/notes',json={'note':'B own analyst note'})
    assert response.status_code==200,response.text
    response=client.get(f'/actors/{ids.actor}')
    assert response.status_code==200,response.text
    assert 'B own analyst note' in response.text
    assert 'A analyst secret' not in response.text and 'A legacy secret' not in response.text
    assert ids.inv_a not in response.text
    with Session(security_engine) as session:
        assert session.query(ActorNote).filter_by(user_id=ids.a).one().text=='A analyst secret'


def test_authenticated_user_limit_is_enforced(two_users,monkeypatch):
    client,_=two_users
    monkeypatch.setenv('DISABLE_RATE_LIMIT','false')
    monkeypatch.setenv('VOIDACCESS_USER_RATE_LIMIT','1')
    assert client.get('/auth/me',headers={'X-Forwarded-For':'1.1.1.1'}).status_code==200
    assert client.get('/auth/me',headers={'X-Forwarded-For':'8.8.8.8'}).status_code==429


def test_all_vector_searches_have_owner_filters(two_users,monkeypatch):
    client,ids=two_users
    import vector
    for path,function,params in (
        ('/search/semantic','search_similar',{'q':'private'}),
        ('/search/similar-to','find_pages_similar_to',{'url':'https://private.test'}),
        ('/search/cross-investigation','cross_investigation_recall',{'q':'private'}),
    ):
        mock=Mock(return_value=[])
        monkeypatch.setattr(vector,function,mock)
        assert client.get(path,params=params).status_code==200
        assert mock.call_args.kwargs['user_id']==ids.b
    count=Mock(return_value=1)
    monkeypatch.setattr(vector,'count_pages',count)
    assert client.get('/search/stats').json()['total_documents']==1
    assert count.call_args.kwargs['user_id']==ids.b
