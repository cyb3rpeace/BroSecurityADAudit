import ast
import unittest
from pathlib import Path
from types import SimpleNamespace
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database import Base, Company, TenantNotifyChannel

class NotificationTenantTests(unittest.TestCase):
    def setUp(self):
        engine=create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.db=sessionmaker(bind=engine,expire_on_commit=False)()
        self.addCleanup(engine.dispose);self.addCleanup(self.db.close)
        self.db.add_all([Company(id=1,name="One"),Company(id=2,name="Two")]);self.db.commit()
        source=Path(__file__).resolve().parents[1]/"app/main.py"
        names={"resolve_company","channel_row","channel_public","mail_channel"}
        nodes=[n for n in ast.parse(source.read_text()).body if isinstance(n,ast.FunctionDef) and n.name in names]
        scope={"Session":object,"User":object,"Company":Company,"NotifyChannel":object,"TenantNotifyChannel":TenantNotifyChannel,"Any":object,"HTTPException":HTTPException}
        exec(compile(ast.Module(body=nodes,type_ignores=[]),str(source),"exec"),scope);self.scope=scope
    def test_isolation(self):
        row=self.scope["channel_row"](self.db,1);row.smtp_server="one.test";row.smtp_password="test-only-secret";self.db.commit()
        other=self.scope["channel_row"](self.db,2)
        self.assertEqual(other.smtp_server,"");self.assertEqual(other.smtp_password,"")
        self.assertNotIn("test-only-secret",str(self.scope["channel_public"](row)))
        self.assertTrue(self.scope["mail_channel"](other)["tenant_scoped"])
    def test_authorization(self):
        with self.assertRaises(HTTPException) as caught:self.scope["resolve_company"](SimpleNamespace(role="company_admin",company_id=1),self.db,2)
        self.assertEqual(caught.exception.status_code,403)
        with self.assertRaises(HTTPException) as caught:self.scope["resolve_company"](SimpleNamespace(role="superadmin"),self.db,None)
        self.assertEqual(caught.exception.status_code,400)
    def test_endpoint_scopes(self):
        source=Path(__file__).resolve().parents[1]/"app/main.py"
        nodes=[n for n in ast.parse(source.read_text()).body if isinstance(n,ast.FunctionDef) and n.name.startswith("notifications_")]
        self.assertEqual(len(nodes),6)
        for node in nodes:
            self.assertIn("company_id",[arg.arg for arg in node.args.args])
            self.assertTrue(any(isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=="resolve_company" for n in ast.walk(node)))
