"""Network-free mail regression tests; no production data or delivery."""
import os,ssl,smtplib,socket,unittest
from unittest.mock import patch
from app.modules import notifier_mail as mail
class MailTests(unittest.TestCase):
    def setUp(self):
        env=patch.dict(os.environ,{},clear=True);env.start();self.addCleanup(env.stop)
        net=patch.object(socket,"create_connection",side_effect=AssertionError("network forbidden"));net.start();self.addCleanup(net.stop)
        smtp=patch.object(mail.smtplib,"SMTP");self.smtp=smtp.start();self.addCleanup(smtp.stop)
        tls=patch.object(mail.smtplib,"SMTP_SSL");self.tls=tls.start();self.addCleanup(tls.stop)
        self.conn=self.smtp.return_value.__enter__.return_value;self.conn.send_message.return_value={}
        self.tlsconn=self.tls.return_value.__enter__.return_value;self.tlsconn.send_message.return_value={}
        self.channel=dict(server="smtp.internal.test",port=587,security="starttls",username="audit@internal.test",password="mock-secret",sender="audit@internal.test")
    def send(self,**kw):
        args=dict(company_name="Test",summary="Summary",findings=[],recipient="owner@internal.test",channel=self.channel);args.update(kw);return mail.send_report(**args)
    def test_starttls(self):
        self.assertTrue(self.send()["ok"])
        ctx=self.conn.starttls.call_args.kwargs["context"]
        self.assertEqual(ctx.verify_mode,ssl.CERT_REQUIRED);self.assertTrue(ctx.check_hostname)
        self.assertEqual([c[0] for c in self.conn.method_calls],["ehlo","starttls","ehlo","login","send_message"])
    def test_ssl(self):
        self.channel.update(port=465,security="ssl");self.assertTrue(self.send()["ok"])
        ctx=self.tls.call_args.kwargs["context"];self.assertTrue(ctx.check_hostname);self.assertEqual(ctx.verify_mode,ssl.CERT_REQUIRED)
    def test_no_cross_tenant_fallback(self):
        with patch.dict(os.environ,{"SMTP_SERVER":"foreign.test","SMTP_USER":"foreign@test.org","SMTP_PASSWORD":"foreign-secret","SMTP_FROM":"foreign@test.org","SMTP_TO":"foreign@test.org"}):
            self.assertFalse(mail._smtp_settings({"tenant_scoped":True},"owner@internal.test")["ok"])
            cfg=mail._smtp_settings(dict(self.channel,tenant_scoped=True,username="",password=""),"owner@internal.test")
            self.assertEqual(cfg["username"],"");self.assertEqual(cfg["password"],"")
    def test_branding_and_literal_html(self):
        self.assertTrue(self.send(summary="<script>unsafe</script>")["ok"])
        body=self.conn.send_message.call_args.args[0].get_body(preferencelist=("html",)).get_content()
        for text in ["#1e293b","#ffffff","#ef4444","#f59e0b","&lt;script&gt;",'name="viewport"',"640"]:self.assertIn(text,body)
        self.assertNotIn("#09090b",body)
        self.assertNotIn("http://",body)
    def test_errors_do_not_leak(self):
        for exc in [smtplib.SMTPAuthenticationError(535,b"private-secret"),smtplib.SMTPDataError(550,b"private-secret"),smtplib.SMTPRecipientsRefused({"owner@internal.test":(550,b"private-secret")}),TimeoutError("private-secret"),ssl.SSLCertVerificationError("private-secret")]:
            with self.subTest(error=type(exc).__name__):
                self.conn.send_message.side_effect=exc;result=self.send();self.assertFalse(result["ok"]);self.assertNotIn("private-secret",str(result))
    def test_invalid_config(self):
        for cfg in [dict(self.channel,server="smtp.company.local"),dict(self.channel,port=0),dict(self.channel,port=True),dict(self.channel,password=""),dict(self.channel,password="password"),dict(self.channel,security="bad")]:
            self.assertFalse(mail._smtp_settings(cfg,"owner@internal.test")["ok"])
    def test_addresses(self):
        for value in ["x@example.com","x@company.local","a@b.org\nBcc:bad@b.org","a@b.org,c@d.org",""]:self.assertEqual(mail.usable_address(value),"")
        self.assertEqual(mail.usable_address("a@internal.test"),"a@internal.test")
    def test_relay_without_auth(self):
        self.channel.update(username="",password="");self.assertTrue(self.send()["ok"]);self.conn.login.assert_not_called()
    def test_refused_recipient(self):
        self.conn.send_message.return_value={"owner@internal.test":(550,b"private-secret")};self.assertFalse(self.send()["ok"])


class TemplateTests(unittest.TestCase):
    def test_full_dataset_and_limit(self):
        findings=[{"severity":"low","hostname":f"host-{i}","title":f"<unsafe {i}>"} for i in range(30)]
        body=mail.render_html("Tenant", "Summary", findings, "Title")
        self.assertIn("Всего находок</span><br><strong", body)
        self.assertIn(">30</strong>", body)
        self.assertIn("host-0", body)
        self.assertIn("host-4", body)
        self.assertNotIn("host-5", body)
        self.assertIn("&lt;unsafe 0&gt;", body)
    def test_unsupported_config_is_na(self):
        body=mail.render_html("Tenant", "Summary", [{"severity":"critical"}], "Title")
        self.assertIn(">н/д</strong>", body)
        self.assertNotIn("config_change", body)
    def test_table_only_and_no_tracker(self):
        body=mail.render_html("Tenant", "Summary", [], "Title", app_url="https://audit.example.test")
        self.assertEqual(body.count("<div"), 0)
        self.assertNotIn("pixel", body.lower())
        self.assertNotIn("utm_", body.lower())
        self.assertIn("https://audit.example.test", body)

if __name__ == "__main__":
    unittest.main()
