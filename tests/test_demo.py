import http.client,json,threading,unittest
from http.server import ThreadingHTTPServer
from urllib.parse import urlencode
from demo import build_app
from agentaudit.views import BANNER
class TestDemo(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.server=ThreadingHTTPServer(("127.0.0.1",0),build_app()); cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True); cls.thread.start(); cls.port=cls.server.server_address[1]
 @classmethod
 def tearDownClass(cls): cls.server.shutdown(); cls.server.server_close()
 def req(self,method,path,body=None,headers=None):
  c=http.client.HTTPConnection("127.0.0.1",self.port,timeout=5); c.request(method,path,body,headers or {}); r=c.getresponse(); data=r.read(); h=dict(r.getheaders()); c.close(); return r.status,data,h
 def test_flow(self):
  status,data,_=self.req("GET","/healthz"); self.assertEqual((status,data),(200,b"ok"))
  status,data,h=self.req("GET","/traces"); self.assertEqual(data.decode().count("href='/traces/"),3); self.assertIn(BANNER,data.decode()); self.assertIn("Content-Security-Policy",h)
  status,data,_=self.req("GET","/traces/"+"2"*32); self.assertIn("orphan",data.decode())
  form=urlencode({"trace":__import__("agentaudit.sample_data",fromlist=["send_sample"]).send_sample()}); status,_,h=self.req("POST","/send",form,{"Content-Type":"application/x-www-form-urlencoded","Content-Length":str(len(form))}); self.assertEqual(status,303)
  _,data,_=self.req("GET","/traces/"+"4"*32); self.assertIn("[EMAIL#",data.decode()); self.assertNotIn("fake.user@example.test",data.decode())
  _,data,_=self.req("POST","/audit/verify","",{"Content-Length":"0"}); self.assertIn("✅",data.decode())
  _,raw,_=self.req("GET","/audit/export.json"); doc=json.loads(raw); doc["entries"][0]["details"]["changed"]=True; form=urlencode({"document":json.dumps(doc)}); _,data,_=self.req("POST","/audit/tamper",form,{"Content-Length":str(len(form))}); self.assertIn("❌",data.decode())
  _,data,_=self.req("GET","/pack");
  for heading in ("Scope","Data inventory","Redaction summary","Residency and processing","Retention","Human approvals register","Audit-chain integrity","Mapping table"): self.assertIn(heading,data.decode())
  _,data,_=self.req("GET","/pack.json"); self.assertIn("Scope",json.loads(data))
  form=urlencode({"email":"person@example.test","intent":"Team $49"}); _,data,_=self.req("POST","/waitlist",form,{"Content-Length":str(len(form))}); self.assertIn("vref_",data.decode()); self.assertNotIn("person@example.test",data.decode())
  status,_,_=self.req("POST","/send",b"x"*70000,{"Content-Length":"70000"}); self.assertEqual(status,413)
  status,_,_=self.req("GET","/static/nope"); self.assertEqual(status,404)
 def test_oversized_ingested_cost_does_not_break_trace_list(self):
  document={"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"hostile-client"}}]},"scopeSpans":[{"spans":[{"traceId":"f"*32,"spanId":"e"*16,"name":"oversized cost","startTimeUnixNano":"1","endTimeUnixNano":"2","attributes":[{"key":"agentaudit.cost_usd","value":{"doubleValue":1e30}}]}]}]}]}
  body=json.dumps(document).encode(); status,_,_=self.req("POST","/v1/traces",body,{"Content-Type":"application/json","Content-Length":str(len(body))}); self.assertEqual(status,400)
  status,data,_=self.req("GET","/traces"); self.assertEqual(status,200); self.assertIn(BANNER,data.decode())
