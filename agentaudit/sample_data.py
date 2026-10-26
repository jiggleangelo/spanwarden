import json

def attr(key,value):
    field="intValue" if isinstance(value,int) else "doubleValue" if isinstance(value,float) else "stringValue"
    return {"key":key,"value":{field:value}}

def document(service,tid,spans):
    return {"resourceSpans":[{"resource":{"attributes":[attr("service.name",service)]},"scopeSpans":[{"spans":spans}]}]}

def span(tid,sid,parent,name,op,attrs=(),status=1):
    return {"traceId":tid,"spanId":sid,"parentSpanId":parent,"name":name,"startTimeUnixNano":"1729760000000000000","endTimeUnixNano":"1729760001000000000","attributes":[attr("gen_ai.operation.name",op),*attrs],"events":[],"status":{"code":status}}

def samples():
    a="1"*32
    refund=[span(a,"1"*16,"","Refund for fake customer alice@example.test +65 8123 4567","invoke_agent"),span(a,"2"*16,"1"*16,"lookup_order","execute_tool",[attr("gen_ai.tool.name","lookup_order"),attr("agentaudit.cost_usd",0.01)]),span(a,"3"*16,"1"*16,"draft reply","chat",[attr("gen_ai.request.model","demo-large"),attr("gen_ai.usage.input_tokens",800),attr("gen_ai.usage.output_tokens",120)]),span(a,"4"*16,"1"*16,"Supervisor approval","other",[attr("agentaudit.approval.approver","supervisor@example.test"),attr("agentaudit.approval.decision","approved"),attr("agentaudit.approval.policy","refunds-over-500-need-supervisor")])]
    b="2"*32
    kyc=[span(b,"5"*16,"","KYC planner","invoke_agent"),span(b,"6"*16,"5"*16,"extractor sub-agent","invoke_agent"),span(b,"7"*16,"6"*16,"extract document S0000001I","chat",[attr("gen_ai.request.model","demo-small"),attr("gen_ai.usage.input_tokens",1200),attr("gen_ai.usage.output_tokens",80)]),span(b,"8"*16,"f"*16,"orphan verifier call","chat",[attr("gen_ai.request.model","demo-large"),attr("gen_ai.usage.input_tokens",400),attr("gen_ai.usage.output_tokens",20)])]
    c="3"*32
    loan=[span(c,"9"*16,"","Loan precheck","invoke_agent"),span(c,"a"*16,"9"*16,"known model","chat",[attr("gen_ai.request.model","demo-small"),attr("gen_ai.usage.input_tokens",300),attr("gen_ai.usage.output_tokens",30)]),span(c,"b"*16,"9"*16,"unknown model","chat",[attr("gen_ai.request.model","mystery-model-x"),attr("gen_ai.usage.input_tokens",500)]),span(c,"c"*16,"9"*16,"credit tool error","execute_tool",[attr("gen_ai.tool.name","fake_credit_check")],2)]
    return [document("refund-agent",a,refund),document("kyc-doc-agent",b,kyc),document("loan-precheck",c,loan)]

def send_sample():
    tid="4"*32
    return json.dumps(document("visitor-agent",tid,[span(tid,"d"*16,"","Help fake.user@example.test from 8.8.8.8","invoke_agent")]),indent=2)
