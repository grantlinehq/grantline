"""Generate the public server contract without reading credentials or environment."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
S, B, I = {"type": "string"}, {"type": "boolean"}, {"type": "integer"}
def obj(properties, required=()):
    return {"type": "object", "properties": properties, "required": list(required), "additionalProperties": False}
def fields(names):
    return obj({k: S for k in names.split()}, names.split())
schemas = {
    "Error": obj({"error":S,"message":S,"fields":{"type":"array","items":obj({"field":S,"message":S,"line":I},["field","message"])},"warnings":{"type":"array","items":S}},["error"]), "Setup": fields("Token Organization Email Name Password"),
    "Login": fields("Email Password"), "AcceptTicket": fields("Token Name Password"),
    "Ticket": obj({"Email": S, "Role": {"enum": ["owner", "admin", "analyst", "viewer"]}, "send_email": B}, ["Email"]),
    "Workspace": obj({"Name": S, "schedule_minutes": {"type": "integer", "minimum": 15, "maximum": 10080}, "retention_days": {"type": "integer", "minimum": 1, "maximum": 365}, "Policy": S, "Bindings": S, "Revision": I,"acknowledge_coverage_reduction":B}, ["Name", "schedule_minutes", "retention_days", "Revision"]),
    "SSO": obj({"issuer": S, "client_id": S, "client_secret": {"type": "string", "writeOnly": True}, "enabled": B, "revision": I}, ["enabled", "revision"]),
    "Triage": obj({"State": {"enum": ["open", "in_review", "accepted_risk", "resolved"]}, "Assignee": S, "Reason": S, "expires_at": {"type": ["string", "null"], "format": "date-time"}, "Revision": I}, ["State", "Revision"]),
    "Integration": obj({"name": S, "config": {"type": "object", "description": "Provider configuration described at /docs/integrations/. Source IDs are server assigned; credentials do not belong in config.", "additionalProperties": True}, "credentials": {"type": "object", "additionalProperties": S, "writeOnly": True}, "secret_ref": S, "enabled": B, "revision": I}, ["name", "config"]),
    "Page": obj({"run_id": S, "items": {"type": "array", "items": {"type": "object"}}, "total": I, "page": I, "page_size": {"const": 50}}),
}
paths = {}
schemas["FindingContext"] = obj({
    "subject": S, "source_ids": {"type":"array","items":S}, "scope": S,
    "identity_count": I, "configuration_count": I, "unresolved_count": I,
    "facts": {"type":"array","items":obj({"label":S,"observed":S,"expected":S},["label","observed"])},
    "rule_outcome": S, "rule_limitations": {"type":"array","items":S},
    "policy_available": B, "policy_revision": {"type":["integer","null"]}, "observed_at": S
})
schemas["Page"]["properties"]["items"]["items"] = {"type":"object","properties":{"context":{"$ref":"#/components/schemas/FindingContext"}},"additionalProperties":True,"description":"Findings include API-only context. Counts distinguish native principals from configuration objects. Facts use known fields and the collection's recorded policy, never current workspace policy. Imported reports may have no original policy. The immutable exported report is unchanged."}
def array(items, nullable=False):
    return {"type":["array","null"] if nullable else "array","items":items}
rule = obj({
    "Severity":{"enum":["low","medium","high","critical"]},
    "ForbidNamespaceOnly":{"type":["boolean","null"]},
    "AllowedGrants":array(fields("SourceID RoleNativeID ServiceAccountNativeID Scope"),True),
    "AllowedVaultKubernetesBindings":array(fields("VaultSourceID RoleNativeID KubernetesSourceID ServiceAccountID"),True),
    "RequireOwnersFor":array(fields("SourceID ObjectID ObjectKind"),True),
    "AllowedAppRoles":array(fields("SourceID PrincipalObjectID ResourceObjectID AppRoleID"),True),
    "SeparatedEnvironments":array(fields("First Second"),True),
    "AllowedSharedIdentities":array(fields("First Second SourceID Kind NativeID Reason"),True),
},["Severity"])
schemas["PolicyRule"] = rule
schemas["PolicyForm"] = obj({"required_sources":array(S,True),"limits":obj({name:S for name in ["max_client_secret_validity","max_x509_svid_ttl","max_jwt_svid_ttl"]}),"rules":obj({f"IL{i:03d}":{"$ref":"#/components/schemas/PolicyRule"} for i in range(1,9)})},["required_sources","rules","limits"])
formref={"$ref":"#/components/schemas/PolicyForm"}
schemas["PolicyCandidate"]={"oneOf":[obj({"policy":S,"bindings":S,"revision":I,"preview":B},["policy","revision"]),obj({"form":formref,"bindings":S,"revision":I,"preview":B},["form","revision"])]}
schemas["PolicyEditor"] = obj({"revision":I,"mode":{"enum":["defaults","custom"]},"effective":formref,"defaults":formref,"yaml":S})
schemas["PolicyValidation"] = obj({"valid":B,"policy":S,"yaml":S,"effective":formref,"disabled_rules":array(S),"warnings":array(S),"requires_acknowledgement":B,"revision":I,"preview":{"type":"object","description":"Read-only simulation on the latest stored snapshot. available=false includes a message; otherwise includes run_id, run_kind, observed_at, fixture_notice, before/after finding counts, added/no_longer_reported counts, per-rule counts/outcomes, completeness and binding_issues.","additionalProperties":True}})
def route(path, method, summary, role="viewer", request=None, status=200, response=None, params=()):
    op = {"summary": summary, "operationId": method + "_" + path.strip("/").replace("/", "_").replace("{", "").replace("}", ""), "tags": [path.strip("/").split("/")[0]], "description": f"Minimum role: {role}." if role != "public" else "Available before sign-in.", "responses": {str(status): {"description": "Success"}, "default": {"description": "Structured error: 400 input; 401 session; 403 role/MFA/CSRF; 404 missing; 409 revision; 422 access test; 429 rate limit; 503 unavailable.", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}}}
    if role == "public": op["security"] = []
    if method not in ("get", "head"):
        op["description"] += " Requires configured public Origin. Signed-in writes also require X-Grantline-CSRF from GET /auth/session."
        if role != "public": op["parameters"] = [{"name": "X-Grantline-CSRF", "in": "header", "required": True, "schema": S}]
    for parameter in ("id", "category"):
        if "{" + parameter + "}" in path:
            op.setdefault("parameters", []).append({"name": parameter, "in": "path", "required": True, "schema": {"enum": ["identities", "findings", "relationships", "evidence"]} if parameter == "category" else S})
    for name in params: op.setdefault("parameters", []).append({"name": name, "in": "query", "schema": I if name == "page" else S})
    def ref(value): return {"$ref": "#/components/schemas/" + value} if isinstance(value, str) else value
    if request: op["requestBody"] = {"required": True, "content": {"application/json": {"schema": ref(request)}}}
    if response: op["responses"][str(status)]["content"] = {"application/json": {"schema": ref(response)}}
    paths.setdefault(path, {})[method] = op

route("/status", "get", "Setup state and sign-in capabilities", "public")
for path, title, request, status in [("setup", "Create organization and first Owner once", "Setup", 201), ("login", "Start password session; privileged accounts require TOTP", "Login", 200), ("accept", "Consume single-use invitation/recovery link", "AcceptTicket", 200), ("forgot", "Queue recovery mail without exposing account membership", fields("Email"), 202)]: route("/auth/"+path,"post",title,"public",request,status)
for path,title in [("session","Current account and CSRF token"),("mfa","TOTP enrollment state and initial setup key"),("sessions","Your active sessions")]: route("/auth/"+path,"get",title)
for path,title,request in [("logout","Revoke current session",None),("mfa","Verify TOTP and rotate pending session",fields("Code")),("password","Change password and revoke all sessions",fields("Current Password")),("sessions/revoke","Revoke your other sessions",None)]: route("/auth/"+path,"post",title,request=request)
route("/auth/oidc/start","post","Start OIDC with PKCE, nonce and optional invitation","public",obj({"Invitation":S}))
route("/auth/oidc/link","post","Explicitly link IdP identity to current account",request=obj({"Invitation":S}))
route("/auth/oidc/callback","get","Verify IdP response and single-use state","public",status=303,params=["code","state"])
route("/users","get","List members")
route("/users/{id}","patch","Change role or disable; revokes sessions","admin",obj({"Role":S,"Disabled":B},["Role","Disabled"]))
route("/users/{id}/sessions/revoke","post","Revoke member sessions","admin")
for path in ["invitations","recovery"]: route("/"+path,"post","Create single-use account link, optionally email","admin","Ticket",201)
route("/overview","get","Selected report coverage and counts",params=["run"])
route("/objects/{category}","get","Search and page immutable report objects",response="Page",params=["run","q","source","kind","native","state","page"])
route("/objects/{category}/{id}","get","Object, bounded evidence, triage and comments",params=["run"])
paths["/objects/{category}/{id}"]["get"]["description"] += " Findings also return a top-level context (FindingContext); other categories omit it. Rule outcome/limitations cover the whole selected snapshot, not just this finding."
report={"$ref":"/docs/reference/report.schema.json"}
route("/report","get","Export immutable report",response=report,params=["run"])
route("/reports/import","post","Import historical report without creating connections","admin",report,201)
route("/graph","get","Bounded relationship neighborhood",params=["run","entity","depth","assertion","type"])
route("/integrations","get","List connections without credentials")
route("/integrations","post","Create encrypted connection","admin","Integration",201)
route("/integrations/{id}","put","Update by revision; omitted credentials retained","admin","Integration",201)
route("/integrations/{id}","delete","Remove credentials; retain historical reports","admin")
route("/integrations/{id}/test","post","Test metadata access and save coverage","admin")
route("/runs","get","Recent 100 attempts")
route("/runs","post","Queue collection; coalesce overlapping jobs","analyst",status=202)
route("/runs/{id}/cancel","post","Request cancellation","analyst",status=202)
route("/triage/{id}","put","Record review independently of policy outcome","analyst","Triage")
route("/comments/{id}","post","Add finding comment","analyst",fields("Body"),201)
route("/activity","get","Recent 200 audit events")
route("/settings","get","Read workspace settings","admin")
route("/settings","put","Version settings; organization rename requires Owner","admin","Workspace")
route("/settings/versions","get","Recent 100 configuration versions","admin")
route("/settings/policy","get","Effective policy, dynamic defaults and canonical YAML","admin",response="PolicyEditor")
route("/settings/policy/validate","post","Validate candidate and optionally simulate on saved evidence without mutation","admin","PolicyCandidate",response="PolicyValidation")
route("/settings/sso","get","Read SSO configuration without secret","owner")
route("/settings/sso","put","Version encrypted SSO configuration","owner","SSO")
document={"openapi":"3.1.0","info":{"title":"Grantline API","version":"0.1.0-dev","license":{"name":"Apache-2.0","identifier":"Apache-2.0"},"description":"Single-organization, cookie-authenticated API. HTTPS sessions use Secure, HttpOnly, SameSite=Lax cookies. No personal API tokens in v0.1."},"servers":[{"url":"/api/v1"}],"security":[{"session":[]}],"paths":paths,"components":{"securitySchemes":{"session":{"type":"apiKey","in":"cookie","name":"grantline_session"}},"schemas":schemas}}
encoded=json.dumps(document,indent=2)+"\n"
(ROOT/"internal/platform/openapi.json").write_text(encoded,encoding="utf-8")
public=ROOT/"docs/guide/public/reference"
public.mkdir(parents=True,exist_ok=True)
for kind in ["report","snapshot"]:
    schema=json.loads((ROOT/f"schema/{kind}/schema.json").read_text())
    schema["$id"]=f"{kind}.schema.json"
    if kind=="report":schema["properties"]["snapshot"]["$ref"]="snapshot.schema.json"
    (public/f"{kind}.schema.json").write_text(json.dumps(schema,indent=2)+"\n",encoding="utf-8")
(public/"openapi.json").write_text(encoded,encoding="utf-8")
print(f"Documented {sum(len(v) for v in paths.values())} API operations.")
