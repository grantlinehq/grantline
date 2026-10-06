-- Federation lookups use exact source/object IDs and evidenced edge endpoints.
-- Expression indexes also give PostgreSQL statistics for these JSON keys.
CREATE INDEX objects_federated_parent ON objects
 (run_id,source_id,(body->'attributes'->>'parent_object_id'))
 WHERE category='identities' AND kind='federated_credential';
CREATE INDEX objects_application_object ON objects
 (run_id,source_id,(body->'attributes'->>'object_id'))
 WHERE category='identities' AND kind='application_registration';
CREATE INDEX objects_federation_endpoints ON objects
 (run_id,(body->>'from'),(body->>'to'))
 WHERE category='relationships' AND kind='trusts_subject';
