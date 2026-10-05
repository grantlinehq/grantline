# Kubernetes with Helm

The chart runs **one application replica** with `Recreate` upgrades. Expect a short
interruption during upgrades. Production defaults to existing PostgreSQL and
independently managed Secrets. The optional bundled database is an evaluation
profile, not a highly available database.

## Prepare configuration

Create a namespace and independently managed Secret from private local files:

```sh
kubectl create namespace grantline
kubectl -n grantline create secret generic grantline-secrets \
  --from-file=database-url=/private/grantline/database-url \
  --from-file=encryption-key=/private/grantline/encryption-key \
  --from-file=setup-token=/private/grantline/setup-token
```

`database-url` is a PostgreSQL URL for a dedicated non-superuser application role.
For an external database require verified TLS. `encryption-key` contains 32 random
bytes encoded with standard base64 without `=` padding. `setup-token` is an
independent random string with at least 32 characters. Back up the encryption key
separately from the database. Kubernetes Secret base64 encoding is not encryption;
configure encryption at rest and least-privilege Secret access in your cluster.

The installation package includes `charts/grantline/examples/production.yaml`.
Copy it to `my-values.yaml` and set your public URL, Ingress host/class and existing
TLS Secret. Select a version or the image digest in the release's `release.json`.

```sh
helm template grantline oci://ghcr.io/grantlinehq/charts/grantline --version 0.1.0-rc.4 -n grantline -f my-values.yaml
helm upgrade --install grantline oci://ghcr.io/grantlinehq/charts/grantline --version 0.1.0-rc.4 -n grantline -f my-values.yaml --wait --timeout 5m
```

The release also contains `grantline-0.1.0-rc.4.tgz`; use that file in place of the
OCI reference for an independently downloaded chart. Verify its checksum and
signature using the [release guide](../operations/releases#verify-a-release).
Source developers can use the local `charts/grantline` directory.

Open your public URL, create the Owner with your setup token, and enroll an
authenticator. Add integrations through the application.

## Evaluation database

Enable `postgresql.enabled` and provide `postgresql.existingSecret`, containing
`postgres-password`. The application database URL must use that same password and
the service `<release>-grantline-postgres:5432`, database/user `grantline`.
Set `sslmode=disable` only for this internal evaluation connection; production
external databases should use verified TLS.

On a fresh PVC, the evaluation database creates `grantline` as a non-superuser
database owner. Bootstrap `postgres` administration is local to the database
container's Unix socket; its network password is removed during initialization.
Existing evaluation PVCs need the development database role check in the upgrade guide.

`examples/evaluation.yaml` expects a `grantline-secrets` application Secret and
a separate `grantline-database` password Secret. The chart never generates keys.
An evaluation PVC is retained on uninstall. A migration init container waits for
the database and must succeed before the app starts.

```sh
helm upgrade --install grantline oci://ghcr.io/grantlinehq/charts/grantline --version 0.1.0-rc.4 -n grantline \
  -f charts/grantline/examples/evaluation.yaml --wait --timeout 5m
kubectl -n grantline port-forward svc/grantline-grantline 8082:8080
```

Open `http://127.0.0.1:8082`. This address must match `publicURL`.

## Cluster observation is explicit

The application ServiceAccount has no Kubernetes API permissions and does not
automount a token. Enabling `observerRBAC.enabled` creates a **separate** observer
ServiceAccount and read/list permissions for namespaces, service accounts, pods,
deployments and RBAC metadata. It grants no secret access. Configure this observer
through the integration wizard with an appropriate, renewable credential; the
application does not automatically connect to its host cluster.

## Rendering without Helm installation

`helm template` produces standard manifests. Apply only after checking namespace,
Secret references, storage class, resources and public URL. Never commit generated
Secrets or real credentials to Git. Changing `replicaCount` away from 1 fails schema
validation. Read the [upgrade and recovery rules](../operations/upgrades) first.
