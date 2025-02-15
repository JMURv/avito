[![Go Coverage](https://github.com/JMURv/avito/wiki/coverage.svg)](https://raw.githack.com/wiki/JMURv/avito/coverage.html)

## Configuration

### App
Configuration files placed in `/configs/{local|dev|prod}.config.yaml`
Example file looks like that:

```yaml
serviceName: "svc-name"
secret: "DYHlaJpPiZ"

server:
  mode: "dev"
  port: 8080
  scheme: "http"
  domain: "localhost"

db:
  host: "localhost"
  port: 5432
  user: "postgres"
  password: "794613825Zx"
  database: "app_db"

jaeger:
  sampler:
    type: "const"
    param: 1
  reporter:
    LogSpans: true
    LocalAgentHostPort: "localhost:6831"
```

- Create your own `local.config.yaml` based on `example.config.yaml`
- Create your own `dev.config.yaml` (it is used in dev docker compose file)
- Create your own `prod.config.yaml` (it is used in prod)

### ENV
Docker compose files using `.env.dev` and `.env.prod` files located at `build/compose/env/` folder, so you need to create them
- Specify `DEV_ENV_FILE` and `PROD_ENV_FILE` vars in `build/Taskfile.yaml`

## Build

### Locally

In root folder run:

```shell
go build -o bin/main ./cmd/main.go
```

After that, you can run app via `./bin/main`

___

### Docker

Head to the `build` folder via:

```shell
cd build
```

After that, you can just start docker compose file that will build image automatically via:

```shell
task dc-dev
```

But if you need to build it manually run:

```shell
task dc-dev-build
```

## Run

### Locally

```shell
go run cmd/main.go
```

Or if you previously build the app, run it via:

```shell
go run bin/main
```

___

### Docker-Compose

Head to the `build` folder via:

```shell
cd build
```

Run dev:

```shell
task dc-dev
```

Run prod:

```shell
task dc-prod
```

___

### K8s

Apply manifests

```shell
task k-up
```

Shutdown manifests

```shell
task k-down
```

___

### Tests

There are tests for each layer, run them via `task` or manually:

```yaml
  t:
    desc: Run tests
    cmds:
      - "task t-hdl"
      - "task t-ctrl"
      - "task t-repo"
      - "task t-integ"

  t-hdl:
    desc: Test handlers
    cmds:
      - "task t-http"
      - "task t-grpc"

  t-http:
    desc: Test http handlers
    cmds:
      - "go test ./internal/hdl/http"
      - "go test -coverprofile=cov_http.out ./internal/hdl/http && go tool cover -func=cov_http.out"

  t-grpc:
    desc: Test grpc handlers
    cmds:
      - "go test ./internal/hdl/grpc"
      - "go test -coverprofile=cov_grpc.out ./internal/hdl/grpc && go tool cover -func=cov_grpc.out"

  t-ctrl:
    desc: Run ctrl tests
    cmds:
      - "go test ./internal/ctrl"
      - "go test -coverprofile=cov_ctrl.out ./internal/ctrl && go tool cover -func=cov_ctrl.out"

  t-repo:
    desc: Run repo tests
    cmds:
      - "go test ./internal/repo/db"
      - "go test -coverprofile=cov_repo.out ./internal/repo/db && go tool cover -func=cov_repo.out"

  t-integ:
    desc: Run integration tests
    cmds:
      - "go test ./tests/"
```

## Questions

```sql
SELECT u.balance, 
    	ARRAY_AGG(
             inv.item_id || '|' || inv.quantity || '|' || i.name
		) AS inventory,
    	ARRAY_AGG(
             t.from_user || '|' || t.to_user || '|' || t.amount
		) AS transactions
FROM users u
JOIN inventory inv ON inv.user_id=u.id
JOIN items i ON i.id=inv.item_id
JOIN transactions t ON t.from_user_id=u.id OR t.to_user_id=u.id
WHERE u.id=$1;
```