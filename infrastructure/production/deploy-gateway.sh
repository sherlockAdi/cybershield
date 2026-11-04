#!/usr/bin/env bash
# Installed once, root-owned, as /usr/local/sbin/cybershield-deploy-gateway.
# The dedicated authorized_keys entry forces this command and disables forwarding.
set -Eeuo pipefail
umask 077
if [[ ! ${SSH_ORIGINAL_COMMAND:-} =~ ^deploy\ ([0-9a-f]{40})$ ]]; then
  echo 'Only deploy <40-character commit SHA> is allowed' >&2
  exit 64
fi
sha=${BASH_REMATCH[1]}
base=/opt/cybershield360
exec 9>"$base/private/deploy.lock"
flock -w 1200 9
release=$(mktemp -d "$base/releases/ci-${sha:0:12}-XXXXXX")
head -c 104857601 > "$release/source.tar"
if [[ $(stat -c %s "$release/source.tar") -gt 104857600 ]]; then
  echo 'Release archive exceeds 100 MiB' >&2; exit 65
fi
python3 - "$release" <<'PY'
import pathlib, sys, tarfile
root=pathlib.Path(sys.argv[1]); source=root/'source'; source.mkdir(mode=0o755)
with tarfile.open(root/'source.tar') as archive:
    members=archive.getmembers()
    if sum(m.size for m in members)>200*1024*1024 or len(members)>20000: raise SystemExit('Archive exceeds limits')
    for member in members:
        path=pathlib.PurePosixPath(member.name)
        if path.is_absolute() or '..' in path.parts or not (member.isfile() or member.isdir()): raise SystemExit('Unsafe archive member')
        if any(p in ('.git','.env','node_modules') for p in path.parts): raise SystemExit('Forbidden archive member')
    archive.extractall(source, members=members, filter='data')
# Source is repository code, never production secrets. Readable in the unprivileged image.
for path in source.rglob('*'):
    path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)
PY
image="cybershield360:$sha"
echo "Building frontend and backend: $sha"
docker build --label "org.opencontainers.image.revision=$sha" -f "$release/source/infrastructure/production/Dockerfile" -t "$image" "$release/source"
compose="$base/deployment/compose.yaml"
backup="$base/private/backups/deploy-${sha}-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -m 700 "$backup"
cp "$compose" "$backup/compose.yaml"
echo 'Backing up live database before migrations'
docker exec cybershield360-db-1 pg_dump -U cyber_bootstrap -d cybershield360 -Fc > "$backup/database.dump"
test -s "$backup/database.dump"
docker exec -i cybershield360-db-1 pg_restore --list < "$backup/database.dump" > /dev/null
cat > "$release/candidate.yaml" <<YAML
services:
  app:
    image: $image
  migrate:
    image: $image
YAML
compose_base=(docker compose --progress plain --env-file "$base/private/production.env" -f "$compose")
echo 'Applying database migrations; old application remains running'
"${compose_base[@]}" -f "$release/candidate.yaml" run --rm --no-deps migrate
# Only additive/backward-compatible migrations may ship automatically.
# Database restores are deliberately manual: rollback must not discard user data.
rollback() {
  status=$?
  trap - ERR
  echo 'Deployment failed; restoring the previous application image' >&2
  cp "$backup/compose.yaml" "$compose"
  "${compose_base[@]}" up -d --no-deps app || true
  echo "Database migration retained. Backup: $backup/database.dump" >&2
  exit "$status"
}
trap rollback ERR
python3 - "$compose" "$image" <<'PY'
import pathlib,re,sys
p=pathlib.Path(sys.argv[1]);text=p.read_text()
text,count=re.subn(r'(?m)^(    image: )cybershield360:[^\s]+$',lambda m:m[1]+sys.argv[2],text)
if count!=2:raise SystemExit('Expected app and migrate image entries')
tmp=p.with_suffix('.next');tmp.write_text(text);tmp.replace(p)
PY
"${compose_base[@]}" up -d --no-deps app
healthy=false
for attempt in $(seq 1 30); do
  if curl --fail --silent --max-time 5 http://127.0.0.1:14100/api/health | python3 -c 'import json,sys; assert json.load(sys.stdin)["status"]=="ok"' 2>/dev/null && curl --fail --silent --max-time 5 http://127.0.0.1:13100/ -o /dev/null; then
    healthy=true; break
  fi
  sleep 2
done
[[ "$healthy" == true ]]
curl --fail --silent --retry 3 --retry-delay 2 --max-time 15 https://cybershield360.vvvitsolutions.online/api/health | python3 -c 'import json,sys; assert json.load(sys.stdin)["status"]=="ok"'
curl --fail --silent --max-time 15 https://cybershield360.vvvitsolutions.online/ -o /dev/null
[[ $(docker inspect cybershield360-app-1 --format '{{.Config.Image}}') == "$image" ]]
printf '%s\n' "$sha" > "$base/deployment/current-revision"
trap - ERR
echo "DEPLOYED $sha; frontend, backend and database migrations verified"
