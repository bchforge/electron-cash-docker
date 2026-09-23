#!/bin/sh

set -eu
umask 077

usage() {
    printf '%s\n' "Usage:" "  ./scripts/backup.sh backup <name>" "  ./scripts/backup.sh restore <name>" >&2
}

fail() {
    printf '%s\n' "[!] $1" >&2
    exit 1
}

[ "$#" -eq 2 ] || { usage; exit 2; }
OPERATION=$1
RAW_NAME=$2
case "$OPERATION" in
    backup|restore) ;;
    *) usage; exit 2 ;;
esac

case "$RAW_NAME" in
    ''|.|..|*/*|*\\*|*..*|*[!A-Za-z0-9._-]*) fail "Invalid backup name." ;;
esac
case "$RAW_NAME" in
    *.ecd.gpg) NAME=${RAW_NAME%.ecd.gpg} ;;
    *) NAME=$RAW_NAME ;;
esac
case "$NAME" in
    ''|.|..|*..*|*[!A-Za-z0-9._-]*) fail "Invalid backup name." ;;
esac

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd -P)
PROJECT_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd -P)
BACKUP_DIR=${BACKUP_DIR:-$PROJECT_DIR/backups}

command -v docker >/dev/null 2>&1 || fail "Docker is required."
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required."

if [ -L "$BACKUP_DIR" ] || { [ -e "$BACKUP_DIR" ] && [ ! -d "$BACKUP_DIR" ]; }; then
    fail "Backup directory is not safe."
fi
mkdir -p "$BACKUP_DIR"
chmod 770 "$BACKUP_DIR"

COMPOSE_ENV=$(docker compose --project-directory "$PROJECT_DIR" config --environment) || \
    fail "Compose environment is unavailable."
IMAGE=${IMAGE:-}
EC_VERSION=${EC_VERSION:-}
TESTNET4=${TESTNET4:-}
ECD_WALLET_VOLUME=${ECD_WALLET_VOLUME:-}
while IFS= read -r line; do
    case "$line" in
        ELECTRON_CASH_IMAGE=*) [ -n "$IMAGE" ] || IMAGE=${line#ELECTRON_CASH_IMAGE=} ;;
        EC_VERSION=*) [ -n "$EC_VERSION" ] || EC_VERSION=${line#EC_VERSION=} ;;
        TESTNET4=*) [ -n "$TESTNET4" ] || TESTNET4=${line#TESTNET4=} ;;
        ECD_WALLET_VOLUME=*) [ -n "$ECD_WALLET_VOLUME" ] || ECD_WALLET_VOLUME=${line#ECD_WALLET_VOLUME=} ;;
    esac
done <<EOF
$COMPOSE_ENV
EOF
EC_VERSION=${EC_VERSION:-4.4.6}
TESTNET4=${TESTNET4:-false}
ECD_WALLET_VOLUME=${ECD_WALLET_VOLUME:-bchforge-electron-cash-data}
IMAGE=${IMAGE:-electron-cash:$EC_VERSION}

case "$ECD_WALLET_VOLUME" in
    ''|*[!A-Za-z0-9_.-]*) fail "Compose selected an unsafe wallet volume name." ;;
esac
case "$TESTNET4" in
    true) BACKUP_NETWORK=testnet4 ;;
    false) BACKUP_NETWORK=mainnet ;;
    *) fail "Compose selected an invalid Electron Cash network." ;;
esac
[ -n "$IMAGE" ] || fail "Compose did not provide an Electron Cash image."
docker volume inspect "$ECD_WALLET_VOLUME" >/dev/null 2>&1 || \
    fail "The configured Electron Cash wallet volume does not exist. Start the stack first."

PROJECT_NAME=$(basename "$PROJECT_DIR")
PROJECT_ID=$(printf '%s' "$PROJECT_NAME" | tr -c 'A-Za-z0-9._-' '-')
PROJECT_ID=${PROJECT_ID%-}
PROJECT_ID=${PROJECT_ID:-electron-cash-docker}
STATE_HOME=${XDG_STATE_HOME:-${HOME:-$PROJECT_DIR}/.local/state}
STATE_DIR=$STATE_HOME/electron-cash-docker
PENDING=$STATE_DIR/restore-pending

RUNNING_CONTAINER=
BACKUP_WAS_RUNNING=false
RESTORE_ACTIVE=false
ROLLBACK_VOLUME=
PASSPHRASE=
ROLLBACK_MANAGED_LABEL=com.bchforge.electron-cash-docker.managed
ROLLBACK_PROJECT_LABEL=com.bchforge.electron-cash-docker.project

is_running() {
    RUNNING_CONTAINER=$(docker compose --project-directory "$PROJECT_DIR" ps -q --status running electron-cash 2>/dev/null || true)
    [ -n "$RUNNING_CONTAINER" ]
}

wait_for_healthy() {
    deadline=$(( $(date +%s) + 180 ))
    last_state=not-started
    while [ "$(date +%s)" -lt "$deadline" ]; do
        container=$(docker compose --project-directory "$PROJECT_DIR" ps -q --status running electron-cash 2>/dev/null || true)
        if [ -n "$container" ]; then
            last_state=$(docker inspect --format '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$container" 2>/dev/null || printf '%s' unavailable)
            case "$last_state" in
                running\|healthy) return 0 ;;
                exited\|*|dead\|*|*\|unhealthy) break ;;
            esac
        fi
        sleep 2
    done
    printf '%s\n' "[!] Electron Cash did not become healthy ($last_state)." >&2
    return 1
}

stop_service() {
    if is_running; then
        docker compose --project-directory "$PROJECT_DIR" stop electron-cash >/dev/null || return 1
    fi
    attempts=0
    while is_running && [ "$attempts" -lt 30 ]; do
        sleep 1
        attempts=$((attempts + 1))
    done
    if is_running; then
        printf '%s\n' "[!] Electron Cash did not stop." >&2
        return 1
    fi
}

start_service() {
    docker compose --project-directory "$PROJECT_DIR" up -d --no-deps electron-cash >/dev/null || return 1
    wait_for_healthy
}

ensure_service_stopped() {
    if is_running; then
        stop_service
    fi
}

ensure_volume_unused() {
    attempts=0
    while :; do
        users=$(docker ps -q --filter "volume=$ECD_WALLET_VOLUME" 2>/dev/null || true)
        [ -z "$users" ] && return 0
        [ "$attempts" -lt 30 ] || break
        sleep 1
        attempts=$((attempts + 1))
    done
    printf '%s\n' "[!] The wallet volume is still in use." >&2
    return 1
}

helper_security() {
    printf '%s\n' \
        "--pull=never" "--rm" "--network" "none" "--read-only" \
        "--cap-drop=ALL" "--cap-add=DAC_OVERRIDE" "--cap-add=CHOWN" \
        "--cap-add=FOWNER" "--security-opt" "no-new-privileges:true" \
        "--user" "0:0" "--tmpfs" "/tmp:rw,noexec,nosuid,size=256m"
}

run_create() {
    docker run -i $(helper_security) \
        --mount "type=volume,src=$ECD_WALLET_VOLUME,dst=/wallet,readonly" \
        --mount "type=bind,src=$BACKUP_DIR,dst=/backups" \
        -e "BACKUP_NETWORK=$BACKUP_NETWORK" -e "EC_VERSION=$EC_VERSION" \
        --entrypoint /home/electroncash/backup.sh "$IMAGE" \
        create "/backups/$NAME.ecd.gpg"
}

run_verify() {
    docker run -i $(helper_security) \
        --mount "type=bind,src=$BACKUP_DIR,dst=/backups,readonly" \
        -e "BACKUP_NETWORK=$BACKUP_NETWORK" -e "EC_VERSION=$EC_VERSION" \
        --entrypoint /home/electroncash/backup.sh "$IMAGE" \
        verify "/backups/$NAME.ecd.gpg"
}

run_snapshot() {
    docker run $(helper_security) \
        --mount "type=volume,src=$ECD_WALLET_VOLUME,dst=/wallet,readonly" \
        --mount "type=volume,src=$ROLLBACK_VOLUME,dst=/snapshot" \
        -e "BACKUP_NETWORK=$BACKUP_NETWORK" -e "EC_VERSION=$EC_VERSION" \
        --entrypoint /home/electroncash/backup.sh "$IMAGE" snapshot /snapshot
}

run_replace() {
    docker run -i $(helper_security) \
        --mount "type=volume,src=$ECD_WALLET_VOLUME,dst=/wallet" \
        --mount "type=bind,src=$BACKUP_DIR,dst=/backups,readonly" \
        -e "BACKUP_NETWORK=$BACKUP_NETWORK" -e "EC_VERSION=$EC_VERSION" \
        --entrypoint /home/electroncash/backup.sh "$IMAGE" \
        replace "/backups/$NAME.ecd.gpg"
}

run_restore_snapshot() {
    docker run $(helper_security) \
        --mount "type=volume,src=$ECD_WALLET_VOLUME,dst=/wallet" \
        --mount "type=volume,src=$ROLLBACK_VOLUME,dst=/snapshot,readonly" \
        -e "BACKUP_NETWORK=$BACKUP_NETWORK" -e "EC_VERSION=$EC_VERSION" \
        --entrypoint /home/electroncash/backup.sh "$IMAGE" restore-snapshot /snapshot
}

write_pending() {
    if [ -e "$PENDING" ] || [ -L "$PENDING" ]; then
        printf '%s\n' "[!] Restore interruption marker already exists; refusing to overwrite it." >&2
        return 1
    fi
    mkdir -p "$STATE_DIR"
    [ ! -L "$STATE_DIR" ] && [ -d "$STATE_DIR" ] || fail "Restore state directory is not safe."
    chmod 700 "$STATE_DIR" || return 1
    pending_tmp=$(mktemp "$STATE_DIR/.restore-pending.XXXXXX") || return 1
    {
        printf '%s\n' "electron-cash-docker-restore-pending-v1"
        printf 'wallet_volume=%s\n' "$ECD_WALLET_VOLUME"
        printf 'rollback_volume=%s\n' "$ROLLBACK_VOLUME"
        printf 'service_running=%s\n' "$BACKUP_WAS_RUNNING"
    } > "$pending_tmp" || { rm -f "$pending_tmp"; return 1; }
    chmod 600 "$pending_tmp" || { rm -f "$pending_tmp"; return 1; }
    if ! mv "$pending_tmp" "$PENDING"; then
        rm -f "$pending_tmp"
        return 1
    fi
}

read_pending() {
    [ ! -L "$PENDING" ] || fail "Restore marker is a symbolic link; refusing recovery."
    [ -e "$PENDING" ] || return 1
    [ -f "$PENDING" ] || fail "Restore marker is not a regular file; refusing recovery."
    pending_header=
    pending_wallet=
    pending_rollback=
    pending_running=
    pending_header_seen=false
    pending_wallet_seen=false
    pending_rollback_seen=false
    pending_running_seen=false
    while IFS= read -r line; do
        case "$line" in
            electron-cash-docker-restore-pending-v1)
                [ "$pending_header_seen" = false ] || fail "Restore marker is invalid; refusing duplicate fields."
                pending_header=$line
                pending_header_seen=true
                ;;
            wallet_volume=*)
                [ "$pending_wallet_seen" = false ] || fail "Restore marker is invalid; refusing duplicate fields."
                pending_wallet=${line#*=}
                pending_wallet_seen=true
                ;;
            rollback_volume=*)
                [ "$pending_rollback_seen" = false ] || fail "Restore marker is invalid; refusing duplicate fields."
                pending_rollback=${line#*=}
                pending_rollback_seen=true
                ;;
            service_running=*)
                [ "$pending_running_seen" = false ] || fail "Restore marker is invalid; refusing duplicate fields."
                pending_running=${line#*=}
                pending_running_seen=true
                ;;
            '') ;;
            *) fail "Restore marker is invalid; refusing to guess wallet state." ;;
        esac
    done < "$PENDING"
    [ "$pending_header" = electron-cash-docker-restore-pending-v1 ] || fail "Restore marker is invalid."
    case "$pending_wallet" in ''|*[!A-Za-z0-9_.-]*) fail "Restore marker has an unsafe wallet volume." ;; esac
    case "$pending_rollback" in ''|*[!A-Za-z0-9_.-]*) fail "Restore marker has an unsafe rollback volume." ;; esac
    case "$pending_running" in true|false) ;; *) fail "Restore marker has an invalid service state." ;; esac
    [ "$pending_wallet" = "$ECD_WALLET_VOLUME" ] || fail "Compose wallet selection changed during an interrupted restore."
    ROLLBACK_VOLUME=$pending_rollback
    BACKUP_WAS_RUNNING=$pending_running
    validate_rollback_volume
    return 0
}

validate_rollback_volume() {
    [ -n "$ROLLBACK_VOLUME" ] || fail "Restore rollback volume is missing."
    [ "$ROLLBACK_VOLUME" != "$ECD_WALLET_VOLUME" ] || fail "Restore rollback volume matches the live wallet."
    labels=$(docker volume inspect --format '{{index .Labels "com.bchforge.electron-cash-docker.managed"}}|{{index .Labels "com.bchforge.electron-cash-docker.project"}}' "$ROLLBACK_VOLUME" 2>/dev/null) || \
        fail "Restore rollback volume is unavailable."
    [ "$labels" = "rollback|$PROJECT_ID" ] || fail "Restore rollback volume is not owned by this installation."
}

validate_state_dir() {
    if [ -L "$STATE_DIR" ] || { [ -e "$STATE_DIR" ] && [ ! -d "$STATE_DIR" ]; }; then
        fail "Restore state directory is not safe."
    fi
    if [ -d "$STATE_DIR" ]; then
        state_mode=$(stat -c '%a' "$STATE_DIR") || fail "Unable to inspect restore state directory."
        case "$state_mode" in
            *[2367]) fail "Restore state directory is group/world writable." ;;
        esac
        [ "$(stat -c '%u' "$STATE_DIR")" = "$(id -u)" ] || fail "Restore state directory is not owned by this user."
    fi
}

remove_rollback_volume() {
    [ -n "$ROLLBACK_VOLUME" ] || return 0
    docker volume rm "$ROLLBACK_VOLUME" >/dev/null
    ROLLBACK_VOLUME=
}

restore_prior_state() {
    if [ "$BACKUP_WAS_RUNNING" = true ]; then
        start_service
    else
        ensure_service_stopped
    fi
}

rollback_restore() {
    reason=$1
    printf '%s\n' "[!] Restore failed: $reason" >&2
    if ! stop_service; then
        printf '%s\n' "[!] Automatic rollback could not stop Electron Cash; marker and snapshot were preserved." >&2
        return 1
    fi
    if ! ensure_volume_unused; then
        printf '%s\n' "[!] Automatic rollback found the wallet volume still in use; marker and snapshot were preserved." >&2
        return 1
    fi
    if ! run_restore_snapshot; then
        printf '%s\n' "[!] Automatic rollback could not restore the previous wallet; marker and snapshot were preserved." >&2
        return 1
    fi
    if ! restore_prior_state; then
        printf '%s\n' "[!] Previous wallet data was restored, but the prior service state could not be recovered; marker and snapshot were preserved." >&2
        return 1
    fi
    if ! remove_rollback_volume; then
        printf '%s\n' "[!] Previous wallet was restored, but temporary rollback cleanup failed; marker was preserved." >&2
        return 1
    fi
    rm -f "$PENDING"
    printf '%s\n' "[+] Previous wallet restored; Electron Cash returned to its prior state." >&2
    return 0
}

recover_pending() {
    read_pending || return 0
    printf '%s\n' "[!] An interrupted restore was found. Restoring its saved wallet before continuing." >&2
    if ! rollback_restore "interrupted restore"; then
        exit 1
    fi
}

prompt_secret() {
    printf '%s' "$1" >&2
    if [ -t 0 ]; then
        stty -echo
        IFS= read -r PASSPHRASE
        stty echo
        printf '\n' >&2
    else
        IFS= read -r PASSPHRASE
    fi
    [ -n "$PASSPHRASE" ] || fail "Backup password cannot be empty."
}

prompt_confirmation() {
    printf '%s' "$1" >&2
    IFS= read -r answer || answer=
    case "$answer" in
        y|Y|yes|YES|Yes) return 0 ;;
        *) return 1 ;;
    esac
}

on_signal() {
    trap - INT TERM
    if [ "$RESTORE_ACTIVE" = true ]; then
        if [ -n "$ROLLBACK_VOLUME" ] && [ -f "$PENDING" ]; then
            rollback_restore "restore interrupted" || true
        else
            restore_prior_state || true
            remove_rollback_volume || true
        fi
    elif [ "$BACKUP_WAS_RUNNING" = true ]; then
        start_service || true
    fi
    exit 130
}
trap on_signal INT TERM

validate_state_dir
recover_pending

if is_running; then
    BACKUP_WAS_RUNNING=true
fi

ARCHIVE=$BACKUP_DIR/$NAME.ecd.gpg
if [ -e "$ARCHIVE" ] || [ -L "$ARCHIVE" ]; then
    [ "$OPERATION" = restore ] || fail "Backup already exists: $ARCHIVE"
    [ -f "$ARCHIVE" ] && [ ! -L "$ARCHIVE" ] || fail "Backup is not a safe regular file: $ARCHIVE"
else
    [ "$OPERATION" = backup ] || fail "Backup is missing: $ARCHIVE"
fi

if [ "$OPERATION" = backup ]; then
    prompt_secret "[?] Enter backup password: "
    FIRST_PASSWORD=$PASSPHRASE
    prompt_secret "[?] Confirm backup password: "
    if [ "$FIRST_PASSWORD" != "$PASSPHRASE" ]; then
        unset PASSPHRASE FIRST_PASSWORD
        fail "Backup passwords do not match."
    fi
    if [ "$BACKUP_WAS_RUNNING" = true ]; then
        printf '%s\n' "[*] Electron Cash is running; stopping it for a consistent backup." >&2
        stop_service || fail "Could not stop Electron Cash for backup."
    else
        printf '%s\n' "[*] Electron Cash is stopped; it will remain stopped." >&2
    fi
    if ! ensure_volume_unused; then
        error="wallet volume is still in use"
        if [ "$BACKUP_WAS_RUNNING" = true ]; then
            start_service || error="$error; Electron Cash could not be returned to healthy running state"
        fi
        unset PASSPHRASE FIRST_PASSWORD
        fail "$error"
    fi
    if ! printf '%s\n' "$PASSPHRASE" | run_create; then
        error="backup creation failed"
        if [ "$BACKUP_WAS_RUNNING" = true ]; then
            start_service || error="$error; Electron Cash could not be returned to healthy running state"
        fi
        unset PASSPHRASE FIRST_PASSWORD
        fail "$error"
    fi
    if [ "$BACKUP_WAS_RUNNING" = true ]; then
        start_service || fail "Backup completed, but Electron Cash could not be returned to healthy running state."
    fi
    unset PASSPHRASE FIRST_PASSWORD
    printf '%s\n' "[+] Backup created: $ARCHIVE"
    exit 0
fi

printf '%s\n' "Electron Cash Docker restore" "Backup: $NAME" "" "WARNING" >&2
if [ "$BACKUP_WAS_RUNNING" = true ]; then
    printf '%s\n' "Restoring this backup will replace the active wallet." "Electron Cash is running and will be stopped temporarily." "The current wallet will be saved for automatic rollback." >&2
else
    printf '%s\n' "Restoring this backup will replace the active wallet." "Electron Cash is currently stopped." "The current wallet will be saved for automatic rollback." >&2
fi
prompt_confirmation "Continue? [y/N] " || {
    printf '%s\n' "Restore cancelled." "No changes were made." >&2
    exit 0
}
prompt_secret "[?] Enter backup password: "
if ! printf '%s\n' "$PASSPHRASE" | run_verify; then
    unset PASSPHRASE
    fail "Backup validation failed; no live wallet data was changed."
fi

RESTORE_ACTIVE=true
if is_running; then
    BACKUP_WAS_RUNNING=true
fi
stop_service || fail "Could not stop Electron Cash before restore."
ensure_volume_unused || fail "Could not safely detach the wallet volume before restore."
    ROLLBACK_VOLUME=$(docker volume create \
     --label "$ROLLBACK_MANAGED_LABEL=rollback" \
     --label "$ROLLBACK_PROJECT_LABEL=$PROJECT_ID") || \
     fail "Could not create the temporary rollback snapshot."
    case "$ROLLBACK_VOLUME" in ''|*[!A-Za-z0-9_.-]*) fail "Docker returned an unsafe rollback volume name." ;; esac
    validate_rollback_volume
run_snapshot || {
    remove_rollback_volume || true
    restore_prior_state || true
    unset PASSPHRASE
    fail "Could not create a verified rollback snapshot; live wallet data was not replaced."
}
if ! write_pending; then
    remove_rollback_volume || true
    restore_prior_state || true
    unset PASSPHRASE
    fail "Could not record the minimal restore interruption marker; live wallet data was not replaced."
fi

if ! printf '%s\n' "$PASSPHRASE" | run_replace; then
    unset PASSPHRASE
    rollback_restore "selected backup could not be restored"
    exit 1
fi
if [ "$BACKUP_WAS_RUNNING" = true ]; then
    if ! start_service; then
        unset PASSPHRASE
        rollback_restore "restored wallet did not become healthy"
        exit 1
    fi
else
    if ! ensure_service_stopped; then
        unset PASSPHRASE
        rollback_restore "service state changed unexpectedly"
        exit 1
    fi
fi
if ! remove_rollback_volume; then
    unset PASSPHRASE
    printf '%s\n' "[!] Restore succeeded, but temporary rollback cleanup failed; marker was preserved." >&2
    exit 1
fi
rm -f "$PENDING"
unset PASSPHRASE
printf '%s\n' "[+] Restore completed successfully: $ARCHIVE"
