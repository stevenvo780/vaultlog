from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path
from typing import Sequence

from .gitops import GitOperationError, git_backup, git_root_for, install_git_hook, remote_url, vault_git_root_for
from .store import (
    DEFAULT_AUTOSAVE_SECONDS,
    DEFAULT_RECOVERY_PATH,
    DEFAULT_VAULT_DIR,
    JournalStore,
    VaultIntegrityReport,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vaultlog",
        description="Vaultlog: diario cifrado con CLI y TUI para terminal.",
    )
    parser.add_argument(
        "--vault",
        type=Path,
        default=DEFAULT_VAULT_DIR,
        help="Ruta del vault cifrado. Default: ./.vaultlog",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Inicializa el vault cifrado")
    add_init_args(init_parser)

    setup_parser = subparsers.add_parser("setup", help="Inicializa o prepara el repo para uso diario")
    add_init_args(setup_parser)
    setup_parser.add_argument("--install-hook", action="store_true", help="Instala el hook Git de seguridad")

    subparsers.add_parser("tui", help="Abre el editor TUI")
    subparsers.add_parser("open", help="Alias de tui")
    subparsers.add_parser("list", help="Lista entradas")

    new_parser = subparsers.add_parser("new", help="Crea una entrada desde CLI")
    new_parser.add_argument("--title", required=True, help="Título de la entrada")
    new_parser.add_argument(
        "--body",
        default=None,
        help="Contenido inicial. Evítalo para secretos: puede quedar en historial de shell.",
    )
    new_parser.add_argument("--body-file", type=Path, default=None, help="Lee el cuerpo desde un archivo")
    new_parser.add_argument("--body-stdin", action="store_true", help="Lee el cuerpo desde stdin")

    show_parser = subparsers.add_parser("show", help="Muestra una entrada desencriptada")
    show_parser.add_argument("identifier", help="Slug o entry_id")
    show_parser.add_argument("--metadata-only", action="store_true", help="No imprime el cuerpo")

    rotate_parser = subparsers.add_parser("change-password", help="Rota la contraseña maestra")
    rotate_parser.add_argument(
        "--recovery-path",
        type=Path,
        default=None,
        help="Nueva ruta para la nota de recuperación. Si se omite, se reutiliza la actual.",
    )

    configure_parser = subparsers.add_parser("configure", help="Ajusta tiempos de bloqueo y autosave")
    configure_parser.add_argument("--idle-lock-minutes", type=int, default=None)
    configure_parser.add_argument("--autosave-seconds", type=int, default=None)

    verify_parser = subparsers.add_parser("verify", help="Verifica que todo el vault desencripte")
    verify_parser.add_argument("--quiet", action="store_true", help="Solo devuelve código de salida")

    backup_parser = subparsers.add_parser("backup", help="Verifica y guarda el vault cifrado en Git")
    backup_parser.add_argument("--message", default=None, help="Mensaje de commit")
    backup_parser.add_argument("--push", action="store_true", help="Ejecuta git push después del commit")
    backup_parser.add_argument("--init-git", action="store_true", help="Inicializa Git dentro del vault si falta")
    backup_parser.add_argument("--remote", default=None, help="Configura origin del repo privado del vault")

    doctor_parser = subparsers.add_parser("doctor", help="Inspección rápida del vault")
    doctor_parser.add_argument("--verify", action="store_true", help="También desencripta todo el vault")

    subparsers.add_parser("scrub-recovery", help="Reescribe la nota de recuperación sin contraseña")
    subparsers.add_parser("install-git-hook", help="Instala hook pre-commit contra secretos/plaintext")
    return parser


def add_init_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--recovery-path",
        type=Path,
        default=DEFAULT_RECOVERY_PATH,
        help=f"Ruta de la nota de recuperación. Default: {DEFAULT_RECOVERY_PATH}",
    )
    parser.add_argument(
        "--idle-lock-minutes",
        type=int,
        default=5,
        help="Minutos de inactividad antes de auto-bloqueo.",
    )
    parser.add_argument(
        "--autosave-seconds",
        type=int,
        default=DEFAULT_AUTOSAVE_SECONDS,
        help="Segundos entre autosaves de la TUI.",
    )


def prompt_new_password() -> str:
    try:
        password = getpass.getpass("Nueva contraseña maestra: ")
        confirm = getpass.getpass("Repite la contraseña: ")
    except (EOFError, KeyboardInterrupt) as exc:
        raise SystemExit("\nCancelado.") from exc
    if not password:
        raise SystemExit("La contraseña no puede estar vacía.")
    if password != confirm:
        raise SystemExit("Las contraseñas no coinciden.")
    return password


def prompt_password(label: str = "Contraseña maestra: ") -> str:
    try:
        password = getpass.getpass(label)
    except (EOFError, KeyboardInterrupt) as exc:
        raise SystemExit("\nCancelado.") from exc
    if not password:
        raise SystemExit("La contraseña no puede estar vacía.")
    return password


def unlock_or_exit(store: JournalStore, label: str = "Contraseña maestra: "):
    try:
        return store.unlock(prompt_password(label))
    except FileNotFoundError as exc:
        raise SystemExit(f"Vault no inicializado en: {store.vault_dir}\nEjecuta: vaultlog setup") from exc
    except ValueError as exc:
        raise SystemExit("Contraseña incorrecta.") from exc


def resolve_store(vault_path: Path) -> JournalStore:
    return JournalStore(vault_path)


def command_init(args: argparse.Namespace) -> int:
    store = resolve_store(args.vault)
    password = prompt_new_password()
    session = store.initialize(
        password=password,
        recovery_path=args.recovery_path,
        idle_lock_minutes=args.idle_lock_minutes,
        autosave_seconds=args.autosave_seconds,
    )
    print(f"Vault inicializado en: {store.vault_dir}")
    print(f"Nota de recuperación segura: {args.recovery_path.expanduser()}")
    print(f"Idle lock: {session.config.idle_lock_minutes} minuto(s)")
    print(f"Autosave: {session.config.autosave_seconds} segundo(s)")
    return 0


def command_setup(args: argparse.Namespace) -> int:
    store = resolve_store(args.vault)
    if not store.initialized():
        result = command_init(args)
    else:
        result = 0
        print(f"Vault ya inicializado en: {store.vault_dir}")
    if args.install_hook:
        try:
            hook_paths = install_relevant_git_hooks(store)
        except GitOperationError as exc:
            raise SystemExit(str(exc)) from exc
        for hook_path in hook_paths:
            print(f"Hook instalado: {hook_path}")
    return result


def command_tui(args: argparse.Namespace) -> int:
    store = resolve_store(args.vault)
    session = unlock_or_exit(store)
    try:
        from .tui import JournalApp
    except ImportError as exc:
        raise SystemExit("Falta Textual. Instala el paquete .deb generado o ejecuta pip install -e .") from exc
    JournalApp(session).run()
    return 0


def command_list(args: argparse.Namespace) -> int:
    store = resolve_store(args.vault)
    session = unlock_or_exit(store)
    entries = session.list_entries()
    if not entries:
        print("Vault vacío.")
        return 0
    for entry in entries:
        print(f"{entry.slug:<24} {entry.updated_at}  {entry.title}")
    return 0


def command_new(args: argparse.Namespace) -> int:
    store = resolve_store(args.vault)
    session = unlock_or_exit(store)
    entry = session.create_entry(args.title, resolve_body(args))
    print(f"Creada: {entry.slug} ({entry.entry_id})")
    return 0


def resolve_body(args: argparse.Namespace) -> str:
    selected = [args.body is not None, args.body_file is not None, args.body_stdin]
    if sum(selected) > 1:
        raise SystemExit("Usa solo una fuente de cuerpo: --body, --body-file o --body-stdin.")
    if args.body_file is not None:
        return args.body_file.read_text(encoding="utf-8")
    if args.body_stdin:
        return sys.stdin.read()
    return args.body or ""


def command_show(args: argparse.Namespace) -> int:
    store = resolve_store(args.vault)
    session = unlock_or_exit(store)
    entry = session.get_entry(args.identifier)
    print(f"# {entry.title}")
    print(f"slug: {entry.slug}")
    print(f"created: {entry.created_at}")
    print(f"updated: {entry.updated_at}")
    if not args.metadata_only:
        print()
        print(entry.body)
    return 0


def command_change_password(args: argparse.Namespace) -> int:
    store = resolve_store(args.vault)
    current = prompt_password("Contraseña actual: ")
    new = prompt_new_password()
    try:
        store.change_password(current, new, recovery_path=args.recovery_path)
    except FileNotFoundError as exc:
        raise SystemExit(f"Vault no inicializado en: {store.vault_dir}\nEjecuta: vaultlog setup") from exc
    except ValueError as exc:
        raise SystemExit("Contraseña incorrecta.") from exc
    print("Contraseña rotada con staging verificado y recovery note segura.")
    return 0


def command_configure(args: argparse.Namespace) -> int:
    if args.idle_lock_minutes is None and args.autosave_seconds is None:
        raise SystemExit("Indica --idle-lock-minutes o --autosave-seconds.")
    store = resolve_store(args.vault)
    unlock_or_exit(store)
    config = store.update_config(
        idle_lock_minutes=args.idle_lock_minutes,
        autosave_seconds=args.autosave_seconds,
    )
    print(f"Idle lock: {config.idle_lock_minutes} minuto(s)")
    print(f"Autosave: {config.autosave_seconds} segundo(s)")
    return 0


def command_verify(args: argparse.Namespace) -> int:
    store = resolve_store(args.vault)
    session = unlock_or_exit(store)
    report = session.verify_integrity()
    if not args.quiet:
        print_report(report)
    return 0 if report.ok else 2


def command_backup(args: argparse.Namespace) -> int:
    store = resolve_store(args.vault)
    session = unlock_or_exit(store)
    report = session.verify_integrity()
    if not report.ok:
        print_report(report)
        return 2
    try:
        result = git_backup(
            store,
            message=args.message,
            push=args.push,
            init_git=args.init_git,
            remote=args.remote,
        )
    except GitOperationError as exc:
        raise SystemExit(str(exc)) from exc
    if result.committed:
        print(f"Commit creado: {result.message}")
    else:
        print("No hay cambios cifrados nuevos para commitear.")
    if result.pushed:
        print("Push completado.")
    elif result.push_skipped_reason:
        print(f"Push omitido: {result.push_skipped_reason}")
    print(f"Repo del vault: {result.repo}")
    return 0


def command_doctor(args: argparse.Namespace) -> int:
    store = resolve_store(args.vault)
    print(f"Vault path: {store.vault_dir}")
    print(f"Config exists: {store.config_path.exists()}")
    print(f"Manifest exists: {store.manifest_path.exists()}")
    print(f"Entries dir: {store.entries_dir}")
    if not store.initialized():
        return 0
    config = store.read_config()
    print(f"Created: {config.created_at}")
    print(f"Recovery note: {config.recovery_note}")
    print(f"Recovery note has plaintext secret: {'yes' if store.recovery_note_has_plaintext_secret() else 'no'}")
    print(f"Idle lock minutes: {config.idle_lock_minutes}")
    print(f"Autosave seconds: {config.autosave_seconds}")
    print(f"Vault permissions: {oct(store.vault_dir.stat().st_mode & 0o777)}")
    print(f"Config permissions: {oct(store.config_path.stat().st_mode & 0o777)}")
    project_git_root = git_root_for(store.vault_dir.parent)
    vault_git_root = vault_git_root_for(store)
    print(f"Project Git root: {project_git_root or 'not found'}")
    print(f"Vault Git root: {vault_git_root or 'not found'}")
    if vault_git_root is not None:
        print(f"Vault Git origin: {remote_url(vault_git_root) or 'not configured'}")
    if args.verify:
        session = unlock_or_exit(store)
        print_report(session.verify_integrity())
    return 0


def command_scrub_recovery(args: argparse.Namespace) -> int:
    store = resolve_store(args.vault)
    try:
        target = store.scrub_recovery_note()
    except FileNotFoundError as exc:
        raise SystemExit(f"Vault no inicializado en: {store.vault_dir}\nEjecuta: vaultlog setup") from exc
    print(f"Recovery note segura escrita en: {target}")
    return 0


def command_install_git_hook(args: argparse.Namespace) -> int:
    store = resolve_store(args.vault)
    try:
        hook_paths = install_relevant_git_hooks(store)
    except GitOperationError as exc:
        raise SystemExit(str(exc)) from exc
    for hook_path in hook_paths:
        print(f"Hook instalado: {hook_path}")
    return 0


def install_relevant_git_hooks(store: JournalStore) -> list[Path]:
    hook_paths: list[Path] = []
    seen: set[Path] = set()
    project_root = git_root_for(store.vault_dir.parent)
    if project_root is not None:
        hook_path = install_git_hook(project_root)
        hook_paths.append(hook_path)
        seen.add(hook_path)
    vault_root = vault_git_root_for(store)
    if vault_root is not None:
        hook_path = install_git_hook(vault_root)
        if hook_path not in seen:
            hook_paths.append(hook_path)
    if not hook_paths:
        raise GitOperationError("No hay repo Git para instalar hooks.")
    return hook_paths


def print_report(report: VaultIntegrityReport) -> None:
    for line in report.lines():
        print(line)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    commands = {
        "init": command_init,
        "setup": command_setup,
        "tui": command_tui,
        "open": command_tui,
        "list": command_list,
        "new": command_new,
        "show": command_show,
        "change-password": command_change_password,
        "configure": command_configure,
        "verify": command_verify,
        "backup": command_backup,
        "doctor": command_doctor,
        "scrub-recovery": command_scrub_recovery,
        "install-git-hook": command_install_git_hook,
    }
    return commands[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
