from __future__ import annotations

from dataclasses import dataclass
from time import monotonic

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Footer, Header, Input, Label, ListItem, ListView, Static, TextArea

from .gitops import GitOperationError, git_backup
from .models import EntryMeta
from .store import UnlockedVault, utc_now_iso


def generate_camouflage(slug: str) -> str:
    timestamp = utc_now_iso()
    return "\n".join(
        [
            f"# file: src/runtime/{slug or 'buffer'}.py",
            f"# generated_at = {timestamp}",
            "",
            "from dataclasses import dataclass",
            "",
            "@dataclass(slots=True)",
            "class EventStream:",
            "    cursor: int = 0",
            "    buffer: list[str] | None = None",
            "",
            "    def pull(self) -> list[str]:",
            "        if self.buffer is None:",
            "            self.buffer = []",
            "        snapshot = self.buffer[self.cursor:]",
            "        self.cursor = len(self.buffer)",
            "        return snapshot",
            "",
            "def reconcile_pipeline(events: list[str]) -> dict[str, int]:",
            "    report = {'processed': len(events), 'retries': 0, 'status': 1}",
            "    for token in events:",
            "        if token.startswith('warn:'):",
            "            report['retries'] += 1",
            "    return report",
        ]
    )


class EntryItem(ListItem):
    def __init__(self, entry: EntryMeta) -> None:
        self.entry = entry
        super().__init__(Label(f"notes/{entry.slug}.md"))


class PromptScreen(ModalScreen[str | None]):
    CSS = """
    PromptScreen {
        align: center middle;
    }

    #prompt-card {
        width: 60;
        height: auto;
        padding: 1 2;
        border: solid #1f6f5f;
        background: #06100d;
    }

    #prompt-title {
        text-style: bold;
        color: #8af0c9;
        padding-bottom: 1;
    }

    #prompt-help {
        color: #6fb9a2;
        padding-top: 1;
    }
    """

    BINDINGS = [Binding("escape", "cancel", "Cancel", show=False)]

    def __init__(self, title: str, *, value: str = "", password: bool = False) -> None:
        super().__init__()
        self.title = title
        self.value = value
        self.password = password

    def compose(self) -> ComposeResult:
        with Vertical(id="prompt-card"):
            yield Label(self.title, id="prompt-title")
            yield Input(value=self.value, password=self.password, id="prompt-input")
            yield Static("Enter para aceptar · Esc para cancelar", id="prompt-help")

    def on_mount(self) -> None:
        self.query_one("#prompt-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value.strip())

    def action_cancel(self) -> None:
        self.dismiss(None)


@dataclass(slots=True)
class EditorState:
    current_entry_id: str | None = None
    dirty: bool = False
    camouflage: bool = False
    locked: bool = False
    shadow_buffer: str = ""


class JournalApp(App[None]):
    CSS = """
    Screen {
        background: #020907;
        color: #d8f5df;
    }

    Header {
        background: #0d2a22;
        color: #d8f5df;
    }

    Footer {
        background: #04110d;
        color: #79c4a3;
    }

    #shell {
        height: 1fr;
    }

    #sidebar {
        width: 34;
        min-width: 28;
        border: solid #143d33;
        background: #06110d;
        padding: 1;
    }

    #main {
        border: solid #143d33;
        background: #030807;
    }

    #sidebar-title, #editor-title {
        color: #8af0c9;
        text-style: bold;
        padding: 0 1;
    }

    #sidebar-hint {
        color: #6fb9a2;
        padding: 1;
    }

    #meta {
        height: 4;
        color: #72c3aa;
        padding: 0 1;
    }

    #status {
        height: 1;
        color: #a7f0d4;
        background: #07140f;
        padding: 0 1;
    }

    ListView {
        height: 1fr;
        border: round #143d33;
        background: #08120f;
    }

    ListItem {
        color: #d8f5df;
    }

    ListItem.-highlight {
        background: #12382f;
        color: #d8f5df;
    }

    TextArea {
        height: 1fr;
        border: none;
    }
    """

    TITLE = "VAULTLOG // SECURE EDITOR"
    SUB_TITLE = "encrypted journal shell"
    BINDINGS = [
        Binding("ctrl+n", "new_entry", "New"),
        Binding("ctrl+r", "rename_entry", "Rename"),
        Binding("ctrl+s", "save_entry", "Save"),
        Binding("ctrl+b", "backup_vault", "Backup"),
        Binding("ctrl+l", "lock_session", "Lock"),
        Binding("f8", "toggle_camouflage", "Panic"),
        Binding("ctrl+g", "focus_entries", "Entries", show=False),
        Binding("ctrl+e", "focus_editor", "Editor", show=False),
        Binding("ctrl+q", "safe_exit", "Quit"),
    ]

    def __init__(self, session: UnlockedVault) -> None:
        super().__init__()
        self.session = session
        self.state = EditorState()
        self.last_activity = monotonic()
        self._suspend_changes = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="shell"):
            with Vertical(id="sidebar"):
                yield Static("VAULT FILES", id="sidebar-title")
                yield ListView(id="entries")
                yield Static("Ctrl+N crea una entrada nueva", id="sidebar-hint")
            with Vertical(id="main"):
                yield Static("notes/<empty>.md", id="editor-title")
                yield TextArea(
                    "",
                    language="markdown",
                    theme="vscode_dark",
                    soft_wrap=True,
                    show_line_numbers=True,
                    highlight_cursor_line=True,
                    id="editor",
                    placeholder="Vault vacío. Crea una entrada con Ctrl+N.",
                )
                yield Static("", id="meta")
                yield Static("Locked and encrypted.", id="status")
        yield Footer()

    @property
    def entries_view(self) -> ListView:
        return self.query_one("#entries", ListView)

    @property
    def editor(self) -> TextArea:
        return self.query_one("#editor", TextArea)

    @property
    def status(self) -> Static:
        return self.query_one("#status", Static)

    @property
    def meta(self) -> Static:
        return self.query_one("#meta", Static)

    @property
    def editor_title(self) -> Static:
        return self.query_one("#editor-title", Static)

    def on_mount(self) -> None:
        self._refresh_entries()
        self.set_interval(15, self._check_idle_lock)
        self.set_interval(max(1, self.session.config.autosave_seconds), self._autosave_dirty)
        self.editor.focus()

    def on_key(self) -> None:
        self.last_activity = monotonic()

    def on_mouse_move(self) -> None:
        self.last_activity = monotonic()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, EntryItem):
            self._load_entry(event.item.entry.entry_id)

    def on_text_area_changed(self, event: TextArea.Changed) -> None:
        if self._suspend_changes or self.state.camouflage or self.state.locked:
            return
        if self.state.current_entry_id is None:
            return
        self.state.dirty = True
        self.state.shadow_buffer = event.text_area.text
        self._update_status("modified // pending save")

    def action_new_entry(self) -> None:
        self.push_screen(PromptScreen("Título o alias de la entrada"), self._handle_new_entry)

    def action_rename_entry(self) -> None:
        if not self.state.current_entry_id:
            self.notify("No hay entrada activa", severity="warning")
            return
        current = self.session.get_entry(self.state.current_entry_id)
        self.push_screen(
            PromptScreen("Nuevo título", value=current.title),
            self._handle_rename_entry,
        )

    def action_save_entry(self) -> None:
        self._save_current_entry()

    def action_backup_vault(self) -> None:
        if self.state.locked:
            return
        self._save_current_entry(silent=True)
        report = self.session.verify_integrity()
        if not report.ok:
            self.notify("Vault no pasó verificación de integridad", severity="error")
            self._update_status("backup failed // integrity check")
            return
        try:
            result = git_backup(
                self.session.store,
                message=None,
                push=True,
                init_git=True,
            )
        except GitOperationError as exc:
            self.notify(str(exc)[:220], severity="error")
            self._update_status("backup failed // git")
            return
        if result.committed and result.pushed:
            self.notify("Backup cifrado commiteado y pusheado", severity="information")
            self._update_status("backup pushed")
        elif result.pushed:
            self.notify("Sin cambios cifrados nuevos; push ejecutado", severity="information")
            self._update_status("backup checked // pushed")
        elif result.push_skipped_reason:
            self.notify(f"Backup local creado; {result.push_skipped_reason}", severity="warning")
            self._update_status("backup committed // remote missing")
        else:
            self.notify("Sin cambios cifrados nuevos", severity="information")
            self._update_status("backup checked")

    def action_lock_session(self) -> None:
        if self.state.locked:
            return
        self._save_current_entry(silent=True)
        self.state.locked = True
        if not self.state.camouflage:
            self.state.shadow_buffer = self.editor.text
        self._replace_editor_text("// session locked //\nEnter the master password to continue.")
        self.editor.read_only = True
        self.editor_title.update("vault://locked")
        self.meta.update("Session is locked")
        self._update_status("locked // password required")
        self.push_screen(PromptScreen("Contraseña maestra", password=True), self._handle_unlock_attempt)

    def action_toggle_camouflage(self) -> None:
        if self.state.locked:
            return
        if not self.state.camouflage:
            self.state.dirty = self.state.dirty or self.editor.text != self.state.shadow_buffer
            self.state.camouflage = True
            self.state.shadow_buffer = self.editor.text
            self._show_camouflage()
            self._update_status("panic mode // hidden")
            return
        self.state.camouflage = False
        self._replace_editor_text(self.state.shadow_buffer)
        self.editor.read_only = False
        self._refresh_current_metadata()
        self._update_status("panic mode disabled")

    def _show_camouflage(self) -> None:
        slug = "buffer"
        if self.state.current_entry_id:
            slug = self.session.get_entry(self.state.current_entry_id).slug
        self._replace_editor_text(generate_camouflage(slug))
        self.editor.read_only = True
        self.editor_title.update(f"src/runtime/{slug}.py")
        self.meta.update("Camouflage mode active")

    def action_focus_entries(self) -> None:
        self.entries_view.focus()

    def action_focus_editor(self) -> None:
        self.editor.focus()

    def action_safe_exit(self) -> None:
        self._save_current_entry(silent=True)
        self.exit()

    def _handle_new_entry(self, title: str | None) -> None:
        if not title:
            return
        entry = self.session.create_entry(
            title,
            body=f"# {title}\n\nCreated: {utc_now_iso()}\n\n",
        )
        self._refresh_entries(select_entry_id=entry.entry_id)
        self._load_entry(entry.entry_id)
        self.notify(f"Entrada creada: {entry.slug}", severity="information")

    def _handle_rename_entry(self, title: str | None) -> None:
        if not title or not self.state.current_entry_id:
            return
        entry = self.session.rename_entry(self.state.current_entry_id, title)
        self._refresh_entries(select_entry_id=entry.entry_id)
        self._refresh_current_metadata()
        self.notify("Entrada renombrada", severity="information")

    def _handle_unlock_attempt(self, password: str | None) -> None:
        if not password:
            self.push_screen(PromptScreen("Contraseña maestra", password=True), self._handle_unlock_attempt)
            return
        if not self.session.verify_password(password):
            self.notify("Contraseña incorrecta", severity="error")
            self.push_screen(PromptScreen("Contraseña maestra", password=True), self._handle_unlock_attempt)
            return
        self.state.locked = False
        if self.state.camouflage:
            self._show_camouflage()
        else:
            self.editor.read_only = False
            self._replace_editor_text(self.state.shadow_buffer)
            self._refresh_current_metadata()
        self._update_status("unlocked")
        self.editor.focus()

    def _refresh_entries(self, select_entry_id: str | None = None) -> None:
        entries = self.session.list_entries()
        self.entries_view.clear()
        self.entries_view.extend(EntryItem(entry) for entry in entries)
        if not entries:
            self.state.current_entry_id = None
            self.editor_title.update("notes/<empty>.md")
            self.meta.update("No entries yet")
            self._replace_editor_text("")
            self._update_status("vault ready // create your first note")
            return
        target = select_entry_id or self.state.current_entry_id or entries[0].entry_id
        for index, entry in enumerate(entries):
            if entry.entry_id == target:
                self.entries_view.index = index
                break

    def _load_entry(self, entry_id: str) -> None:
        if self.state.camouflage or self.state.locked:
            return
        if self.state.current_entry_id == entry_id and not self.state.dirty:
            return
        self._save_current_entry(silent=True)
        record = self.session.get_entry(entry_id)
        self.state.current_entry_id = record.entry_id
        self.state.dirty = False
        self.state.shadow_buffer = record.body
        self._replace_editor_text(record.body)
        self.editor_title.update(f"notes/{record.slug}.md")
        self.meta.update(
            f"{record.title}\ncreated {record.created_at}\nupdated {record.updated_at}"
        )
        self._update_status(f"opened // {record.slug}")
        self.editor.focus()

    def _save_current_entry(self, silent: bool = False) -> None:
        if self.state.current_entry_id is None or self.state.locked:
            return
        body = self.state.shadow_buffer if self.state.camouflage else self.editor.text
        if not self.state.dirty and body == self.state.shadow_buffer:
            return
        record = self.session.update_entry(self.state.current_entry_id, body)
        self.state.dirty = False
        self.state.shadow_buffer = record.body
        if not silent:
            self._refresh_entries(select_entry_id=record.entry_id)
        self._refresh_current_metadata()
        if not silent:
            self.notify("Guardado cifrado", severity="information")
        self._update_status(f"saved // {record.updated_at}")

    def _refresh_current_metadata(self) -> None:
        if self.state.camouflage:
            return
        if not self.state.current_entry_id:
            self.meta.update("No active entry")
            return
        record = self.session.get_entry(self.state.current_entry_id)
        self.editor_title.update(f"notes/{record.slug}.md")
        self.meta.update(
            f"{record.title}\ncreated {record.created_at}\nupdated {record.updated_at}"
        )

    def _replace_editor_text(self, text: str) -> None:
        self._suspend_changes = True
        self.editor.load_text(text)
        self._suspend_changes = False

    def _update_status(self, message: str) -> None:
        self.status.update(message)

    def _check_idle_lock(self) -> None:
        if self.state.locked:
            return
        idle_seconds = monotonic() - self.last_activity
        if idle_seconds >= self.session.config.idle_lock_minutes * 60:
            self.action_lock_session()

    def _autosave_dirty(self) -> None:
        if self.state.dirty and not self.state.locked and not self.state.camouflage:
            self._save_current_entry(silent=True)
