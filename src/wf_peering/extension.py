from jinja2 import FileSystemLoader, PrefixLoader
from pathlib import Path
import json

from webfluid.exceptions import FrameworkException
from webfluid.extensions import FluidExtension
from webfluid.utils import enabled

PACKAGE = Path(__file__).resolve().parent
EXT_ID = "wf-peering"
PREFIX = EXT_ID.replace('-', '_')
ASSETS = f"/{EXT_ID}/static"
I18N_PREFIX = "PEERING_"


class Peering(FluidExtension):
    def __init__(self, fluid=None, *args, **kwargs):
        self._fluid = None
        self._role = None
        self._texts = ()
        super().__init__(fluid, *args, **kwargs)

    def expand_fluid(self, fluid, role=None, root=None, *_, **__):
        from .role import NodeRole, use

        if self._fluid is not None:
            if self._fluid is fluid and role in (None, self._role): return
            raise FrameworkException(f"{EXT_ID} is already expanded for another application or role.")
        if not isinstance(role, NodeRole):
            raise FrameworkException(
                f"{EXT_ID} needs a NodeRole: the peering Additive provides the host role, the peering app the peer role."
            )
        if not enabled("EXT_SQLALCHEMY"):
            raise FrameworkException(f"EXT_SQLALCHEMY is required for {EXT_ID} to work.")
        if not enabled("EXT_BABEL"):
            raise FrameworkException(f"EXT_BABEL is required for {EXT_ID} to work.")

        from .settings import configure
        settings = configure(fluid.config, role.name, Path(root) if root else Path(fluid.project_root))
        use(role)

        from .models import set_bind
        set_bind(fluid.config.get("PEERING_MODELS_DB_BIND"))

        from .services.identity import NodeIdentity
        NodeIdentity.setup()

        from webfluid.core.ext import babel
        from .i18n import translations
        babel.update_translations("messages", translations)
        self._texts = tuple(json.loads((PACKAGE / "i18n" / "default.json").read_text(encoding="utf-8")))

        fluid.static_files.add(ASSETS, PACKAGE / "static", f"{PREFIX}_static")
        fluid.static_prefixes.add(ASSETS)
        fluid.add_template_loader(PrefixLoader({
            PREFIX: FileSystemLoader(PACKAGE / "templates")
        }))

        if settings.schedule:
            if not enabled("EXT_SCHEDULING"):
                raise FrameworkException(f"EXT_SCHEDULING is required for {EXT_ID}, or set PEERING_SCHEDULE = False.")
            from .jobs import schedule
            schedule()

        self._fluid = fluid
        self._role = role

    async def render_status(self, api: str) -> str:
        if self._fluid is None: Peering.raise_unexpanded()
        from webfluid.core.ext import babel
        from webfluid.extensions.babel import get_locale
        from .services.identity import NodeIdentity
        from .settings import settings
        texts = { key.removeprefix(I18N_PREFIX): await babel.agettext(key) for key in self._texts }
        return await self._fluid.render(
            f"{PREFIX}/status.html", role=settings.role, node=NodeIdentity.node_id(), host=settings.assessed,
            api=api, static=ASSETS, texts=texts, lang=get_locale().language, debug=settings.debug
        )

    @property
    def role(self):
        if self._role is None: Peering.raise_unexpanded()
        return self._role


peering = Peering()
