"""mlacp-core — the IO-free contract of the Multi-Layered Agentic
Communication Protocol.

Six layers, each ported from a reference architecture (see
docs/research/soviet-communications-architectures.md):

- layer 1  primary network / channels      (mlacp_engine.channels)
- layer 2  store-and-dump custody          (mlacp_core.custody)
- layer 3  communications grid             (mlacp_core.grid)
- layer 4  hierarchical directory           (mlacp_core.directory)
- layer 5  capability chain of custody      (mlacp_core.authority)
- layer 6  GOST cryptographic layer          (mlacp_core.gost)
"""

__version__ = "0.1.0"

from .addresses import Address  # noqa: F401
from .authority import CapabilityChain, DelegationEscalation, NotPermitted  # noqa: F401
from .custody import CustodyRelay  # noqa: F401
from .directory import HierarchicalDirectory  # noqa: F401
from .errors import (  # noqa: F401
    BusinessRefusal,
    InfrastructureFailure,
    MlacpError,
    UnknownKind,
    VersionMismatch,
)
from .grid import CommunicationsGrid, NoRoute  # noqa: F401
from .gost import (  # noqa: F401
    Kuznyechik,
    cbc_mac,
    ctr_decrypt,
    ctr_encrypt,
    secure_decrypt,
    secure_encrypt,
)
from .messages import (  # noqa: F401
    MAX_TTL,
    WIRE_KINDS,
    Bundle,
    Envelope,
    frame,
    parse_frame,
)
