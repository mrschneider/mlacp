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

__version__ = "0.2.2"

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
    Magma,
    ctr_acpkm_encrypt,
    ctr_acpkm_master,
    ctr_decrypt,
    ctr_encrypt,
    gcm_acpkm_decrypt,
    gcm_acpkm_encrypt,
    gcm_acpkm_master_decrypt,
    gcm_acpkm_master_encrypt,
    gost_mac,
    mgm_decrypt,
    mgm_encrypt,
    omac_acpkm_master,
    secure_decrypt,
    secure_encrypt,
    streebog_256,
    streebog_512,
    streebog_practical,
)
from .gost_ec import (  # noqa: F401
    CURVE_256A,
    CURVE_512A,
    generate_keypair,
    point_from_wire,
    point_to_wire,
    vko,
)
from .messages import (  # noqa: F401
    MAX_TTL,
    WIRE_KINDS,
    Bundle,
    Envelope,
    frame,
    parse_frame,
)
