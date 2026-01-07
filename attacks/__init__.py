"""Attack scripts demonstrating CORS vulnerabilities"""

from attacks.models import AttackResult
from attacks.base_attack import BaseAttack
from attacks.brute_force import BruteForceAttack
from attacks.reflection import ReflectionAttack
from attacks.null_origin import NullOriginAttack
from attacks.permissive import PermissiveAttack
from attacks.vary_attack import VaryAttack

__all__ = [
    "AttackResult",
    "BaseAttack",
    "BruteForceAttack",
    "ReflectionAttack",
    "NullOriginAttack",
    "PermissiveAttack",
    "VaryAttack",
]
