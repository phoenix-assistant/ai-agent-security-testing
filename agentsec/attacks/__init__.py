"""Attack module registry."""

from agentsec.attacks.prompt_injection import PromptInjectionAttack
from agentsec.attacks.jailbreak import JailbreakAttack
from agentsec.attacks.data_exfiltration import DataExfiltrationAttack
from agentsec.attacks.tool_abuse import ToolAbuseAttack
from agentsec.attacks.ssrf import SSRFAttack
from agentsec.attacks.indirect_injection import IndirectInjectionAttack

ATTACK_REGISTRY: dict[str, type] = {
    "prompt_injection": PromptInjectionAttack,
    "jailbreak": JailbreakAttack,
    "data_exfiltration": DataExfiltrationAttack,
    "tool_abuse": ToolAbuseAttack,
    "ssrf": SSRFAttack,
    "indirect_injection": IndirectInjectionAttack,
}
