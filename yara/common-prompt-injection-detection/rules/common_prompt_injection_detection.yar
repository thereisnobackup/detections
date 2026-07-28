rule Prompt_Injection_Instruction_Override
{
    meta:
        description = "Detects instruction-override prompt injection pattern"
        category    = "prompt_injection"

    strings:
        $re1 = /(ignore|disregard|override|reset|discard|forget).{0,200}(previous|prior|above|current|everything|the|your).{0,200}(instruction(s)?|request|above)/ nocase
        $re2 = /(new|real).{0,200}(instruction(s)?|request|prompt)/ nocase
        $re3 = /you.{0,200}are.{0,200}now.{0,200}(an?.{0,200})?(unrestricted|unfiltered|uncensored)?/ nocase
        $re4 = /act.{0,200}as.{0,200}(an?.{0,200})?(unrestricted|unfiltered|uncensored)?/ nocase

    condition:
        2 of them
}