"""Compatibility API for the revised published prompt contract.
Historical benchmark-specific prompts are preserved in legacy_source.
"""
import json
from .revision_prompts import messages, normalize, BASE, GUIDANCE
ALIASES={"b1_direct_llm":"direct_llm","b2_llm4sa_style":"llm4sa_style",
         "b3_zerofalse_style":"zerofalse_style","ours_query_centered":"queryfpm"}
SYSTEM_PROMPTS={key:BASE+GUIDANCE for key in ALIASES}
def build_user_prompt(evidence, *, allowed_templates=None, mode="one-shot", view="zerofalse", baseline="b3_zerofalse_style"):
    return messages(evidence,allowed_templates or [],method=ALIASES.get(baseline,"matched_one_shot"),view=view)[1]["content"]
def judge_once(client,evidence,*,allowed_templates=None,mode="one-shot",view="zerofalse",
               baseline="b3_zerofalse_style",temperature=0,max_tokens=4096):
    prompt=messages(evidence,allowed_templates or [],method=ALIASES.get(baseline,"matched_one_shot"),view=view)
    raw,usage=client.chat_json(prompt,temperature=temperature,max_tokens=max_tokens)
    return normalize(raw),usage
def normalize_decision(decision,*,baseline="b3_zerofalse_style"):
    return normalize(decision)
def few_shot_examples(baseline): return []
