"""从标准输入读取 AdGuard DNS filter，仅转换域名规则。"""
import re
import sys
from pathlib import Path


def host_rules(mask):
    match = re.fullmatch(r"(\|\||\|)?([a-zA-Z0-9_.*-]+)(\^\|?|\|)?", mask)
    if not match:
        return []
    anchor, host, end = match.groups()
    literal = "*" not in host
    if literal and anchor == "||" and end:
        return [f"DOMAIN-SUFFIX,{host}"]
    if literal and ((anchor == "|" and end) or
                    (not anchor and not end and not host.startswith("."))):
        return [f"DOMAIN,{host}"]

    pattern = host if end else host + "*"
    if anchor == "||":
        patterns = [pattern, "*." + pattern]
    else:
        patterns = [pattern if anchor else "*" + pattern]
    return ["DOMAIN-WILDCARD," + re.sub(r"\*+", "*", p) for p in patterns]


def convert(lines):
    rules = {line.strip() for line in lines}
    rules = {rule for rule in rules if rule and not rule.startswith(("!", "#"))}
    # $badfilter 按原文禁用对应规则，与两者出现的顺序无关。
    disabled = {rule.removesuffix("$badfilter") for rule in rules if rule.endswith("$badfilter")}
    groups = {"allow": set(), "block-important": set(), "block": set()}
    skipped = 0
    for rule in rules - disabled:
        if rule.endswith("$badfilter"):
            continue
        if rule.startswith("@@"):
            group = "allow"
            mask = rule[2:]
        elif rule.endswith("$important"):
            group = "block-important"
            mask = rule.removesuffix("$important")
        else:
            group = "block"
            mask = rule

        # URL、正则及其他修饰符不转为域名规则，以免扩大匹配范围。
        entries = host_rules(mask)
        if entries:
            groups[group].update(entries)
        else:
            skipped += 1

    if not groups["block"]:
        raise ValueError("输入中没有可转换的普通屏蔽规则")
    for name, entries in groups.items():
        path = Path(__file__).with_name(f"{name}.list")
        path.write_text("".join(rule + "\n" for rule in sorted(entries)), encoding="utf-8")
    print(f"跳过 {skipped} 条不支持的规则", file=sys.stderr)


if __name__ == "__main__":
    convert(sys.stdin)
