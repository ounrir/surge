## DOMAIN-SET

| Source | Output |
| --- | --- |
| [dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list) | [china.txt](./china.txt) |

## RULE-SET

Source: [AdGuardSDNSFilter](https://github.com/AdguardTeam/AdGuardSDNSFilter)

| Output | Description |
| --- | --- |
| [block-important.list](./AdGuardSDNSFilter/block-important.list) | High-priority blocking rules |
| [block.list](./AdGuardSDNSFilter/block.list) | Standard blocking rules |
| [allow.list](./AdGuardSDNSFilter/allow.list) | Exceptions to standard blocking rules |

**Usage**

```ini
[Rule]
RULE-SET,AdGuardSDNSFilter,REJECT,pre-matching

[Ruleset AdGuardSDNSFilter]
RULE-SET,https://raw.githubusercontent.com/ounrir/surge/refs/heads/main/AdGuardSDNSFilter/block-important.list
AND,((RULE-SET,https://raw.githubusercontent.com/ounrir/surge/refs/heads/main/AdGuardSDNSFilter/block.list),(NOT,((RULE-SET,https://raw.githubusercontent.com/ounrir/surge/refs/heads/main/AdGuardSDNSFilter/allow.list))))
```

Priority: `block-important` > `allow` > `block`.

Updated weekly.
