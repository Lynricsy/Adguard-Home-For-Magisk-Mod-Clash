# AdRulesUltra

[![Build and release AdRulesUltra MRS](https://github.com/Lynricsy/AdRulesUltra/actions/workflows/build-release.yml/badge.svg)](https://github.com/Lynricsy/AdRulesUltra/actions/workflows/build-release.yml)
[![Latest release](https://img.shields.io/github/v/release/Lynricsy/AdRulesUltra?label=release&sort=semver&color=7c3aed)](https://github.com/Lynricsy/AdRulesUltra/releases/latest)
[![Release downloads](https://img.shields.io/github/downloads/Lynricsy/AdRulesUltra/total?label=downloads&color=0891b2)](https://github.com/Lynricsy/AdRulesUltra/releases)
![Ads domains](https://img.shields.io/badge/dynamic/json?label=ads%20domains&query=%24.badges.ads_domains&url=https%3A%2F%2Fgithub.com%2FLynricsy%2FAdRulesUltra%2Freleases%2Flatest%2Fdownload%2Fstats.json&color=dc2626)
![Allow domains](https://img.shields.io/badge/dynamic/json?label=allow%20domains&query=%24.badges.allow_domains&url=https%3A%2F%2Fgithub.com%2FLynricsy%2FAdRulesUltra%2Freleases%2Flatest%2Fdownload%2Fstats.json&color=16a34a)
![Malware domains](https://img.shields.io/badge/dynamic/json?label=malware%20domains&query=%24.badges.malware_domains&url=https%3A%2F%2Fgithub.com%2FLynricsy%2FAdRulesUltra%2Freleases%2Flatest%2Fdownload%2Fstats.json&color=f97316)
![Total rules](https://img.shields.io/badge/dynamic/json?label=total%20rules&query=%24.badges.total_rules&url=https%3A%2F%2Fgithub.com%2FLynricsy%2FAdRulesUltra%2Freleases%2Flatest%2Fdownload%2Fstats.json&color=2563eb)
![MRS size](https://img.shields.io/badge/dynamic/json?label=main%20MRS&query=%24.badges.ads_mrs_size&url=https%3A%2F%2Fgithub.com%2FLynricsy%2FAdRulesUltra%2Freleases%2Flatest%2Fdownload%2Fstats.json&color=9333ea)

AdRulesUltra 是一个独立的广告与恶意域名规则聚合项目。它定时拉取多个上游 DNS 规则源，合并、去重并转换为 mihomo 可直接加载的 `.mrs` 规则集。

当前合并的上游：

- [AdGuard Home For Magisk Mod](https://github.com/liuzq2002/Adguard-Home-For-Magisk-Mod)
- [anti-AD](https://github.com/privacy-protection-tools/anti-AD)
- [Coolapk 1007 reward](https://raw.githubusercontent.com/lingeringsound/10007/main/reward)

## 产物

GitHub Actions 会每天拉取上游仓库，生成并发布这些 Release 资产：

| 文件 | mihomo behavior | 建议策略 | 说明 |
|---|---|---|---|
| `adrules_ultra_allow.mrs` | `domain` | `PASS` | 从 `@@` 例外规则抽取的放行集，只取消本项目的拦截 |
| `adrules_ultra_ads.mrs` | `domain` | `REJECT` | 多上游广告域名拦截 |
| `adrules_ultra_malware.mrs` | `domain` | `REJECT` | 恶意域名拦截 |
| `adrules_ultra_allow_ipcidr.mrs` | `ipcidr` | `PASS` | 从例外规则抽取的 IP，只取消本项目的拦截；非空时发布 |
| `adrules_ultra_ads_ipcidr.mrs` | `ipcidr` | `REJECT` | 从广告规则抽取的 IP；非空时发布 |
| `adrules_ultra_malware_ipcidr.mrs` | `ipcidr` | `REJECT` | 从恶意域名规则抽取的 IP；非空时发布 |
| `manifest.md` | - | - | 本次转换统计和上游提交 |
| `stats.json` | - | - | README 动态徽章读取的规则数量和 MRS 体积 |
| `SHA256SUMS` | - | - | Release 资产校验和 |

## 使用教程

### 1. 直接使用 Release

使用 `latest/download` 地址即可长期订阅最新产物。推荐把本项目规则放进 `sub-rules`，让 `@@` 例外规则使用 `PASS`：命中白名单时只退出 AdRulesUltra 子规则，后续仍会继续匹配你自己的代理、直连、地区分流规则。

```yaml
rule-providers:
  adrules_ultra_allow:
    type: http
    behavior: domain
    format: mrs
    path: ./ruleset/adrules_ultra_allow.mrs
    url: https://github.com/Lynricsy/AdRulesUltra/releases/latest/download/adrules_ultra_allow.mrs
    interval: 86400

  adrules_ultra_allow_ipcidr:
    type: http
    behavior: ipcidr
    format: mrs
    path: ./ruleset/adrules_ultra_allow_ipcidr.mrs
    url: https://github.com/Lynricsy/AdRulesUltra/releases/latest/download/adrules_ultra_allow_ipcidr.mrs
    interval: 86400

  adrules_ultra_ads:
    type: http
    behavior: domain
    format: mrs
    path: ./ruleset/adrules_ultra_ads.mrs
    url: https://github.com/Lynricsy/AdRulesUltra/releases/latest/download/adrules_ultra_ads.mrs
    interval: 86400

  adrules_ultra_ads_ipcidr:
    type: http
    behavior: ipcidr
    format: mrs
    path: ./ruleset/adrules_ultra_ads_ipcidr.mrs
    url: https://github.com/Lynricsy/AdRulesUltra/releases/latest/download/adrules_ultra_ads_ipcidr.mrs
    interval: 86400

  adrules_ultra_malware:
    type: http
    behavior: domain
    format: mrs
    path: ./ruleset/adrules_ultra_malware.mrs
    url: https://github.com/Lynricsy/AdRulesUltra/releases/latest/download/adrules_ultra_malware.mrs
    interval: 86400

rules:
  - SUB-RULE,(NETWORK,tcp),adrules_ultra_filter
  - SUB-RULE,(NETWORK,udp),adrules_ultra_filter
  # 这里继续放你原本的代理、直连、地区分流规则。
  - MATCH,DIRECT

sub-rules:
  adrules_ultra_filter:
    - RULE-SET,adrules_ultra_allow,PASS
    - RULE-SET,adrules_ultra_allow_ipcidr,PASS,no-resolve
    - RULE-SET,adrules_ultra_ads,REJECT
    - RULE-SET,adrules_ultra_ads_ipcidr,REJECT,no-resolve
    - RULE-SET,adrules_ultra_malware,REJECT
    - MATCH,PASS
```

上游当前样本中 `adrules_ultra_malware_ipcidr.txt` 为空，GitHub Actions 只会在对应 text 非空时发布 `.mrs`。如果后续 Release 出现 `adrules_ultra_malware_ipcidr.mrs`，再按同样格式添加 `behavior: ipcidr` provider 即可。

不要把 `adrules_ultra_allow` 直接写成 `DIRECT`，否则命中 `@@` 例外的域名会强制直连，无法继续匹配你后面的代理规则。也不要把 `PASS` 白名单和 `REJECT` 拦截规则平铺在同一个 `rules` 列表里，否则白名单 `PASS` 后仍可能继续命中后面的广告拦截规则。

### 2. 手动下载校验

```bash
mkdir -p ruleset
cd ruleset

base=https://github.com/Lynricsy/AdRulesUltra/releases/latest/download
curl -fLO "$base/adrules_ultra_allow.mrs"
curl -fLO "$base/adrules_ultra_ads.mrs"
curl -fLO "$base/adrules_ultra_malware.mrs"
curl -fLO "$base/adrules_ultra_allow_ipcidr.mrs"
curl -fLO "$base/adrules_ultra_ads_ipcidr.mrs"
curl -fLO "$base/SHA256SUMS"

sed 's#  dist/#  #' SHA256SUMS | sha256sum -c --ignore-missing
```

`SHA256SUMS` 里会列出本次 Release 的全部资产；`--ignore-missing` 允许你只下载自己启用的规则集。

### 3. 自动更新来源

仓库自带 GitHub Actions：每天 UTC `20:23` 拉取三个上游，转换 text rule-provider，调用 mihomo 生成 `.mrs`，再发布到 Release。需要立即刷新时，也可以在 Actions 页面手动运行 `Build and release AdRulesUltra MRS`。

## 转换策略

转换器只保留能被 mihomo `domain` / `ipcidr` MRS 安全表达的 DNS 级规则：

- `||example.com^` 转为 `+.example.com`
- `@@||example.com^` 转入 `adrules_ultra_allow`
- `||203.0.113.1^` 转为 `203.0.113.1/32`
- `||216.239.35.0/24^` 转为 `216.239.35.0/24`
- `0.0.0.0 ads.example.com` 这类 hosts 规则转为 `ads.example.com`
- `||example.com/path.js^`、`||example.com:8443^` 会在能明确抽出 host 时降级为 `+.example.com`
- `||ads*-normal*.example.com^` 这类可被 mihomo domain MRS 编译的 wildcard 会保留为 `+.ads*-normal*.example.com`
- `@@://www.example.com/path`、`@@|blob:https://www.example.com` 会在能解析 URL host 时转入 `adrules_ultra_allow`
- `$important` 会被接受，但 mihomo 只能靠规则顺序近似优先级

这些降级转换会尽量减少丢规则，但会比上游原始规则更宽。例如带路径的规则在 mihomo 里只能表达成整个域名命中；带 `@@` 的例外规则建议在 `sub-rules` 内用 `PASS` 近似“取消本项目拦截，然后回到主规则继续分流”。

这些规则会被跳过并写入统计：

- 正则规则，例如 `/example.*/`
- 纯路径规则或无法解析 host 的 URL 规则
- 只有 `$domain=` / `$app=` / `$client=` 这类条件、但没有拦截目标 host 的规则
- mihomo MRS 无法表达的 DNS 修饰符，例如 `$client`、`$dnstype`、`$dnsrewrite`
- 无法安全映射到 Clash wildcard 的复杂模式

## 本地运行

```bash
git clone --depth=1 https://github.com/liuzq2002/Adguard-Home-For-Magisk-Mod upstream-adguard
git clone --depth=1 https://github.com/privacy-protection-tools/anti-AD upstream-anti-ad
curl -fsSL https://raw.githubusercontent.com/lingeringsound/10007/main/reward -o upstream-coolapk-1007-reward.txt

uv run python -m scripts.build_rulesets \
  --adguard-source upstream-adguard \
  --anti-ad-source upstream-anti-ad \
  --coolapk-1007-reward-source upstream-coolapk-1007-reward.txt \
  --output dist \
  --adguard-commit "$(git -C upstream-adguard rev-parse HEAD)" \
  --anti-ad-commit "$(git -C upstream-anti-ad rev-parse HEAD)" \
  --coolapk-1007-reward-commit "$(sha256sum upstream-coolapk-1007-reward.txt | cut -d ' ' -f 1)"
```

生成 `.mrs` 需要 mihomo：

```bash
mihomo convert-ruleset domain text dist/adrules_ultra_ads.txt dist/adrules_ultra_ads.mrs
mihomo convert-ruleset domain text dist/adrules_ultra_allow.txt dist/adrules_ultra_allow.mrs
mihomo convert-ruleset domain text dist/adrules_ultra_malware.txt dist/adrules_ultra_malware.mrs
```
