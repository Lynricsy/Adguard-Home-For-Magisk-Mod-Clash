# AdGuard Home For Magisk Mod Clash

把 [AdGuard Home For Magisk Mod](https://github.com/liuzq2002/Adguard-Home-For-Magisk-Mod) 内置的 AdGuard Home DNS 规则，定时转换为 mihomo 可直接加载的 `.mrs` 规则集。

## 产物

GitHub Actions 会每天拉取上游仓库，生成并发布这些 Release 资产：

| 文件 | mihomo behavior | 建议策略 | 说明 |
|---|---|---|---|
| `adguard_allow.mrs` | `domain` | `PASS` | 从 `@@` 例外规则抽取的放行集，只取消本项目的拦截 |
| `adguard_ads.mrs` | `domain` | `REJECT` | GOODBYEADS 和模块自定义域名拦截 |
| `adguard_malware.mrs` | `domain` | `REJECT` | URLHaus 恶意域名拦截 |
| `adguard_allow_ipcidr.mrs` | `ipcidr` | `PASS` | 从例外规则抽取的 IP，只取消本项目的拦截；非空时发布 |
| `adguard_ads_ipcidr.mrs` | `ipcidr` | `REJECT` | 从广告规则抽取的 IP；非空时发布 |
| `adguard_malware_ipcidr.mrs` | `ipcidr` | `REJECT` | 从恶意域名规则抽取的 IP；非空时发布 |
| `manifest.md` | - | - | 本次转换统计 |
| `SHA256SUMS` | - | - | Release 资产校验和 |

## 使用教程

### 1. 直接使用 Release

使用 `latest/download` 地址即可长期订阅最新产物。推荐把本项目规则放进 `sub-rules`，让 `@@` 例外规则使用 `PASS`：命中白名单时只退出 AdGuard 子规则，后续仍会继续匹配你自己的代理、直连、分流规则。

```yaml
rule-providers:
  adguard_allow:
    type: http
    behavior: domain
    format: mrs
    path: ./ruleset/adguard_allow.mrs
    url: https://github.com/Lynricsy/Adguard-Home-For-Magisk-Mod-Clash/releases/latest/download/adguard_allow.mrs
    interval: 86400

  adguard_allow_ipcidr:
    type: http
    behavior: ipcidr
    format: mrs
    path: ./ruleset/adguard_allow_ipcidr.mrs
    url: https://github.com/Lynricsy/Adguard-Home-For-Magisk-Mod-Clash/releases/latest/download/adguard_allow_ipcidr.mrs
    interval: 86400

  adguard_ads:
    type: http
    behavior: domain
    format: mrs
    path: ./ruleset/adguard_ads.mrs
    url: https://github.com/Lynricsy/Adguard-Home-For-Magisk-Mod-Clash/releases/latest/download/adguard_ads.mrs
    interval: 86400

  adguard_ads_ipcidr:
    type: http
    behavior: ipcidr
    format: mrs
    path: ./ruleset/adguard_ads_ipcidr.mrs
    url: https://github.com/Lynricsy/Adguard-Home-For-Magisk-Mod-Clash/releases/latest/download/adguard_ads_ipcidr.mrs
    interval: 86400

  adguard_malware:
    type: http
    behavior: domain
    format: mrs
    path: ./ruleset/adguard_malware.mrs
    url: https://github.com/Lynricsy/Adguard-Home-For-Magisk-Mod-Clash/releases/latest/download/adguard_malware.mrs
    interval: 86400

rules:
  - SUB-RULE,(NETWORK,tcp),adguard_filter
  - SUB-RULE,(NETWORK,udp),adguard_filter
  # 这里继续放你原本的代理、直连、地区分流规则。
  - MATCH,DIRECT

sub-rules:
  adguard_filter:
    - RULE-SET,adguard_allow,PASS
    - RULE-SET,adguard_allow_ipcidr,PASS,no-resolve
    - RULE-SET,adguard_ads,REJECT
    - RULE-SET,adguard_ads_ipcidr,REJECT,no-resolve
    - RULE-SET,adguard_malware,REJECT
    - MATCH,PASS
```

上游当前样本中 `adguard_malware_ipcidr.txt` 为空，GitHub Actions 只会在对应 text 非空时发布 `.mrs`。如果后续 Release 出现 `adguard_malware_ipcidr.mrs`，再按同样格式添加 `behavior: ipcidr` provider 即可。

不要把 `adguard_allow` 直接写成 `DIRECT`，否则命中 `@@` 例外的域名会强制直连，无法继续匹配你后面的代理规则。也不要把 `PASS` 白名单和 `REJECT` 拦截规则平铺在同一个 `rules` 列表里，否则白名单 `PASS` 后仍可能继续命中后面的广告拦截规则。

### 2. 手动下载校验

```bash
mkdir -p ruleset
cd ruleset

base=https://github.com/Lynricsy/Adguard-Home-For-Magisk-Mod-Clash/releases/latest/download
curl -fLO "$base/adguard_allow.mrs"
curl -fLO "$base/adguard_ads.mrs"
curl -fLO "$base/adguard_malware.mrs"
curl -fLO "$base/adguard_allow_ipcidr.mrs"
curl -fLO "$base/adguard_ads_ipcidr.mrs"
curl -fLO "$base/SHA256SUMS"

sed 's#  dist/#  #' SHA256SUMS | sha256sum -c --ignore-missing
```

`SHA256SUMS` 里会列出本次 Release 的全部资产；`--ignore-missing` 允许你只下载自己启用的规则集。

### 3. 自动更新来源

仓库自带 GitHub Actions：每天 UTC `20:23` 拉取上游 [AdGuard Home For Magisk Mod](https://github.com/liuzq2002/Adguard-Home-For-Magisk-Mod)，转换 text rule-provider，调用 mihomo 生成 `.mrs`，再发布到 Release。需要立即刷新时，也可以在 Actions 页面手动运行 `Build and release mihomo MRS`。

## 转换策略

转换器只保留能被 mihomo `domain` / `ipcidr` MRS 安全表达的 DNS 级规则：

- `||example.com^` 转为 `+.example.com`
- `@@||example.com^` 转入 `adguard_allow`
- `||203.0.113.1^` 转为 `203.0.113.1/32`
- `||216.239.35.0/24^` 转为 `216.239.35.0/24`
- `||example.com/path.js^`、`||example.com:8443^` 会在能明确抽出 host 时降级为 `+.example.com`
- `||ads*-normal*.example.com^` 这类可被 mihomo domain MRS 编译的 wildcard 会保留为 `+.ads*-normal*.example.com`
- `@@://www.example.com/path`、`@@|blob:https://www.example.com` 会在能解析 URL host 时转入 `adguard_allow`
- `$important` 会被接受，但 mihomo 只能靠规则顺序近似优先级

这些降级转换会尽量减少丢规则，但会比 AdGuard 原始规则更宽。例如带路径的规则在 mihomo 里只能表达成整个域名命中；带 `@@` 的例外规则建议在 `sub-rules` 内用 `PASS` 近似“取消本项目拦截，然后回到主规则继续分流”。

这些规则会被跳过并写入统计：

- 正则规则，例如 `/example.*/`
- 纯路径规则或无法解析 host 的 URL 规则
- 只有 `$domain=` / `$app=` / `$client=` 这类条件、但没有拦截目标 host 的规则
- mihomo MRS 无法表达的 DNS 修饰符，例如 `$client`、`$dnstype`、`$dnsrewrite`；当前上游样本没有发现这三类 DNS 专用修饰符
- 无法安全映射到 Clash wildcard 的复杂模式

## 本地运行

```bash
git clone --depth=1 https://github.com/liuzq2002/Adguard-Home-For-Magisk-Mod upstream
uv run python -m scripts.build_rulesets --source upstream --output dist --upstream-commit "$(git -C upstream rev-parse HEAD)"
```

生成 `.mrs` 需要 mihomo：

```bash
mihomo convert-ruleset domain text dist/adguard_ads.txt dist/adguard_ads.mrs
mihomo convert-ruleset domain text dist/adguard_allow.txt dist/adguard_allow.mrs
mihomo convert-ruleset domain text dist/adguard_malware.txt dist/adguard_malware.mrs
```
