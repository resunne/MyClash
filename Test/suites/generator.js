'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..');
const generator = require(path.join(ROOT, 'Tools', 'generate-singbox-rules.js'));
const TARGET = 'Script/mihomoScript.js';

// 上游数据源的本地副本（与 MyClash 同级的 sing-box-rules 仓库）；不存在时跳过同步类用例
const LOCAL_DIR = path.resolve(ROOT, '..', 'sing-box-rules');

/** 用本地数据源计算期望的生成区块；目录缺失时返回 null */
function expectedBlock() {
  if (!fs.existsSync(LOCAL_DIR)) return null;
  const ruleSets = {};
  for (const source of generator.SOURCES) {
    const json = JSON.parse(fs.readFileSync(path.join(LOCAL_DIR, source.file), 'utf8'));
    ruleSets[source.name] = generator.convertRuleSet(json, source.policy, source.file);
  }
  return generator.buildBlock(ruleSets);
}

/**
 * sing-box-rules 生成相关测试：
 * 1. 转换器把 sing-box 规则集正确映射为 mihomo 规则，无法表达的字段显式报错；
 * 2. Script/mihomoScript.js 的生成区块由数据源生成，未被手改 / 未过期；
 * 3. main() 输出的规则链里确实插入了这些规则。
 */
function runGeneratorTests(h, api, fx) {
  h.section('生成测试 · sing-box-rules 转换器');

  h.test('domain → DOMAIN，domain_suffix → DOMAIN-SUFFIX（去前导点、小写）', () => {
    const json = { version: 3, rules: [{ domain: ['Exact.COM'], domain_suffix: ['.Baowu.CN', 'baosight.com'] }] };
    h.assertDeep(generator.convertRuleSet(json, '直连'), [
      'DOMAIN,exact.com,直连',
      'DOMAIN-SUFFIX,baowu.cn,直连',
      'DOMAIN-SUFFIX,baosight.com,直连',
    ]);
  });

  h.test('domain_keyword / domain_regex 映射', () => {
    const json = { version: 3, rules: [{ domain_keyword: ['Baowu'], domain_regex: ['^a\\..*'] }] };
    h.assertDeep(generator.convertRuleSet(json, '默认代理'), [
      'DOMAIN-KEYWORD,baowu,默认代理',
      'DOMAIN-REGEX,^a\\..*,默认代理',
    ]);
  });

  h.test('ip_cidr / source_ip_cidr / process_name / network / port 映射', () => {
    const json = {
      version: 3,
      rules: [
        { ip_cidr: ['1.2.3.0/24'], source_ip_cidr: ['10.0.0.0/8'], network: ['udp'] },
        { process_name: ['foo.exe'], port: ['443', '1000:2000'] },
      ],
    };
    h.assertDeep(generator.convertRuleSet(json, '默认代理'), [
      'IP-CIDR,1.2.3.0/24,默认代理,no-resolve',
      'SRC-IP-CIDR,10.0.0.0/8,默认代理,no-resolve',
      'NETWORK,UDP,默认代理',
      'PROCESS-NAME,foo.exe,默认代理',
      'DST-PORT,443,默认代理',
      'DST-PORT,1000:2000,默认代理',
    ]);
  });

  h.test('重复条目去重，顺序保持', () => {
    const json = { version: 3, rules: [{ domain: ['a.com'] }, { domain: ['a.com', 'b.com'] }] };
    h.assertDeep(generator.convertRuleSet(json, '直连'), ['DOMAIN,a.com,直连', 'DOMAIN,b.com,直连']);
  });

  h.test('无法表达为 mihomo 规则时显式报错（不静默丢规则）', () => {
    h.assertThrows(
      () => generator.convertRuleSet({ rules: [{ domain: ['a.com'], invert: true }] }, '直连'),
      /invert/,
      'invert 应报错',
    );
    h.assertThrows(() => generator.convertRuleSet({ rules: [{ query_type: ['A'] }] }, '直连'), /不支持的字段/);
    h.assertThrows(() => generator.convertRuleSet({}, '直连'), /rules 数组/);
  });

  h.section('生成测试 · 脚本生成区块');

  const scriptSource = fs.readFileSync(path.join(ROOT, TARGET), 'utf8');
  const block = generator.extractBlock(scriptSource);

  h.test(`${TARGET} 含有完整的生成标记`, () => h.assert(block, '应存在 BEGIN/END 生成标记'));

  h.test('生成区块位置：prefixRules 之后、customizeProxies 之前', () => {
    const begin = scriptSource.indexOf(generator.BEGIN_MARKER);
    const prefixIdx = scriptSource.indexOf('const prefixRules = [');
    const customizeIdx = scriptSource.indexOf('const customizeProxies = [');
    h.assert(prefixIdx !== -1 && customizeIdx !== -1, '应能找到 prefixRules / customizeProxies');
    h.assert(begin > prefixIdx && begin < customizeIdx, '生成区块位置异常');
  });

  h.test('生成区块内容与本地 sing-box-rules 数据源一致（未手改 / 未过期）', () => {
    const expected = expectedBlock();
    if (!expected) {
      console.log(`        ⚠ 未找到 ${LOCAL_DIR}，跳过与数据源的比对`);
      return;
    }
    h.assertEqual(block, expected, '生成区块应与数据源重新生成的结果一致');
  });

  h.test('生成区块声明了 baowu / sun-direct / sun-proxy 三组规则', () => {
    for (const source of generator.SOURCES) {
      h.assert(block.includes(`${source.name}:`) || block.includes(`'${source.name}':`), `应声明规则集 ${source.name}`);
    }
  });

  h.section('生成测试 · main() 规则链注入');

  h.test('baowu / sun-direct 走直连，sun-proxy 走默认代理', () => {
    const rules = api.main(fx.minimalSubscription()).rules;
    const contain = (rule) => rules.includes(rule);
    const expected = expectedBlock();
    if (!expected) {
      // 数据源不在本地时，最少保证注入通道可用（区块内容可能为空）
      h.assert(Array.isArray(rules) && rules.length > 0, '规则链不应为空');
      return;
    }
    for (const rule of ['DOMAIN-SUFFIX,baosight.com,直连', 'DOMAIN,199998.xyz,直连', 'DOMAIN,hmoe.top,默认代理']) {
      h.assert(contain(rule), `规则链应包含 ${rule}`);
    }
  });

  h.test('直连规则插在兜底 IP 规则之前，代理规则插在 MATCH 之前', () => {
    const rules = api.main(fx.minimalSubscription()).rules;
    const expected = expectedBlock();
    if (!expected) return;

    const directIdx = rules.indexOf('DOMAIN-SUFFIX,baosight.com,直连');
    const proxyIdx = rules.indexOf('DOMAIN,hmoe.top,默认代理');
    const fallbackIpIdx = rules.lastIndexOf('RULE-SET,private_ip,直连');
    const matchIdx = rules.findIndex((r) => r.startsWith('MATCH,'));
    const cnProxyIdx = rules.indexOf('RULE-SET,geolocation-!cn,默认代理');

    h.assert(directIdx !== -1 && directIdx < fallbackIpIdx, '直连规则应早于兜底 IP 规则');
    h.assert(proxyIdx !== -1 && proxyIdx < matchIdx, '代理规则应早于 MATCH');
    h.assert(proxyIdx !== -1 && proxyIdx < cnProxyIdx, 'sun-proxy 规则应早于 geolocation-!cn（更精确者优先）');
  });
}

module.exports = { runGeneratorTests };
