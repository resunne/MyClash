'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..');
const generator = require(path.join(ROOT, 'Tools', 'generate-singbox-rules.js'));
const TARGET = 'Script/mihomoScript.js';

// 上游数据源的本地副本（与 MyClash 同级的 sing-box-rules 仓库）；不存在时跳过同步类用例
const LOCAL_DIR = path.resolve(ROOT, '..', 'sing-box-rules');

// sing-box-rules 分流组图标前缀（与脚本里的 singBoxIconBaseUrl 一致）
const SINGBOX_ICON_PREFIX = 'https://github.com/resunne/MyClash/raw/refs/heads/main/Icons/sing-box-rules/svg/';

/** 用本地数据源计算期望的生成区块；目录缺失时返回 null */
function expectedBlock() {
  if (!fs.existsSync(LOCAL_DIR)) return null;
  const ruleSets = {};
  for (const source of generator.SOURCES) {
    const json = JSON.parse(fs.readFileSync(path.join(LOCAL_DIR, source.file), 'utf8'));
    ruleSets[source.name] = generator.convertRuleSet(json, source.group, source.file);
  }
  return generator.buildBlock(ruleSets);
}

/**
 * sing-box-rules 生成相关测试：
 * 1. 转换器把 sing-box 规则集正确映射为 mihomo 规则，无法表达的字段显式报错；
 * 2. Script/mihomoScript.js 的生成区块由数据源生成，未被手改 / 未过期；
 * 3. 三份规则各自对应独立的分流策略组（与 FCM / YouTube / Microsoft 同级），开关独立控制。
 */
function runGeneratorTests(h, api, fx) {
  h.section('生成测试 · sing-box-rules 转换器');

  h.test('domain → DOMAIN，domain_suffix → DOMAIN-SUFFIX（去前导点、小写）', () => {
    const json = { version: 3, rules: [{ domain: ['Exact.COM'], domain_suffix: ['.Baowu.CN', 'baosight.com'] }] };
    h.assertDeep(generator.convertRuleSet(json, '宝武'), [
      'DOMAIN,exact.com,宝武',
      'DOMAIN-SUFFIX,baowu.cn,宝武',
      'DOMAIN-SUFFIX,baosight.com,宝武',
    ]);
  });

  h.test('domain_keyword / domain_regex 映射', () => {
    const json = { version: 3, rules: [{ domain_keyword: ['Baowu'], domain_regex: ['^a\\..*'] }] };
    h.assertDeep(generator.convertRuleSet(json, 'Sun代理'), [
      'DOMAIN-KEYWORD,baowu,Sun代理',
      'DOMAIN-REGEX,^a\\..*,Sun代理',
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
    h.assertDeep(generator.convertRuleSet(json, 'Sun代理'), [
      'IP-CIDR,1.2.3.0/24,Sun代理,no-resolve',
      'SRC-IP-CIDR,10.0.0.0/8,Sun代理,no-resolve',
      'NETWORK,UDP,Sun代理',
      'PROCESS-NAME,foo.exe,Sun代理',
      'DST-PORT,443,Sun代理',
      'DST-PORT,1000:2000,Sun代理',
    ]);
  });

  h.test('重复条目去重，顺序保持', () => {
    const json = { version: 3, rules: [{ domain: ['a.com'] }, { domain: ['a.com', 'b.com'] }] };
    h.assertDeep(generator.convertRuleSet(json, '宝武'), ['DOMAIN,a.com,宝武', 'DOMAIN,b.com,宝武']);
  });

  h.test('无法表达为 mihomo 规则时显式报错（不静默丢规则）', () => {
    h.assertThrows(
      () => generator.convertRuleSet({ rules: [{ domain: ['a.com'], invert: true }] }, '宝武'),
      /invert/,
      'invert 应报错',
    );
    h.assertThrows(() => generator.convertRuleSet({ rules: [{ query_type: ['A'] }] }, '宝武'), /不支持的字段/);
    h.assertThrows(() => generator.convertRuleSet({}, '宝武'), /rules 数组/);
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

  h.section('生成测试 · 独立分流策略组');

  h.test('三个分流策略组均已生成，且与 FCM / YouTube 同级（select + 图标）', () => {
    const groups = api.main(fx.minimalSubscription())['proxy-groups'];
    const byName = (name) => groups.find((g) => g.name === name);
    for (const source of generator.SOURCES) {
      const group = byName(source.group);
      h.assert(group, `应生成策略组「${source.group}」`);
      h.assertEqual(group.type, 'select', `「${source.group}」应为 select 类型`);
      h.assert((group.icon || '').startsWith(SINGBOX_ICON_PREFIX), `「${source.group}」应使用 sing-box-rules 图标`);
    }
    h.assertEqual(byName('宝武').icon, `${SINGBOX_ICON_PREFIX}baowu.svg`);
    h.assertEqual(byName('Sun直连').icon, `${SINGBOX_ICON_PREFIX}direct.svg`);
    h.assertEqual(byName('Sun代理').icon, `${SINGBOX_ICON_PREFIX}proxy.svg`);
  });

  h.test('引用的图标文件在仓库中真实存在', () => {
    for (const file of ['baowu.svg', 'direct.svg', 'proxy.svg']) {
      const abs = path.join(ROOT, 'Icons', 'sing-box-rules', 'svg', file);
      h.assert(fs.existsSync(abs), `图标文件应存在：Icons/sing-box-rules/svg/${file}`);
    }
  });

  h.test('策略组顺序：Sun代理 / Sun直连 / 宝武 紧跟「默认代理」之后', () => {
    const out = api.main(fx.minimalSubscription());
    const names = out['proxy-groups'].map((g) => g.name);
    const defIdx = names.indexOf('默认代理');
    h.assert(defIdx !== -1, '应存在「默认代理」组');
    h.assertDeep(names.slice(defIdx + 1, defIdx + 4), ['Sun代理', 'Sun直连', '宝武'], '三个分流组应紧跟「默认代理」');
    // GLOBAL 成员顺序与 proxy-groups 顺序一致
    const global = out['proxy-groups'].find((g) => g.name === 'GLOBAL');
    const gDefIdx = global.proxies.indexOf('默认代理');
    h.assertDeep(
      global.proxies.slice(gDefIdx + 1, gDefIdx + 4),
      ['Sun代理', 'Sun直连', '宝武'],
      'GLOBAL 中三个分流组也应紧跟「默认代理」',
    );
  });

  h.test('直连侧策略组含「直连」并默认选中，代理侧组不含「直连」', () => {
    const groups = api.main(fx.minimalSubscription())['proxy-groups'];
    const byName = (name) => groups.find((g) => g.name === name);
    for (const name of ['宝武', 'Sun直连']) {
      h.assert(byName(name).proxies.includes('直连'), `「${name}」应包含直连`);
      h.assertEqual(byName(name)['default-selected'], '直连', `「${name}」应默认选中直连`);
    }
    h.assert(!byName('Sun代理').proxies.includes('直连'), '「Sun代理」不应含直连');
  });

  h.test('规则分别指向各自的策略组，且与开关联动', () => {
    const out = api.main(fx.minimalSubscription());
    const expected = expectedBlock();
    if (expected) {
      for (const rule of ['DOMAIN-SUFFIX,baosight.com,宝武', 'DOMAIN,199998.xyz,Sun直连', 'DOMAIN,hmoe.top,Sun代理']) {
        h.assert(out.rules.includes(rule), `规则链应包含 ${rule}`);
      }
    }

    // 关闭单个开关 → 仅移除该组的组与规则
    const saved = api.ruleOptionsEnable['宝武'];
    api.ruleOptionsEnable['宝武'] = false;
    try {
      const off = api.main(fx.minimalSubscription());
      h.assert(!off['proxy-groups'].some((g) => g.name === '宝武'), '关闭后不应生成「宝武」组');
      h.assert(!off.rules.some((r) => r.endsWith(',宝武')), '关闭后不应有指向「宝武」的规则');
      h.assert(
        off['proxy-groups'].some((g) => g.name === 'Sun直连'),
        '其它组不受影响',
      );
    } finally {
      api.ruleOptionsEnable['宝武'] = saved;
    }
  });

  h.test('规则位置：早于 geolocation-!cn 与 MATCH，且晚于前置直连规则', () => {
    const rules = api.main(fx.minimalSubscription()).rules;
    const expected = expectedBlock();
    if (!expected) return;

    const baowuIdx = rules.indexOf('DOMAIN-SUFFIX,baosight.com,宝武');
    const sunProxyIdx = rules.indexOf('DOMAIN,hmoe.top,Sun代理');
    const cnProxyIdx = rules.indexOf('RULE-SET,geolocation-!cn,默认代理');
    const matchIdx = rules.findIndex((r) => r.startsWith('MATCH,'));
    const prefixIdx = rules.indexOf('RULE-SET,private,直连');

    h.assert(baowuIdx !== -1 && baowuIdx > prefixIdx, '生成规则应排在前置规则之后');
    h.assert(sunProxyIdx !== -1 && sunProxyIdx < cnProxyIdx, '生成规则应早于 geolocation-!cn（更精确者优先）');
    h.assert(baowuIdx < matchIdx && sunProxyIdx < matchIdx, '生成规则应早于 MATCH');
  });
}

module.exports = { runGeneratorTests };
