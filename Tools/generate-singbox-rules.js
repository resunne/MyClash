#!/usr/bin/env node
'use strict';

/**
 * 把 sing-box-rules 仓库的规则 JSON 转换成 mihomo 规则，并写入 Script/mihomoScript.js 的生成区块。
 *
 * 数据源：https://github.com/resunne/sing-box-rules 的
 *   baowu.json      → 分流策略组「宝武」（直连侧）
 *   sun-direct.json → 分流策略组「Sun直连」（直连侧）
 *   sun-proxy.json  → 分流策略组「Sun代理」
 *
 * 三个策略组在脚本的 serviceConfigs 里与 FCM / YouTube / Microsoft 等同级，
 * 由 ruleOptionsEnable 的开关单独控制；本脚本只负责生成它们各自的规则数组。
 *
 * 用法：
 *   node Tools/generate-singbox-rules.js                       # 从 GitHub raw 拉取，写回脚本
 *   node Tools/generate-singbox-rules.js --source-dir <目录>    # 从本地目录读取（离线 / 调试）
 *   node Tools/generate-singbox-rules.js --check               # 只校验，不写文件（有差异退出码 1）
 *
 * 生成区块在 Script/mihomoScript.js 中以
 *   // ===== BEGIN GENERATED: sing-box-rules ... =====
 *   // ===== END GENERATED: sing-box-rules =====
 * 标记；区块内**不要手改**，改了也会在下次生成/CI 时被覆盖。
 */

const fs = require('fs');
const path = require('path');
const https = require('https');

const ROOT = path.resolve(__dirname, '..');
const TARGET_FILE = path.join(ROOT, 'Script', 'mihomoScript.js');

const DEFAULT_SOURCE_BASE = 'https://raw.githubusercontent.com/resunne/sing-box-rules/main/';

const BEGIN_MARKER = '// ===== BEGIN GENERATED: sing-box-rules';
const END_MARKER = '// ===== END GENERATED: sing-box-rules';

/**
 * 数据源清单：
 * - name  → 脚本里 singBoxRuleSets 的键名
 * - file  → 上游 sing-box-rules 仓库里的文件名
 * - group → 对应的分流策略组名（同时也是规则里的目标策略）
 */
const SOURCES = [
  { name: 'baowu', file: 'baowu.json', group: '宝武' },
  { name: 'sun-direct', file: 'sun-direct.json', group: 'Sun直连' },
  { name: 'sun-proxy', file: 'sun-proxy.json', group: 'Sun代理' },
];

const SUPPORTED_KEYS = [
  'domain',
  'domain_suffix',
  'domain_keyword',
  'domain_regex',
  'ip_cidr',
  'source_ip_cidr',
  'process_name',
  'port',
  'network',
];

/** 单引号 JS 字符串字面量 */
function quote(value) {
  return `'${String(value).replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
}

/** 对象键：合法标识符不加引号（与 prettier 保持一致） */
function quoteKey(key) {
  return /^[A-Za-z_$][\w$]*$/.test(key) ? key : quote(key);
}

/** 去掉前导点：sing-box 的 ".example.com" 与 mihomo 的 DOMAIN-SUFFIX 都覆盖自身及子域 */
function stripLeadingDots(domain) {
  return String(domain).replace(/^\.+/, '');
}

function asList(value, key, label) {
  if (Array.isArray(value)) return value;
  if (typeof value === 'string' || typeof value === 'number') return [value];
  throw new Error(`[${label}] 字段 ${key} 不是数组或字符串：${JSON.stringify(value)}`);
}

/** 把单个 sing-box 规则对象的某个字段转换成 mihomo 规则行 */
const FIELD_CONVERTERS = {
  domain: (list, policy, key) => asList(list, key, '').map((d) => `DOMAIN,${String(d).toLowerCase()},${policy}`),
  domain_suffix: (list, policy, key) =>
    asList(list, key, '').map((d) => `DOMAIN-SUFFIX,${stripLeadingDots(d).toLowerCase()},${policy}`),
  domain_keyword: (list, policy, key) =>
    asList(list, key, '').map((d) => `DOMAIN-KEYWORD,${String(d).toLowerCase()},${policy}`),
  domain_regex: (list, policy, key) => asList(list, key, '').map((d) => `DOMAIN-REGEX,${d},${policy}`),
  ip_cidr: (list, policy, key) => asList(list, key, '').map((c) => `IP-CIDR,${c},${policy},no-resolve`),
  source_ip_cidr: (list, policy, key) => asList(list, key, '').map((c) => `SRC-IP-CIDR,${c},${policy},no-resolve`),
  process_name: (list, policy, key) => asList(list, key, '').map((p) => `PROCESS-NAME,${p},${policy}`),
  port: (list, policy, key) => asList(list, key, '').map((p) => `DST-PORT,${String(p).replace(/\s+/g, '')},${policy}`),
  network: (list, policy, key) => {
    const values = asList(list, key, '').map((n) => String(n).toLowerCase());
    if (values.length !== 1 || (values[0] !== 'tcp' && values[0] !== 'udp')) {
      throw new Error(`network 仅支持单个 tcp/udp，当前为 ${JSON.stringify(list)}`);
    }
    return [`NETWORK,${values[0].toUpperCase()},${policy}`];
  },
};

/**
 * 把一份 sing-box 规则集 JSON 转换成 mihomo 规则数组。
 * 遇到无法表达为 mihomo 规则的字段直接抛错（宁可让 CI 失败，也不要静默丢规则）。
 * @param {object} json sing-box 规则集（{ version, rules: [...] }）
 * @param {string} policy 命中后的策略（直连 / 默认代理 …）
 * @param {string} label 数据源名称，仅用于报错信息
 * @returns {string[]}
 */
function convertRuleSet(json, policy, label = 'sing-box-rules') {
  if (!json || typeof json !== 'object' || !Array.isArray(json.rules)) {
    throw new Error(`[${label}] 不是合法的 sing-box 规则集：缺少 rules 数组`);
  }

  const out = [];
  const seen = new Set();

  for (const [index, rule] of json.rules.entries()) {
    if (!rule || typeof rule !== 'object') {
      throw new Error(`[${label}] rules[${index}] 不是对象`);
    }
    if (rule.invert) {
      throw new Error(`[${label}] rules[${index}] 使用了 invert，mihomo 无对应写法`);
    }

    for (const key of Object.keys(rule)) {
      const converter = FIELD_CONVERTERS[key];
      if (!converter) {
        throw new Error(`[${label}] rules[${index}] 含不支持的字段 "${key}"（支持：${SUPPORTED_KEYS.join(' / ')}）`);
      }
      for (const line of converter(rule[key], policy, key)) {
        if (seen.has(line)) continue;
        seen.add(line);
        out.push(line);
      }
    }
  }

  return out;
}

const PRINT_WIDTH = 120;

/** 终端显示宽度（prettier 按宽度判断换行，CJK 占 2 列） */
function displayWidth(text) {
  let width = 0;
  for (const ch of String(text)) {
    const cp = ch.codePointAt(0);
    const wide =
      (cp >= 0x1100 && cp <= 0x115f) ||
      (cp >= 0x2e80 && cp <= 0xa4cf) ||
      (cp >= 0xac00 && cp <= 0xd7a3) ||
      (cp >= 0xf900 && cp <= 0xfaff) ||
      (cp >= 0xfe30 && cp <= 0xfe6f) ||
      (cp >= 0xff00 && cp <= 0xff60) ||
      (cp >= 0xffe0 && cp <= 0xffe6);
    width += wide ? 2 : 1;
  }
  return width;
}

/** 生成写入脚本的整段代码（不含尾随换行） */
function buildBlock(ruleSets) {
  const lines = [
    `${BEGIN_MARKER} =====`,
    '// 由 Tools/generate-singbox-rules.js 生成，请勿手动修改。',
    '// 数据源：https://github.com/resunne/sing-box-rules（baowu / sun-direct / sun-proxy）',
    '// 三组规则分别对应 serviceConfigs 里的「宝武」「Sun直连」「Sun代理」分流策略组。',
    'const singBoxRuleSets = {',
  ];

  for (const source of SOURCES) {
    const rules = ruleSets[source.name] || [];
    const key = quoteKey(source.name);
    const inline = `  ${key}: [${rules.map(quote).join(', ')}],`;
    // 与 prettier 的输出保持一致：宽度放得下就写一行（CJK 按 2 列计），否则逐条换行
    if (rules.length === 0) {
      lines.push(`  ${key}: [],`);
    } else if (displayWidth(inline) <= PRINT_WIDTH) {
      lines.push(inline);
    } else {
      lines.push(`  ${key}: [`);
      for (const rule of rules) lines.push(`    ${quote(rule)},`);
      lines.push('  ],');
    }
  }

  lines.push('};');
  lines.push(END_MARKER);

  return lines.join('\n');
}

/** 用生成的代码块替换脚本里的旧区块（要求标记齐全） */
function upsertBlock(source, block) {
  const beginAt = source.indexOf(BEGIN_MARKER);
  const endAt = source.indexOf(END_MARKER);
  if (beginAt === -1 || endAt === -1 || endAt < beginAt) {
    throw new Error(
      `目标脚本缺少生成标记（${BEGIN_MARKER} … ${END_MARKER}），请先在 Script/mihomoScript.js 中补齐空区块`,
    );
  }
  const eol = detectEol(source);
  const endLineEnd = source.indexOf('\n', endAt);
  const tail = endLineEnd === -1 ? '' : source.slice(endLineEnd + 1);
  return source.slice(0, beginAt) + toEol(block, eol) + eol + tail;
}

/** 取脚本里的当前生成区块（用于 --check 与测试）；行尾统一归一为 \n，避免 CRLF/LF 误报 */
function extractBlock(source) {
  const beginAt = source.indexOf(BEGIN_MARKER);
  const endAt = source.indexOf(END_MARKER);
  if (beginAt === -1 || endAt === -1 || endAt < beginAt) return null;
  return normalizeBlock(source.slice(beginAt, endAt + END_MARKER.length));
}

/** 检测文本的换行风格：出现 CRLF 即视为 CRLF 文件 */
function detectEol(text) {
  return text.includes('\r\n') ? '\r\n' : '\n';
}

/** 把统一用 \n 拼好的文本转成目标行尾风格 */
function toEol(text, eol) {
  return eol === '\n' ? text : text.replace(/\n/g, eol);
}

/** 比对生成区块时忽略行尾差异（Windows 检出为 CRLF，CI 为 LF） */
function normalizeBlock(text) {
  return text == null ? null : text.replace(/\r\n/g, '\n');
}

function fetchText(url, redirects = 0) {
  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { 'user-agent': 'MyClash-rule-generator' } }, (res) => {
        const { statusCode = 0, headers } = res;
        if (statusCode >= 300 && statusCode < 400 && headers.location && redirects < 5) {
          res.resume();
          resolve(fetchText(new URL(headers.location, url).toString(), redirects + 1));
          return;
        }
        if (statusCode !== 200) {
          res.resume();
          reject(new Error(`拉取 ${url} 失败：HTTP ${statusCode}`));
          return;
        }
        let data = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => resolve(data));
      })
      .on('error', reject);
  });
}

async function loadSource(source, options) {
  if (options.sourceDir) {
    const file = path.join(options.sourceDir, source.file);
    return fs.readFileSync(file, 'utf8');
  }
  return fetchText(options.sourceBase + source.file);
}

function parseArgs(argv) {
  const options = { sourceDir: process.env.SING_BOX_RULES_DIR || '', sourceBase: DEFAULT_SOURCE_BASE, check: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--check') {
      options.check = true;
    } else if (arg === '--source-dir') {
      options.sourceDir = argv[i + 1] || '';
      i += 1;
    } else if (arg.startsWith('--source-dir=')) {
      options.sourceDir = arg.slice('--source-dir='.length);
    } else if (arg === '--help' || arg === '-h') {
      options.help = true;
    } else {
      throw new Error(`未知参数：${arg}`);
    }
  }
  return options;
}

async function run(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    console.log('用法：node Tools/generate-singbox-rules.js [--source-dir DIR] [--check]');
    return { changed: false };
  }
  if (options.sourceDir && !fs.existsSync(options.sourceDir)) {
    throw new Error(`--source-dir 指向的目录不存在：${options.sourceDir}`);
  }

  const ruleSets = {};
  for (const source of SOURCES) {
    const text = await loadSource(source, options);
    let json;
    try {
      json = JSON.parse(text);
    } catch (err) {
      throw new Error(`[${source.file}] JSON 解析失败：${err.message}`);
    }
    ruleSets[source.name] = convertRuleSet(json, source.group, source.file);
    console.log(`  ${source.file} → ${ruleSets[source.name].length} 条规则（分流组：${source.group}）`);
  }

  const block = buildBlock(ruleSets);
  const before = fs.readFileSync(TARGET_FILE, 'utf8');
  const after = upsertBlock(before, block);

  if (before === after) {
    console.log('生成区块已是最新，无需改动。');
    return { changed: false };
  }

  if (options.check) {
    console.log('生成区块与数据源不一致（--check 模式不写文件）。');
    process.exitCode = 1;
    return { changed: true };
  }

  fs.writeFileSync(TARGET_FILE, after, 'utf8');
  console.log(`已更新 ${path.relative(ROOT, TARGET_FILE)} 的生成区块。`);
  return { changed: true };
}

if (require.main === module) {
  run().catch((err) => {
    console.error(`生成失败：${err.message}`);
    process.exit(1);
  });
}

module.exports = {
  SOURCES,
  BEGIN_MARKER,
  END_MARKER,
  SUPPORTED_KEYS,
  convertRuleSet,
  buildBlock,
  upsertBlock,
  extractBlock,
  run,
};
