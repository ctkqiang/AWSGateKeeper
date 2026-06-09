---
name: Security Concern / 安全问题
about: Report a security vulnerability or concern / 报告安全漏洞或问题
title: "[SECURITY] "
labels: security, critical
assignees: ctkqiang
---

## Security Concern / 安全问题

**English:** Describe the security concern or vulnerability.

**中文：** 描述安全顾虑或漏洞。

## Severity Assessment / 严重性评估

**English:**
- [ ] **CRITICAL** — Direct credential exposure, privilege escalation, or data breach
- [ ] **HIGH** — Authentication bypass or policy violation
- [ ] **MEDIUM** — Information disclosure or configuration weakness
- [ ] **LOW** — Best-practice deviation

**中文：**
- [ ] **严重** — 直接凭证泄露、权限提升或数据泄露
- [ ] **高** — 认证绕过或策略违规
- [ ] **中** — 信息泄露或配置弱点
- [ ] **低** — 最佳实践偏离

## Affected Component / 受影响组件

- [ ] IAM Role Governance / IAM 角色治理
- [ ] GuardDuty Integration / GuardDuty 集成
- [ ] Inspector Integration / Inspector 集成
- [ ] Detective / CloudTrail
- [ ] Quarantine Engine / 隔离引擎
- [ ] SIEM Forwarding / SIEM 转发
- [ ] API Endpoints / API 端点
- [ ] Configuration Loading / 配置加载
- [ ] Other / 其他: ___

## Proof of Concept / 概念验证

**English:** If applicable, provide steps to reproduce or a proof of concept.

**中文：** 如适用，提供复现步骤或概念验证。

## Suggested Fix / 建议修复

**English:** Do you have a suggested fix?

**中文：** 你有建议的修复方案吗？

## Disclosure Preference / 披露偏好

**English:**
- [ ] Public disclosure after fix / 修复后公开披露
- [ ] Private disclosure preferred / 倾向私下披露

---

**IMPORTANT / 重要:** For critical vulnerabilities, please also contact the maintainer directly. / 对于严重漏洞，请同时直接联系维护者。
