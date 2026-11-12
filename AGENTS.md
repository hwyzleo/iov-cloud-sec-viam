# SPEC-Driven Development 约束文档
- 参考 Notion Page ID: 37d0ec7a4b9280bd8c84c922f57f6d3e

# 全局研发环境与行为准则
- 参考 Notion Page ID: 37d0ec7a4b928005aee8d863af5b2518

# 开源车联网研发与行为准则
- 参考 Notion Page ID: 37d0ec7a4b92802d8915c7c310e24486

# 当前项目需求文档
- 参考 Notion Page ID: 40b0ec7a4b9280d6af1cd71e0a937ab2
- 变更记录 Notion Page ID: 40b0ec7a4b92802b9a9fdcefbb2b13f2

# 当前项目设计文档
- 参考 Notion Page ID: 40b0ec7a4b92804fbed3c50dac05f27d
- 变更记录 Notion Page ID: 40b0ec7a4b928038b659c024fe5a6ba7

# 当前项目系统架构文档
- 参考 Notion Page ID: 4120ec7a4b928055bc50fcd0b536763e

# 当前项目功能架构文档
- 参考 Notion Page ID: 4140ec7a4b928005ab1ecf1e537f3a69

# 当前项目数据库文档
- 参考 Notion Page ID: 4160ec7a4b928053a459f6207a4b0426

# graphify

This project has a graphify knowledge graph at graphify-out/.

Rules:
- Before answering architecture or codebase questions, read graphify-out/GRAPH_REPORT.md for god nodes and community structure
- If graphify-out/wiki/index.md exists, navigate it instead of reading raw files
- For cross-module "how does X relate to Y" questions, prefer `graphify query "<question>"`, `graphify path "<A>" "<B>"`, or `graphify explain "<concept>"` over grep — these traverse the graph's EXTRACTED + INFERRED edges instead of scanning files
- After modifying code files in this session, run `graphify update .` to keep the graph current (AST-only, no API cost)
