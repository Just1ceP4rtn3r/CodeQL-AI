# 开发工作流

## 步骤简述

1. 需求不明确时先讨论。
2. 创建 Issue，并补全标签、项目、负责人和状态。
3. 将任务改为 `In Progress`。
4. 从 `main` 拉出功能分支。
5. 开发、验证、提交并推送。
6. 创建 PR，并通过 `Closes #<issue-number>` 关联 Issue。
7. 处理 CI 和 review 反馈。
8. 合并 PR。
9. 确认 Issue 已关闭，Project 状态已更新为 `Done`。



## 1. 先判断是否需要讨论

如果需求还不明确、有多种实现方案，或者会影响多个模块，先使用 `Discussions` 讨论。

如果任务已经很明确，例如以下情况，可以直接创建 `Issue`：
- 增加一个按钮
- 增加一个筛选条件
- 增加一个接口
- 增加一个表单字段

## 2. 创建并完善 Issue

创建功能类 `Issue`，标题和内容要清楚说明背景、方案和预期效果。

建议至少补充以下信息：
- 项目看板：将 Issue 加入团队使用的 `Project`
- 负责人：在 `Assignees` 中指定 owner
- 状态：设置为 `Backlog` 或 `Ready`

## 3. 开始开发

正式编码前，先将 Issue 状态改为 `In Progress`。

然后从 `main` 创建功能分支。

示例：

```bash
git checkout main
git pull origin main
git checkout -b feature/team-invite
```

## 4. 在本地开发并验证

在功能分支上完成代码修改。

提交前先检查当前改动：

```bash
git status
git diff
```

提交代码时，使用清晰的提交信息：

```bash
git add .
git commit -m "feat: support team invitation flow"
```

推送分支到远端：

```bash
git push -u origin feature/team-invite
```

## 5. 创建 Pull Request

创建 PR 时，分支选择如下：
- `base`: `main`
- `compare`: 你的功能分支

PR 标题示例：

```text
feat: 支持邀请成员加入团队
```

如果仓库已经配置了 PR 模板，按模板填写即可。至少应包含：
- 本次改动摘要
- 关联的 Issue
- 验证方式或结果
- 风险说明

示例：

```md
## Summary
新增邀请成员功能，管理员可以输入邮箱发送邀请链接。

## Related Issue
Closes #12

## Validation
- 本地功能测试通过
- 关键链路已验证

## Risk
Medium
```

其中 `Closes #12` 要替换为真实的 Issue 编号。PR 合并后，GitHub 会自动关闭该 Issue。

## 6. 处理评审和 CI

PR 创建后，需要继续完成以下动作：
- 选择 reviewer
- 等待 CI / GitHub Actions 结果
- 处理 AI review 或人工 review 的评论

如果需要修改，继续在同一个分支提交并推送：

```bash
git add .
git commit -m "fix: address review comments"
git push
```

PR 提交后，建议将项目看板中的任务状态更新为 `In Review`。

## 7. 合并并收尾

满足以下条件后可以合并 PR：
- CI 通过
- 必要的 review 已 approve
- 没有未处理的阻塞问题

除非仓库有特殊要求，默认优先使用 `Squash and merge`。

合并后需要确认：
- 对应 Issue 已自动关闭
- 项目看板中的状态已更新为 `Done`
- 已合并分支已删除，如果仓库没有自动删除则手动清理

本地删除分支示例：

```bash
git checkout main
git pull origin main
git branch -d feature/team-invite
```

删除远端分支示例：

```bash
git push origin --delete feature/team-invite
```

