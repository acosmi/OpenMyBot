# Chinese UI terminology

Brand name: Wrok Bot. Keep translations consistent across screens.

| en | zh-CN | 说明 |
| --- | --- | --- |
| Wrok Bot | Wrok Bot（不译） | 产品名，任何位置都不翻译；单独的 Bot 不作为界面用词 |
| Assistant | 助手 | 用户创建、可配技能的对象；界面上一律「助手」/ assistant，不用「同事」「机器人」「代理」「智能体」或 coworker、bot、agent。协议名（AG-UI）保持原样 |
| Channel | 频道 | 一个协作空间 |
| Thread | 会话 | 频道内的一次完整对话 |
| Run | 运行 | 一次工具 / 技能的执行 |
| Tool | 工具 | 可被调用的能力单元 |
| Skill | 技能 | 用户可编辑、可授权给助手的工作指令 |
| Plugin | 插件 | 第三方扩展包 |
| Connector | 连接器 | 连接外部服务（如 Google Drive）的组件 |
| Computer | 电脑 | 助手可操作的机器（UI spec v5.2 §10.2）；不用「计算机」「桌面」 |
| Deployment | 部署 | |
| Boundary | 边界 | 工具调用的权限 / 数据边界 |
| Credential | 凭据 | 不用「证书」「密钥」（密钥另有其词） |
| Identity provider | 身份提供方 | 不用「身份供应商」 |
| People | 成员 | admin 里的人员列表；不用「人员」「用户」 |
| Grant | 授权 | 名词与动词同形 |
| Approval | 审批 | 不用「批准」（那是动作 Approve）；`/approvals` 页面与入口统一叫「需要处理」/ Needs attention（UI spec v5.2 §9.1） |
| Audit | 审计 | |
| Component | 组件 | 助手渲染出的 UI 组件 |
| Gallery | 组件库 | 组件的浏览页；不用「画廊」 |
| Memory | 记忆 | 不用「内存」 |
| Tenant package | 租户包 | |


`en.json` and `zh-CN.json` must contain identical keys and interpolation parameters. Run `cargo xtask i18n-check` after editing locale files.
