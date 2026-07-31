//! Console-wide language: 中文 / English.
//!
//! The embedded Deploy workspace shipped its own language toggle, which meant
//! the console spoke two languages at once — the shell in English, the Deploy
//! pane in whichever language its own switch was last set to. Language is a
//! property of the console, not of one pane, so it lives here: chosen once,
//! stored in a cookie, rendered by the server, and pushed into the Deploy
//! iframe so it follows along.
//!
//! Strings are keyed rather than interpolated so a missing translation is a
//! visible key, not silently English text pretending to be translated.

use axum::http::HeaderMap;

pub const LANG_COOKIE: &str = "sc_lang";

/// "en" | "zh". Absent cookie falls back to the browser's Accept-Language, so
/// a Chinese browser gets Chinese on the first visit without configuring
/// anything.
pub fn lang(headers: &HeaderMap) -> &'static str {
    match crate::util::cookie_value(headers, LANG_COOKIE).as_deref() {
        Some("zh") => "zh",
        Some("en") => "en",
        _ => {
            let accept = headers
                .get(axum::http::header::ACCEPT_LANGUAGE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if accept.to_ascii_lowercase().contains("zh") {
                "zh"
            } else {
                "en"
            }
        }
    }
}

/// The BCP-47 tag for `<html lang>`.
pub fn html_lang(l: &str) -> &'static str {
    if l == "zh" {
        "zh-CN"
    } else {
        "en"
    }
}

/// Look up a key. Unknown keys return the key itself, which shows up loudly in
/// the UI rather than quietly rendering the wrong language.
///
/// `key` is `&'static str` because every key is a literal; that is also what
/// lets an unknown key be echoed back without allocating.
pub fn t(l: &str, key: &'static str) -> &'static str {
    let zh = l == "zh";
    match key {
        // ---- shell / navigation ----
        "nav.files" => if zh { "文件" } else { "Files" },
        "nav.deploy" => if zh { "部署" } else { "Deploy" },
        "nav.monitor" => if zh { "监控" } else { "Monitor" },
        "nav.lab" => if zh { "实验室" } else { "Lab" },
        "nav.test" => if zh { "测试" } else { "Testing" },
        "shell.signout" => if zh { "退出登录" } else { "Sign out" },
        "shell.signedin" => if zh { "已登录" } else { "signed in" },
        "shell.cluster" => if zh { "集群" } else { "cluster" },
        "shell.language" => if zh { "语言" } else { "Language" },
        "theme.label" => if zh { "主题" } else { "Theme" },
        "theme.light" => if zh { "浅色" } else { "Light" },
        "theme.dark" => if zh { "深色" } else { "Dark" },

        // ---- login ----
        "login.tenant" => if zh { "租户" } else { "Tenant" },
        "login.user" => if zh { "用户" } else { "User" },
        "login.key" => if zh { "密钥" } else { "Key" },
        "login.submit" => if zh { "登录" } else { "Sign in" },
        "login.title" => if zh { "登录" } else { "Sign in" },
        "login.note" => if zh {
            "没有 .admin 角色的用户只能看到其 ACL 允许的内容。"
        } else {
            "Users without the .admin role see only what their ACLs allow."
        },
        "login.bad" => if zh { "租户、用户或密钥不正确。" } else { "Wrong tenant, user, or key." },
        "login.failed" => if zh { "登录失败：{e}" } else { "Sign in failed: {e}" },

        // ---- files ----
        "files.title" => if zh { "文件" } else { "Files" },
        "files.newbucket" => if zh { "新建存储桶" } else { "New bucket" },
        "files.buckets" => if zh { "存储桶" } else { "Buckets" },
        "files.bucket" => if zh { "存储桶" } else { "Bucket" },
        "files.objects" => if zh { "对象数" } else { "Objects" },
        "files.size" => if zh { "大小" } else { "Size" },
        "files.nobuckets" => if zh { "还没有存储桶" } else { "No buckets yet" },
        "files.search" => if zh { "搜索" } else { "Search" },
        "files.trash" => if zh { "回收站" } else { "Trash" },
        "files.account" => if zh { "账户" } else { "Account" },
        "files.users" => if zh { "租户与用户" } else { "Tenants & Users" },
        "files.noquota" => if zh { "未设置账户配额" } else { "no account quota" },
        "files.used" => if zh { "已用" } else { "used" },
        "files.name" => if zh { "名称" } else { "Name" },
        "files.type" => if zh { "类型" } else { "Type" },
        "files.modified" => if zh { "修改时间" } else { "Modified" },
        "files.folder" => if zh { "文件夹" } else { "folder" },
        "files.system" => if zh { "系统" } else { "system" },
        // A count and its noun cannot be looked up separately: English
        // pluralises the noun, Chinese puts a measure word between the two and
        // orders the clause differently. The whole phrase is one key.
        "files.stat" => if zh {
            "{n} 个存储桶 · 已用 {used} · {quota}"
        } else {
            "{n} bucket{s} · {used} used · {quota}"
        },
        "files.quota" => if zh { "账户配额 {q}" } else { "account quota {q}" },
        "files.nobucketshint" => if zh {
            "还没有存储桶，先创建一个再上传。"
        } else {
            "No buckets yet. Create one to start uploading."
        },
        "files.namehint" => if zh { "最多 255 个字符，不能含斜杠。" } else { "Up to 255 characters, no slashes." },
        "files.createbucket" => if zh { "创建存储桶" } else { "Create bucket" },
        "files.bucketsettings" => if zh { "存储桶设置" } else { "Bucket settings" },
        "files.deletebucket" => if zh { "删除存储桶" } else { "Delete bucket" },
        "files.filter" => if zh { "筛选" } else { "Filter" },
        "files.pager.range" => if zh {
            "第 {a}–{b} 条，共 {n} 条"
        } else {
            "{a}–{b} of {n}"
        },
        "files.pager.per" => if zh { "每页" } else { "Per page" },
        "files.pager.prev" => if zh { "上一页" } else { "Previous" },
        "files.pager.next" => if zh { "下一页" } else { "Next" },
        "files.pager.page" => if zh { "第 {p} / {m} 页" } else { "Page {p} / {m}" },
        "files.settings" => if zh { "设置" } else { "Settings" },
        "files.upload" => if zh { "上传" } else { "Upload" },
        "files.zip" => if zh { "打包下载" } else { "Zip" },
        "files.ziptitle" => if zh { "将当前文件夹打包为 zip 下载" } else { "Download this folder as a zip" },
        "files.emptyfolder" => if zh {
            "此文件夹为空。上传文件或新建文件夹。"
        } else {
            "This folder is empty. Upload files or create a folder."
        },
        "files.trunc" => if zh { "列表已在 10000 条处截断。" } else { "Listing truncated at 10000 entries." },
        "files.dlzip" => if zh { "将文件夹打包为 zip 下载" } else { "Download folder as zip" },
        "files.trashfolder" => if zh { "将文件夹移入回收站" } else { "Move folder to trash" },
        "files.delfolder" => if zh { "删除文件夹" } else { "Delete folder" },
        "files.details" => if zh { "对象详情" } else { "Object details" },
        "files.download" => if zh { "下载" } else { "Download" },
        "files.share" => if zh { "分享" } else { "Share" },
        "files.trashobj" => if zh { "移入回收站" } else { "Move to trash" },
        "files.newfolder" => if zh { "新建文件夹" } else { "New folder" },
        "files.foldername" => if zh { "文件夹名称" } else { "Folder name" },
        "files.createfolder" => if zh { "创建文件夹" } else { "Create folder" },
        "files.uploadfiles" => if zh { "上传文件" } else { "Upload files" },
        "files.uploadhint" => if zh {
            "单个文件最大 1 GiB。超过 64 MiB 的文件按分段大对象上传。"
        } else {
            "Files up to 1 GiB. Files over 64 MiB are uploaded as segmented large objects."
        },
        "files.startupload" => if zh { "开始上传" } else { "Start upload" },
        "files.object" => if zh { "对象" } else { "Object" },
        "files.contenttype" => if zh { "内容类型" } else { "Content type" },
        "files.mimetype" => if zh { "MIME 类型" } else { "MIME type" },
        "files.metadata" => if zh { "元数据" } else { "Metadata" },
        "files.addrow" => if zh { "添加一行" } else { "Add row" },
        "files.expiry" => if zh { "过期" } else { "Expiry" },
        "files.deleteat" => if zh { "删除时间" } else { "Delete at" },
        "files.clearexpiry" => if zh { "清除过期时间" } else { "Clear expiry" },
        "files.expiryhint" => if zh {
            "过期清理进程尚未部署：过期时间会被记录，但自动删除还没生效。"
        } else {
            "The expirer daemon is not yet deployed: expiry is recorded but auto-deletion is pending."
        },
        "files.publiclink" => if zh { "公开链接" } else { "Public link" },
        "files.danger" => if zh { "危险操作" } else { "Danger" },
        "files.delsegments" => if zh { "同时删除 SLO 分段" } else { "Also delete SLO segments" },
        "files.delperm" => if zh { "永久删除" } else { "Delete permanently" },
        "files.templink" => if zh { "临时链接" } else { "Temporary link" },
        "files.validfor" => if zh { "有效期" } else { "Valid for" },
        "files.hour1" => if zh { "1 小时" } else { "1 hour" },
        "files.day1" => if zh { "1 天" } else { "1 day" },
        "files.day7" => if zh { "7 天" } else { "7 days" },
        "files.custom" => if zh { "自定义" } else { "Custom" },
        "files.seconds" => if zh { "秒数" } else { "Seconds" },
        "files.genlink" => if zh { "生成链接" } else { "Generate link" },
        "files.linkhint" => if zh {
            "链接指向集群的负载均衡器：在集群网络内或通过隧道都能访问。"
        } else {
            "Links point at the cluster load balancer; they work from the cluster network or through your tunnel."
        },
        "files.publichint" => if zh {
            "该存储桶是公开读：任何拿到 URL 的人都能取走这个对象。"
        } else {
            "This bucket is public: anyone with the URL can fetch this object."
        },
        "files.access" => if zh { "访问权限" } else { "Access" },
        "files.private" => if zh { "私有" } else { "Private" },
        "files.publicread" => if zh { "公开读" } else { "Public read" },
        "files.aclhint" => if zh {
            "公开读会把 ACL 设为 <code>.r:*,.rlistings</code>，任何拿到 URL 的人都能读取和列举。"
        } else {
            "Public read sets the ACL to <code>.r:*,.rlistings</code> so anyone with the URL can fetch and list."
        },
        "files.readacl" => if zh { "读取 ACL" } else { "Read ACL" },
        "files.writeacl" => if zh { "写入 ACL" } else { "Write ACL" },
        "files.quotasec" => if zh { "配额" } else { "Quota" },
        "files.maxbytes" => if zh { "最大字节数" } else { "Max bytes" },
        "files.maxobjects" => if zh { "最大对象数" } else { "Max objects" },
        "files.emptynone" => if zh { "留空表示不限" } else { "empty = none" },
        "files.trashnote" => if zh {
            "删除的内容会移到 <code>.trash</code> 容器，按原存储桶和路径存放。恢复就是把它们复制回原处。"
        } else {
            "Deleted items are moved to the <code>.trash</code> container under their original \
             bucket and path. Restoring copies them back."
        },
        "files.emptytrash" => if zh { "清空回收站" } else { "Empty trash" },
        "files.trashempty" => if zh { "回收站是空的。" } else { "Trash is empty." },
        "files.restore" => if zh { "恢复" } else { "Restore" },
        "files.restoreall" => if zh { "全部恢复" } else { "Restore all" },
        "files.deleteall" => if zh { "全部删除" } else { "Delete all" },
        "files.item" => if zh { "内容" } else { "Item" },
        "files.deleted" => if zh { "删除时间" } else { "Deleted" },
        "files.items" => if zh { "{n} 项" } else { "{n} item{s}" },

        // ---- account ----
        "acct.stat" => if zh {
            "{who} · 已用 {used} · {containers} 个容器 · {objects} 个对象"
        } else {
            "{who} · {used} used · {containers} containers · {objects} objects"
        },
        "acct.quota" => if zh { "账户配额" } else { "Account quota" },
        "acct.quotabytes" => if zh { "配额字节数" } else { "Quota bytes" },
        "acct.savequota" => if zh { "保存配额" } else { "Save quota" },
        "acct.quotahint" => if zh {
            "账户配额由集群强制执行，但只有 reseller 管理员能改。在 tempauth 下这属于部署配置，\
             这里被拒绝是正常的，界面会如实显示。"
        } else {
            "Account quotas are enforced by the cluster but can only be changed by a reseller \
             admin. With tempauth this is deployed configuration; a rejection here is expected \
             and shown honestly."
        },
        "acct.tempkey" => if zh { "临时链接密钥" } else { "Temp URL key" },
        "acct.keyset" => if zh { "该账户已设置临时链接密钥。" } else { "A temp URL key is set for this account." },
        "acct.keynone" => if zh {
            "还没有临时链接密钥：第一次生成分享链接时会自动生成一个。"
        } else {
            "No temp URL key yet: one will be generated automatically for the first share link."
        },
        "acct.newkey" => if zh { "新密钥" } else { "New key" },
        "acct.keyrandom" => if zh { "留空表示随机生成" } else { "empty = generate random" },
        "acct.setkey" => if zh { "设置密钥" } else { "Set key" },
        "acct.defexp" => if zh {
            "默认链接有效期（秒，仅本次会话）"
        } else {
            "Default link expiry (seconds, this session)"
        },
        "acct.savedefault" => if zh { "保存默认值" } else { "Save default" },
        "acct.keyhint" => if zh {
            "更换密钥会让此前生成的所有临时链接立即失效。"
        } else {
            "Changing the key invalidates all previously generated temporary links."
        },
        "acct.meta" => if zh { "账户元数据" } else { "Account metadata" },
        "acct.savemeta" => if zh { "保存元数据" } else { "Save metadata" },
        "acct.nometa" => if zh { "还没有账户元数据。添加一行来设置。" } else { "No account metadata yet. Add a row to set some." },
        "acct.users" => if zh { "用户" } else { "Users" },
        "acct.noaccounts" => if zh { "控制台配置里没有列出任何账户。" } else { "No accounts listed in the console config." },
        "acct.usershint" => if zh {
            "tempauth 用户属于部署配置，不是 API 数据：这份列表来自控制台配置文件。\
             要新增或修改用户，请在部署页面改 proxy-server.conf，再逐台滚动重启代理节点。"
        } else {
            "Tempauth users are deployed configuration, not API data: this list comes from the \
             console config file. Create or change users through the Deploy surface \
             (proxy-server.conf) and roll the proxies."
        },
        "acct.ratelimits" => if zh { "限速" } else { "Rate limits" },
        "acct.ratehint" => if zh {
            "限速中间件已在代理管线中启用。限制值写在 proxy-server.conf（部署配置）里，\
             这里没有可以改它的接口。"
        } else {
            "The ratelimit middleware is active in the proxy pipeline. Limits are set in \
             proxy-server.conf (deployed configuration); there is no API to change them here."
        },

        // ---- tenants & users ----
        "users.add" => if zh { "添加用户" } else { "Add user" },
        "users.edit" => if zh { "编辑用户" } else { "Edit user" },
        "users.intro" => if zh {
            "<code>{cluster}</code> 上的 tempauth 身份。一个租户就是一个账户；每个用户以 \
             <code>租户:用户</code> 加密钥登录。变更会写入每个代理节点，并逐台滚动生效。\
             密钥只写不读 —— 这里永远不会显示。"
        } else {
            "tempauth identities on <code>{cluster}</code>. A tenant is an account; each user \
             signs in as <code>tenant:user</code> with its key. Changes are written to every \
             proxy and rolled out one node at a time. Keys are write-only — they are never \
             shown here."
        },
        "users.rostererr" => if zh { "读不到账户名册：{e}" } else { "Could not read the account roster: {e}" },
        "users.none" => if zh { "没有账户。" } else { "No accounts." },
        "users.noaccess" => if zh { "你没有访问租户与用户的权限。" } else { "You do not have access to Tenants & Users." },
        "users.tenant" => if zh { "租户" } else { "Tenant" },
        "users.user" => if zh { "用户" } else { "User" },
        "users.roles" => if zh { "角色" } else { "Roles" },
        "users.groups" => if zh { "用户组" } else { "Groups" },
        "users.reseller" => if zh { "reseller 管理员" } else { "reseller admin" },
        "users.admin" => if zh { "管理员" } else { "admin" },
        "users.member" => if zh { "普通成员" } else { "member" },
        "users.key" => if zh { "密钥" } else { "Key" },
        "users.keyph" => if zh { "用户密钥" } else { "secret key" },
        "users.keyhint" => if zh { "用户用这个密钥登录。不能有空格。" } else { "The user signs in with this key. No spaces." },
        "users.adminrole" => if zh { "账户管理员（.admin）" } else { "Account admin (.admin)" },
        "users.resellerrole" => if zh { "Reseller 管理员（.reseller_admin）" } else { "Reseller admin (.reseller_admin)" },
        "users.groupsfld" => if zh { "用户组（可选，空格分隔）" } else { "Groups (optional, space-separated)" },
        "users.save" => if zh { "保存用户" } else { "Save user" },
        "users.busy" => if zh {
            "正在下发到各个代理节点 —— 会逐台重启代理，需要一点时间…"
        } else {
            "Applying across proxies — this restarts each proxy in turn and can take a moment…"
        },

        // ---- search ----
        "search.allcontainers" => if zh { "全部容器" } else { "All containers" },
        "search.deep" => if zh { "包含自定义元数据（较慢）" } else { "Include custom metadata (slower)" },
        "search.reindex" => if zh { "重建索引" } else { "Reindex" },
        "search.indexed" => if zh {
            "已索引 {n} 个对象 · {ago} 秒前建立"
        } else {
            "Indexed {n} object{s} &middot; built {ago}s ago"
        },
        "search.deepnote" => if zh { " · 含自定义元数据" } else { " &middot; includes custom metadata" },
        "search.truncnote" => if zh { " · 已截断" } else { " &middot; truncated" },
        "search.noindex" => if zh {
            "还没有索引 —— 点重建索引给这个账户建一个。"
        } else {
            "No index yet — Reindex to build one for this account."
        },
        "search.name" => if zh { "名称包含" } else { "Name contains" },
        "search.container" => if zh { "容器" } else { "Container" },
        "search.ctype" => if zh { "内容类型" } else { "Content-type" },
        "search.metakey" => if zh { "元数据键" } else { "Metadata key" },
        "search.metaval" => if zh { "元数据值" } else { "Metadata value" },
        "search.minsize" => if zh { "最小大小（字节）" } else { "Min size (bytes)" },
        "search.maxsize" => if zh { "最大大小（字节）" } else { "Max size (bytes)" },

        // ---- lab ----
        "lab.title" => if zh { "实验室" } else { "Lab" },
        "lab.intro" => if zh {
            "解释集群而非操作集群的工具：Ring 会怎么变、某个策略要花多少钱、某个对象为什么会这样。"
        } else {
            "Tools that explain the cluster rather than operate it: what the ring would do, \
             what a policy would cost, why one object behaved the way it did."
        },
        "lab.soon" => if zh { "尚未构建" } else { "not built yet" },
        "lab.reachable" => if zh { "个节点可达" } else { "nodes reachable" },
        "lab.slowest" => if zh { "最慢" } else { "slowest" },
        "lab.nonodes" => if zh {
            "未配置集群节点 —— 需要读取节点的实验室工具将无法使用。"
        } else {
            "No cluster nodes configured — Lab tools that read the nodes will not work."
        },
        "lab.noanswer" => if zh { "无响应" } else { "no answer from" },

        "ring.title" => "RingScope",
        "policy.title" => if zh { "策略经济学" } else { "Policy Economist" },
        "ring.simulate" => if zh { "模拟" } else { "Simulate" },
        "ring.reset" => if zh { "重置" } else { "Reset" },
        "ring.rebalance" => if zh { "重新平衡" } else { "Rebalance" },
        "ring.policy" => if zh { "存储策略" } else { "Storage policy" },
        "ring.scenario" => if zh { "场景" } else { "Scenario" },
        "ring.nochanges" => if zh {
            "没有变更 —— 显示当前 Ring 状态"
        } else {
            "no changes — showing the ring as it stands"
        },
        "ring.reading" => if zh { "正在读取 Ring…" } else { "Reading the ring…" },
        "ring.simulating" => if zh { "模拟中…" } else { "Simulating…" },
        "ring.add" => if zh { "添加" } else { "Add" },
        "ring.op.fail_node" => if zh { "让一个节点下线" } else { "Take a node offline" },
        "ring.op.fail_device" => if zh { "拔掉一块磁盘" } else { "Pull a disk" },
        "ring.op.fail_zone" => if zh { "失去整个 zone" } else { "Lose a whole zone" },
        "ring.op.remove_device" => if zh { "永久retire一块磁盘" } else { "Retire a disk permanently" },
        "ring.op.set_weight" => if zh { "修改权重" } else { "Change a weight" },
        "ring.op.add_device" => if zh { "增加一台机器" } else { "Add a machine" },

        // ---- testing ----
        "test.title" => if zh { "性能测试" } else { "Testing" },
        "test.intro" => if zh {
            "对本集群跑真实读写负载，结果可以看表格、图表，或导出。"
        } else {
            "Run a real read/write workload against this cluster; read the results as a \
             table or a chart, or export them."
        },
        "test.run" => if zh { "开始测试" } else { "Run test" },
        "test.stop" => if zh { "停止" } else { "Stop" },
        "test.running" => if zh { "测试进行中…" } else { "Test running…" },
        "test.size" => if zh { "对象大小" } else { "Object size" },
        "test.op" => if zh { "操作" } else { "Operation" },
        "test.workers" => if zh { "并发数" } else { "Workers" },
        "test.duration" => if zh { "时长（秒）" } else { "Duration (s)" },
        "test.read" => if zh { "读取" } else { "read" },
        "test.write" => if zh { "写入" } else { "write" },
        "test.mixed" => if zh { "读写混合" } else { "mixed" },
        "test.results" => if zh { "测试结果" } else { "Results" },
        "test.noruns" => if zh { "还没有测试记录。" } else { "No test runs yet." },
        "test.table" => if zh { "表格" } else { "Table" },
        "test.chart" => if zh { "图表" } else { "Chart" },
        "test.export" => if zh { "导出 CSV" } else { "Export CSV" },
        "test.throughput" => if zh { "吞吐量" } else { "Throughput" },
        "test.bandwidth" => if zh { "带宽" } else { "Bandwidth" },
        "test.latency" => if zh { "延迟" } else { "Latency" },
        "test.errors" => if zh { "错误" } else { "Errors" },
        "test.started" => if zh { "开始时间" } else { "Started" },
        "test.ops" => if zh { "操作数" } else { "Operations" },
        "test.busy" => if zh {
            "已有测试在运行，请等待其结束。"
        } else {
            "A test is already running; wait for it to finish."
        },

        // ---- Lab tool registry (rendered into the side-nav and the index) ----
        "lab.soon" => if zh { "待建" } else { "soon" },
        "lab.notbuilt" => if zh { "尚未构建" } else { "not built yet" },
        "lab.tool.ring.title" => "RingScope",
        "lab.tool.ring.blurb" => if zh {
            "拔盘、掉 zone、加机器 —— 看清哪些 partition 会迁移、多少数据要过网络、集群还能扛住什么。"
        } else {
            "Pull a disk, lose a zone, add a machine — see which partitions move, how much \
             data crosses the network, and what the cluster can still survive."
        },
        "lab.tool.policy.title" => if zh { "策略经济学" } else { "Policy Economist" },
        "lab.tool.policy.blurb" => if zh {
            "在耐久性、成本、重建流量和修复时间上对比多副本与纠删码，用的是本集群的真实容量。"
        } else {
            "Compare replication against erasure coding on durability, cost, rebuild traffic \
             and repair time, against this cluster's real capacity."
        },
        "lab.tool.capsule.title" => if zh { "对象胶囊" } else { "Object Capsule" },
        "lab.tool.capsule.blurb" => if zh {
            "单个对象的完整诊断：storage policy、partition、每一份副本或分片、每块盘上真正存了什么、现在还读不读得出 —— 可以当链接发出去。"
        } else {
            "One object's full diagnostic: policy, partition, every replica or fragment, what \
             each disk actually holds, and whether it still reads — shareable as a link."
        },
        "lab.tool.tombstone.title" => if zh { "墓碑博物馆" } else { "Tombstone Museum" },
        "lab.tool.tombstone.blurb" => if zh {
            "把一个对象的一生画成时间轴：写入、副本落盘、删除、tombstone、冲突与收敛 —— 附一份尸检报告。"
        } else {
            "An object's whole life as a timeline: writes, replicas landing, deletes, \
             tombstones, conflicts and convergence — with an autopsy."
        },
        "lab.tool.shadow.title" => if zh { "接口对照" } else { "API Parity" },
        "lab.tool.shadow.blurb" => if zh {
            "录制真实请求的响应，与第二套实现或历史回放逐字段比对：状态码、header、ETag、元数据、listing 与收敛行为，积累一份接口兼容性语料。"
        } else {
            "Record real request responses and diff them field by field against a second \
             implementation or a historical replay — status, headers, ETag, metadata, \
             listings, and convergence — building an API compatibility corpus."
        },
        "lab.tool.nodes.title" => if zh { "节点宕机演练" } else { "Node HA Drill" },
        "lab.tool.nodes.blurb" => if zh {
            "让整台存储节点宕机，观察集群在少一节点时的读写与自愈；到期自动重启。"
        } else {
            "Take a whole storage node down and watch the cluster serve and heal with one node gone; auto-restarts on TTL."
        },
        "nodes.disabled" => if zh {
            "节点宕机需要在配置中开启 lab_mutations。"
        } else {
            "Node down/up requires lab_mutations to be enabled in the config."
        },
        "nodes.col.node" => if zh { "节点" } else { "Node" },
        "nodes.col.state" => if zh { "状态" } else { "State" },
        "nodes.col.services" => if zh { "服务" } else { "Services" },
        "nodes.col.action" => if zh { "操作" } else { "Action" },
        "nodes.state.up" => if zh { "正常" } else { "up" },
        "nodes.state.down" => if zh { "演练宕机" } else { "DOWN (drill)" },
        "nodes.state.degraded" => if zh { "降级" } else { "degraded" },
        "nodes.state.unreachable" => if zh { "不可达" } else { "unreachable" },
        "nodes.act.take" => if zh { "下机" } else { "Take down" },
        "nodes.act.bring" => if zh { "恢复上线" } else { "Bring up" },
        "nodes.act.confirm" => if zh {
            "确认让 {node} 下机？到期后会自动重启。"
        } else {
            "Take {node} down? It auto-restarts after the TTL."
        },
        "nodes.act.stopping" => if zh { "正在停止 {node}…" } else { "stopping {node}…" },
        "nodes.act.starting" => if zh { "正在启动 {node}…" } else { "starting {node}…" },
        "nodes.act.down_ok" => if zh {
            "{node} 已下机；约 {secs} 秒后自动重启"
        } else {
            "{node} down; auto-restart in {secs}s"
        },
        "nodes.act.up_ok" => if zh { "{node} 已恢复" } else { "{node} back up" },
        "wh.preview.title" => if zh { "对象预览" } else { "Object preview" },
        "wh.preview.close" => if zh { "关闭" } else { "Close" },
        "wh.preview.loading" => if zh { "读取中…" } else { "Loading…" },
        "wh.preview.hint" => if zh {
            "点击血缘图里的文件节点可预览前几 KB（真实对象，Range 读取）。"
        } else {
            "Click a file node in the lineage graph to preview the first few KB (live Range GET)."
        },
        "lab.tool.chaos.title" => if zh { "故障街机" } else { "Chaos Arcade" },
        "lab.tool.chaos.blurb" => if zh {
            "选一种故障、先预测结果，再让集群真的跑一遍，然后回放修复过程。每个故障都自带撤销。"
        } else {
            "Pick a fault, predict the outcome, then watch the cluster actually run it and \
             replay the repair. Every fault carries its own undo."
        },
        "lab.tool.warehouse.title" => if zh { "Agent 仓库" } else { "Agent Warehouse" },
        "lab.tool.warehouse.blurb" => if zh {
            "这是集群上的一块对象工作区，专门给自动化任务用：每个任务一个目录，中间文件会过期，\
             正式产出留下血缘，agent 通过 MCP 读写，人和控制台看的是同一份数据。"
        } else {
            "A cluster-side object workspace for automated jobs: one directory per job, \
             working files expire, published artifacts keep lineage, and agents read and \
             write it over MCP — the same data the console shows."
        },
        "lab.tool.debt.title" => if zh { "修复债务指数" } else { "Repair Debt Index" },
        "lab.tool.debt.blurb" => if zh {
            "把复制积压、磁盘压力、ring 不平衡和修复吞吐压成一个状态变量：损伤速度是否超过自我修复速度？"
        } else {
            "Compress backlog, disk pressure, ring imbalance and repair throughput into one \
             state variable: is damage arriving faster than the cluster can repay it?"
        },
        "debt.proxy_note" => if zh {
            "债务由可审计的代理指标计算（async_pending、quarantine、ring balance、磁盘与复制速率），不是虚构的 backlog gauge。"
        } else {
            "Debt is computed from auditable proxies (async_pending, quarantine, ring balance, \
             disk and replicator rates) — not a fabricated backlog gauge."
        },
        "debt.k.debt" => if zh { "修复债务" } else { "Repair Debt" },
        "debt.k.interest" => if zh { "利息（变化率）" } else { "Interest rate" },
        "debt.k.tti" => if zh { "距失控" } else { "Time to insolvency" },
        "debt.tti.none" => if zh { "∞（债务未膨胀）" } else { "∞ (not growing)" },
        "debt.tti.insolvent" => if zh { "已失控" } else { "already insolvent" },
        "debt.h.top" => if zh { "最大债务来源" } else { "Largest debt source" },
        "debt.h.bars" => if zh { "贡献分解" } else { "Contribution breakdown" },
        "debt.h.feed" => if zh { "原始代理数据" } else { "Raw proxy feeds" },
        "debt.c.backlog" => if zh { "复制/隔离积压" } else { "Replication / quarantine backlog" },
        "debt.c.balance" => if zh { "Ring 不平衡" } else { "Ring imbalance" },
        "debt.c.disk" => if zh { "磁盘压力" } else { "Disk pressure" },
        "debt.c.failures" => if zh { "复制失败速率" } else { "Replicator failure rate" },
        "debt.c.unhealthy" => if zh { "Swift 节点不健康" } else { "Unhealthy Swift nodes" },
        "wh.how.title" => if zh { "它实际在做什么" } else { "What this actually does" },
        "wh.how.1.t" => if zh { "1. 建任务" } else { "1. Create a job" },
        "wh.how.1.d" => if zh {
            "在集群上建出 inputs/、working/、artifacts/ 四个目录，并写入任务说明。"
        } else {
            "Creates inputs/, working/, and artifacts/ on the cluster and writes a job manifest."
        },
        "wh.how.2.t" => if zh { "2. 写中间结果" } else { "2. Write working files" },
        "wh.how.2.d" => if zh {
            "中间产物进 working/，由 Swift 的临时 URL / 过期时间负责删除，不会永久占盘。"
        } else {
            "Intermediate outputs go into working/ and expire under Swift’s own delete-at rules."
        },
        "wh.how.3.t" => if zh { "3. 发布产出" } else { "3. Publish artifacts" },
        "wh.how.3.d" => if zh {
            "值得留下的文件提升到 artifacts/，并记下它是从哪些输入算出来的，方便事后核对。"
        } else {
            "Keepers are promoted into artifacts/ with the inputs they were built from recorded."
        },

        // ---- Chaos Arcade ----
        "chaos.disarmed" => if zh {
            "故障注入未启用：控制台配置里没有开 lab_mutations 和 lab_root。没有沙箱边界就不会动任何数据。"
        } else {
            "Fault injection is off: lab_mutations and lab_root are not set in the console \
             config. Without a sandbox boundary this tool will not touch anything."
        },
        "chaos.q.drop_copy" => if zh {
            "删掉一份副本或分片后，对象还读得出来吗？谁来修，多久？"
        } else {
            "With one replica or fragment gone, does the object still read — and who \
             rebuilds it, how fast?"
        },
        "chaos.q.corrupt_copy" => if zh {
            "文件名和大小都没变，只有内容被改坏了。集群会发现吗？"
        } else {
            "The name and size are untouched and only the bytes are wrong. Does the \
             cluster notice?"
        },
        "chaos.q.drop_durable" => if zh {
            "去掉 durability marker，这份分片还算数吗？"
        } else {
            "Without its durability marker, does that fragment still count?"
        },
        "chaos.q.stale_timestamp" => if zh {
            "一份旧时间戳的副本重新出现，它会赢还是会被清掉？"
        } else {
            "An older-timestamped copy reappears. Does it win, or get cleaned up?"
        },

        // ---- API Parity ----
        "shadow.intro" => if zh {
            "对照本集群与另一套实现（或历史回放）对每个请求的响应。持久资产是语料库：每个请求、两边的回答、差异定级，以及哪一边的行为才是对的。"
        } else {
            "Compare this cluster's response to each request against a second implementation \
             or a historical replay. The durable asset is the corpus: every request, both \
             answers, how the difference classifies, and which behaviour is correct."
        },
        "shadow.cap.parity.t" => if zh { "接口对照" } else { "API Parity" },
        "shadow.cap.parity.d" => if zh {
            "同一请求的两份响应并排呈现，逐字段标注一致、表面差异、语义差异与破坏性差异。"
        } else {
            "Place two responses to the same request side by side, field by field, marking \
             identical, cosmetic, semantic, and breaking differences."
        },
        "shadow.cap.compat.t" => if zh { "兼容性比对" } else { "Compatibility Diff" },
        "shadow.cap.compat.d" => if zh {
            "按行为族汇总差异：listing、元数据、ETag、区间读取、拒绝路径与收敛时间各自独立定级。"
        } else {
            "Summarise differences by behaviour family: listings, metadata, ETag, byte ranges, \
             refusal paths, and convergence each get their own classification."
        },
        "shadow.cap.response.t" => if zh { "响应比对" } else { "Response Diff" },
        "shadow.cap.response.d" => if zh {
            "状态码、header、body 摘要与元数据 key 的大小写全部参与比对；已知噪声字段按规则挡掉。"
        } else {
            "Status code, headers, body digest, and metadata key casing all participate; \
             known noise fields are set aside by rule."
        },
        "shadow.act.capture" => if zh { "采集一轮" } else { "Capture a run" },
        "shadow.act.replay" => if zh { "回放最近一轮" } else { "Replay the latest run" },
        "shadow.act.mutate" => if zh { "协议突变" } else { "Mutate" },
        "shadow.act.mutate_seed" => if zh { "种子" } else { "Seed" },
        "shadow.act.hint" => if zh {
            "采集会在本工具自己的两个临时容器里建测试数据，跑完即删；不碰其他任何数据。协议突变用种子生成非常规请求序列，寻找语义裂缝。"
        } else {
            "A capture builds its fixture in two scratch containers this tool owns and removes \
             them when it finishes. Mutate builds a seeded unconventional request sequence to \
             hunt semantic cracks."
        },

        "shadow.empty.h" => if zh { "语料库还是空的。" } else { "The corpus is empty." },
        "shadow.empty.d" => if zh {
            "点上面的「采集一轮」，把下面这些行为逐条发给集群，并把确切的回答录下来——状态码、每一个响应头、ETag、元数据 key 的大小写、字节区间的边界、错误响应体。录完之后可以回放，也可以在第二套实现配置好后直接拿去比对。"
        } else {
            "Capture a run to send each of the behaviours below to the cluster and record the \
             exact answers — status code, every response header, the ETag, the case of each \
             metadata key, byte-range boundaries, error bodies. Once recorded they can be \
             replayed, and diffed once a second implementation is configured."
        },

        "shadow.mode.single" => if zh { "单端" } else { "single-sided" },
        "shadow.mode.dual" => if zh { "双端" } else { "two-sided" },
        "shadow.mode.single.h" => if zh {
            "单端模式：未配置第二套实现。"
        } else {
            "Single-sided: no second implementation is configured."
        },
        "shadow.mode.single.d" => if zh {
            "没有配置第二个端点，因此这里没有任何一条记录被比对过。语料库存的是基准：这套集群对每个请求的确切回答。回放能抓出这套实现相对于历史记录的漂移。这里不会给出兼容率，因为没有可以当分母的东西。"
        } else {
            "No second endpoint is configured, so nothing here has been compared to anything. \
             The corpus holds a reference: the exact answers this cluster gives. A replay \
             catches this implementation drifting from its own record. There is no \
             compatibility percentage because there is no denominator."
        },
        "shadow.mode.dual.h" => if zh {
            "双端模式：每个请求同时发给本集群和 {0}，两边的回答都已录入并比对。"
        } else {
            "Two-sided: every request goes to this cluster and to {0}; both answers are \
             recorded and compared."
        },

        "shadow.verdict.single" => if zh {
            "已从一套实现录下 {0} 个请求，覆盖 {1} 类行为——这是一份基准语料，不是兼容性结论。"
        } else {
            "{0} requests recorded from one implementation across {1} behaviour families — a \
             reference corpus, not a compatibility result."
        },
        "shadow.verdict.clean" => if zh {
            "扣掉必然不同的字段之后，{0} 个请求两边的回答完全一致——这一组请求上没有发现兼容性问题。"
        } else {
            "All {0} requests answered identically once the fields that must differ were set \
             aside — no compatibility finding on this request set."
        },
        "shadow.verdict.diff" => if zh {
            "{3} 个请求里发现 {0} 处会直接把接入方打断的差异、{1} 处语义差异、{2} 处仅表面差异：按其中一套实现写出来的客户端，在另一套上会拿到不同的答案。"
        } else {
            "{0} breaking, {1} semantic and {2} cosmetic differences across {3} compared \
             requests: a client written against one implementation gets a different answer \
             from the other."
        },
        "shadow.denom.single" => if zh {
            "分母：0 次比对 —— 每条记录都只有一边的答案。"
        } else {
            "Denominator: 0 comparisons — every record has one side only."
        },
        "shadow.denom.dual" => if zh {
            "分母：{0} 个请求，本集群与 {1} 各答一次，逐字段比对。"
        } else {
            "Denominator: {0} requests, answered once by this cluster and once by {1}, compared \
             field by field."
        },
        "shadow.olderrun" => if zh {
            "你正在看一轮较早的采集，不是最新的一轮。"
        } else {
            "This is an earlier run, not the most recent one."
        },

        "shadow.h.matrix" => if zh { "行为族 × 差异定级" } else { "Family by diff class" },
        "shadow.h.surface" => if zh { "真正参与比对的字段" } else { "What is actually compared" },
        "shadow.h.findings" => if zh { "发现" } else { "Findings" },
        "shadow.h.cases" => if zh { "逐个请求" } else { "Request by request" },
        "shadow.h.replay" => if zh { "回放：哪些结论仍然成立" } else { "Replay: which verdicts still hold" },
        "shadow.h.noise" => if zh { "必然不同的字段，以及为什么" } else { "Fields that must differ, and why" },
        "shadow.h.corpus" => if zh { "语料库" } else { "The corpus" },

        "shadow.class.identical" => if zh { "完全一致" } else { "Identical" },
        "shadow.class.cosmetic" => if zh { "表面差异" } else { "Cosmetic" },
        "shadow.class.semantic" => if zh { "语义差异" } else { "Semantic" },
        "shadow.class.breaking" => if zh { "破坏性差异" } else { "Breaking" },
        "shadow.class.unpaired" => if zh { "未比对" } else { "Unpaired" },

        "shadow.fam.listing" => if zh { "容器列表" } else { "Listings" },
        "shadow.fam.meta" => if zh { "元数据" } else { "Metadata" },
        "shadow.fam.etag" => if zh { "ETag 摘要" } else { "ETag" },
        "shadow.fam.range" => if zh { "字节区间" } else { "Byte ranges" },
        "shadow.fam.error" => if zh { "拒绝路径" } else { "Refusals" },
        "shadow.fam.convergence" => if zh { "收敛" } else { "Convergence" },
        "shadow.famd.listing" => if zh {
            "列表里有什么、按什么顺序、空容器长什么样，以及 prefix / marker / limit / delimiter 各自怎么裁剪。"
        } else {
            "What is in a listing, in what order, what an empty container looks like, and how \
             prefix, marker, limit and delimiter each cut it."
        },
        "shadow.famd.meta" => if zh {
            "用户自定义元数据的往返，包括 key 的大小写是否被原样保留。"
        } else {
            "User metadata surviving a round trip, including whether the case of the key is \
             preserved."
        },
        "shadow.famd.etag" => if zh {
            "集群为它持有的内容交回的摘要，以及条件请求怎么用它。"
        } else {
            "The digest handed back for content the cluster holds, and how conditional \
             requests use it."
        },
        "shadow.famd.range" => if zh {
            "字节区间的边界：第一个字节、最后一个字节、越界、无法满足的区间、多段区间和写错的区间。"
        } else {
            "Byte-range boundaries: the first byte, the last byte, past the end, an \
             unsatisfiable range, a multi-range and a malformed one."
        },
        "shadow.famd.error" => if zh {
            "拒绝路径：返回哪个状态码，响应体又说了什么。"
        } else {
            "Refusals: which status code comes back, and what the body says."
        },
        "shadow.famd.convergence" => if zh {
            "DELETE 之后，容器列表要过多久才不再提到这个对象——实测，不是假设。"
        } else {
            "How long after a DELETE the container listing stops naming the object — measured, \
             not assumed."
        },

        "shadow.col.family" => if zh { "行为族" } else { "Family" },
        "shadow.col.case" => if zh { "请求" } else { "Request" },
        "shadow.col.status" => if zh { "状态码" } else { "Status" },
        "shadow.col.ms" => if zh { "耗时 ms" } else { "ms" },
        "shadow.col.findings" => if zh { "发现数" } else { "Findings" },
        "shadow.col.class" => if zh { "定级" } else { "Class" },
        "shadow.col.header" => if zh { "响应头" } else { "Header" },
        "shadow.col.why" => if zh { "为什么允许它不同" } else { "Why it is allowed to differ" },
        "shadow.col.scope" => if zh { "适用范围" } else { "Applies to" },
        "shadow.col.verdict" => if zh { "结论" } else { "Verdict" },
        "shadow.col.evidence" => if zh { "依据" } else { "Evidence" },
        "shadow.col.run" => if zh { "轮次" } else { "Run" },
        "shadow.col.when" => if zh { "时间 (UTC)" } else { "When (UTC)" },
        "shadow.col.mode" => if zh { "模式" } else { "Mode" },
        "shadow.col.cases" => if zh { "个请求" } else { "requests" },
        "shadow.col.probes" => if zh { "会探测什么" } else { "What it probes" },

        "shadow.matrix.d" => if zh {
            "每一格是落在该行为族、该定级下的请求数。单边模式下所有请求都落在最后一列，这正是这张表要说的事：语料库里到目前为止有多少内容真正被比对过。"
        } else {
            "Each cell is the number of requests in that family that landed in that class. \
             Single-sided, everything sits in the last column — which is exactly what the grid \
             is for: how much of this corpus has ever been compared to anything."
        },
        "shadow.surface.d" => if zh {
            "一句兼容性结论真正的分母是「比对了多少个字段」，而不是「发了多少个请求」。这里把它摊开：有多少响应头字段进入比对，有多少被噪声名单挡掉，其中又有多少真的不一样。"
        } else {
            "The honest denominator of a compatibility claim is fields compared, not requests \
             sent. This is that number, opened up: how many header fields entered the \
             comparison, how many the noise list set aside, and how many actually differ."
        },
        "shadow.surface.compared" => if zh { "参与比对" } else { "Compared" },
        "shadow.surface.suppressed" => if zh { "按噪声挡掉" } else { "Set aside as noise" },
        "shadow.surface.differing" => if zh { "确有差异" } else { "Differing" },

        "shadow.findings.none" => if zh {
            "没有发现：扣掉必然不同的字段之后，两边逐字段完全一致。"
        } else {
            "No findings: once the fields that must differ were set aside, the two answers \
             matched field for field."
        },
        "shadow.findings.none.single" => if zh {
            "这里不会有发现，因为没有做过比对。只有一边回答的时候，能录下的是回答本身，不是结论。"
        } else {
            "There are no findings here because nothing was compared. With one side answering, \
             what can be recorded is the answer, not a verdict."
        },

        "shadow.cases.rawa" => if zh { "本集群" } else { "This cluster" },
        "shadow.cases.nob" => if zh {
            "第二边没有响应可放：没有配置第二个端点。这一格是空的，不是相同的。"
        } else {
            "There is no second response to put here: no second endpoint is configured. This \
             slot is empty, not equal."
        },
        "shadow.cases.trunc" => if zh { "响应体已截断，完整内容由上面的 md5 覆盖" } else { "body truncated; the md5 above covers all of it" },

        "shadow.conv.ok" => if zh {
            "DELETE 之后 {0} ms、第 {1} 次轮询时，列表不再提到该对象。"
        } else {
            "The listing stopped naming the object {0} ms after the DELETE, on poll {1}."
        },
        "shadow.conv.stuck" => if zh {
            "8 秒的观测窗口内，列表始终还在提这个已删除的对象。窗口之外发生了什么，未知。"
        } else {
            "The listing still named the deleted object throughout the 8 s window. What happens \
             after that window is unknown — it was not measured."
        },

        "shadow.replay.none" => if zh {
            "还没有回放过。回放会把语料库里每一个请求按原样重新发给当前的集群，再逐字段对照当初录下的回答，报告哪些结论仍然成立——这一步才让这份语料从日志变成回归测试。"
        } else {
            "Nothing has been replayed yet. A replay re-issues every stored request against the \
             cluster as it is now and checks each answer field by field against what was \
             recorded — that is the step that turns this corpus from a log into a regression \
             suite."
        },
        "shadow.replay.verdict" => if zh {
            "{1} 条已录行为中 {0} 条仍然成立，{2} 条发生漂移。复核时间 {3} UTC。"
        } else {
            "{0} of {1} recorded behaviours still hold; {2} drifted. Re-checked {3} UTC."
        },
        "shadow.replay.holds" => if zh { "仍然成立" } else { "Holds" },
        "shadow.replay.drifted" => if zh { "已漂移" } else { "Drifted" },
        "shadow.replay.error" => if zh { "没跑成" } else { "Not run" },
        "shadow.replay.same" => if zh { "与录下的回答逐字段一致。" } else { "Field for field, the same answer as recorded." },

        "shadow.corpus.d" => if zh {
            "{0} 条记录，{1} 轮采集，占 {2}。写在磁盘上、可追加、重启后仍在。"
        } else {
            "{0} records across {1} runs, {2} on disk. Appended to a file, so it survives a \
             restart."
        },
        "shadow.corpus.span" => if zh { "最早 {0}，最新 {1}。" } else { "Earliest {0}, latest {1}." },

        "shadow.noise.d" => if zh {
            "两台服务器在这些字段上本来就必须不同。把它们报成差异，是让兼容性工具变成没人再看的噪声的最快方式，所以名单写死在这里，每一条都附上理由。"
        } else {
            "Two servers must differ on these fields. Reporting them is the fastest way to turn \
             a compatibility tool into noise nobody reads, so the list is written down here and \
             every entry carries its reason."
        },
        "shadow.noise.always" => if zh { "始终" } else { "always" },
        "shadow.noise.replayonly" => if zh { "仅回放时" } else { "replay only" },

        "shadow.why.date" => if zh {
            "每个响应都带着应答方自己的时钟。两台服务器回答同一个请求的时刻本来就不同。"
        } else {
            "Every response carries the responder's own clock. Two servers answering the same \
             request answer at different instants."
        },
        "shadow.why.transid" => if zh {
            "逐请求生成的唯一标识。这里如果相等，说明标识本身坏了，而不是两套实现一致。"
        } else {
            "A per-request identifier, unique by construction. Equal values here would mean the \
             identifier is broken, not that the implementations agree."
        },
        "shadow.why.reqid" => if zh {
            "同一个逐请求标识的 OpenStack 名字。"
        } else {
            "The same per-request identifier under its OpenStack name."
        },
        "shadow.why.transidextra" => if zh {
            "回显在事务 id 上的调用方后缀；它跟着标识走，跟回答无关。"
        } else {
            "The caller-supplied suffix echoed onto the transaction id. It travels with the \
             identifier, not with the answer."
        },
        "shadow.why.server" => if zh {
            "实现自报的名号。两套实现在这里不同正是本工具的前提，不是缺陷。"
        } else {
            "The implementation banner. Two implementations differing here is the premise of \
             this tool, not a finding."
        },
        "shadow.why.hopbyhop" => if zh {
            "连接层的传输框架（RFC 9110 §7.6.1）。它属于这一跳而不属于消息本身，任何中间代理都可以改写。"
        } else {
            "Connection framing (RFC 9110 §7.6.1). It belongs to the hop, not to the message, \
             and any intermediary may rewrite it."
        },
        "shadow.why.via" => if zh {
            "记录响应经过了哪些代理——这是路径的属性，不是回答的属性。"
        } else {
            "Records which proxies the response passed through — a property of the path, not of \
             the answer."
        },
        "shadow.why.backend" => if zh {
            "内部管道用的头。它们从来不属于对客户端的契约，这里的差异伤不到接入方。"
        } else {
            "Internal plumbing headers. They are never part of the client contract, so a \
             difference here cannot break an integrator."
        },
        "shadow.why.token" => if zh {
            "每次登录单独签发的会话凭据。两套实现签出来的本来就不该一样。"
        } else {
            "Session credentials, issued per login. Two implementations must issue different \
             ones."
        },
        "shadow.why.replayts" => if zh {
            "写入时间戳。回放会重建测试数据，所以同一个请求描述的确实是一个更新的对象。两套实现之间它不算噪声。"
        } else {
            "The write timestamp. A replay re-creates its fixture, so the same request \
             legitimately describes a newer object. Between two implementations it is not \
             noise."
        },
        "shadow.why.replaymod" => if zh {
            "Last-Modified 由写入时间戳推导而来，回放时会跟着一起变。"
        } else {
            "Last-Modified is derived from that write timestamp and moves with it on a replay."
        },

        "shadow.h.limits" => if zh { "这一轮没有测到的东西" } else { "What this run did not measure" },
        "shadow.limits.d" => if zh {
            "一份说自己测了什么的报告，必须同样说清楚自己没测什么。以下每一条都是这套采集路径看不到的，因此在上面的任何结论里都算「未知」，而不是「一致」。"
        } else {
            "A report that says what it measured has to say what it did not. Each line below is \
             something this capture path cannot see, and therefore counts as unknown in every \
             verdict above — never as agreement."
        },
        "shadow.limits.case" => if zh {
            "响应头名字在网线上的大小写：本控制台用的 HTTP 客户端会把收到的头名统一转成小写，所以两套实现之间真实的头名大小写差异，采集端根本观察不到。比对逻辑本身能识别并定级这种差异（元数据 key 的大小写按语义差异处理），但要真正测到它，得换一个保留原始大小写的采集客户端。"
        } else {
            "The case of header names on the wire. The HTTP client this console uses lower-cases \
             every header name it receives, so a real difference in header-name case between two \
             implementations is invisible to the capture path. The diff core does recognise and \
             classify it — a metadata key differing in case is treated as semantic — but actually \
             observing it would need a capture client that preserves the case it was sent."
        },
        "shadow.limits.order" => if zh {
            "响应头的先后顺序：同样没有被保留，所以顺序差异不会被发现。对合规的客户端来说这无关紧要，但这里不假装测过。"
        } else {
            "The order response headers arrive in. It is not preserved either, so an ordering \
             difference would go unseen. It does not matter to a compliant client, but it is not \
             claimed as measured here."
        },
        "shadow.limits.dup" => if zh {
            "同一个头出现多次时，采集端会把它们按客户端库看到的样子合并成一行；因此「发了两次」和「发了一次逗号分隔」这两种情况在这里是分不开的。"
        } else {
            "A header sent more than once is joined into one line, the way a client library sees \
             it. Sending a field twice and sending it once comma-separated are therefore \
             indistinguishable here."
        },
        "shadow.limits.body" => if zh {
            "超过 2 KiB 的响应体只保留前 2 KiB 原文，完整内容用 md5 摘要覆盖。摘要相同即内容相同；摘要不同时，页面上能展开看到的只是开头那一段。"
        } else {
            "Bodies over 2 KiB keep only their first 2 KiB verbatim; the whole body is covered by \
             an md5. Equal digests mean equal content, but when they differ, only that opening \
             slice can be read back on this page."
        },
        "shadow.limits.window" => if zh {
            "收敛只在 DELETE 之后的 8 秒窗口内测量。窗口内收敛了，报的是实测毫秒数；没收敛，报的就是「没收敛」，而不是一个猜出来的更长时间。"
        } else {
            "Convergence is measured inside an 8 s window after the DELETE. Converged inside it, \
             the number reported is measured; not converged, what is reported is that it did not \
             — never a guess at a longer time."
        },
        "shadow.limits.scope" => if zh {
            "只观察对外的请求与响应。磁盘上的布局、副本与分片的分布、后台进程做了什么，都不在这份语料里——那些是 Lab 里其他工具的事。"
        } else {
            "Only the request and the response are observed. What is on disk, how replicas and \
             fragments are placed, and what background processes did are not in this corpus — \
             other Lab tools answer those."
        },
        "shadow.why.replayacct" => if zh {
            "账户级的总计数（容器数、对象数、已用字节、各策略小计）。它们属于这个账户，不属于这次请求：只要有别的客户端往同一个账户写东西，两次采集之间它们就会变。两套实现之间它们仍然要比。"
        } else {
            "Account-wide totals — container count, object count, bytes used, per-policy \
             subtotals. They belong to the account, not to this request: any other client \
             writing to the same account moves them between two captures. Between two \
             implementations they are still compared."
        },
        "shadow.why.clen" => if zh {
            "对列表响应来说，Content-Length 只是响应体的另一种说法，而响应体已经在逐条比对了。再比一次，会把一处列表差异报成两处；列表完全一致时它也不会报。"
        } else {
            "On a listing, Content-Length only restates a body that is already being compared \
             entry by entry. Comparing it as well turns one listing difference into two, and it \
             raises nothing when the listing matches."
        },
        "shadow.noise.listingonly" => if zh { "仅列表响应" } else { "listings only" },
        "shadow.why.crange" => if zh {
            "对区间请求来说，Content-Range 声明的正是「返回了哪一段」，而这一段已经连同实际字节数一起比过了。再按普通响应头比一次，同一处边界差异会被报成两条。"
        } else {
            "On a range request, Content-Range declares the window that has already been judged \
             alongside the bytes that actually arrived. Comparing it again as an ordinary header \
             reports one boundary difference as two."
        },
        "shadow.noise.rangeonly" => if zh { "仅区间请求" } else { "range requests only" },
        "shadow.rule.status.class" => if zh {
            "一边返回 {0}，另一边返回 {1}。按状态码大类分支的客户端会走进完全不同的路径——本该走错误处理的地方走了成功处理，或者反过来。"
        } else {
            "One implementation answers {0}, the other {1}. A client branching on the status \
             class takes a different path entirely — a success handler runs where an error \
             handler should, or the other way round."
        },
        "shadow.rule.status.code" => if zh {
            "两边同属一个大类（{0} 对 {1}），但按精确状态码分支的客户端——503 重试、500 放弃——会在其中一边走错。"
        } else {
            "Both answer in the same class ({0} vs {1}), but a client that matches the exact \
             code — retry on 503, give up on 500 — takes the wrong branch on one of them."
        },
        "shadow.rule.hdr.missing" => if zh {
            "{0} 只有一边返回，另一边没有。读这个头的客户端在一边拿到值、在另一边什么都拿不到，而且没有任何报错提示它。"
        } else {
            "{0} is returned by one implementation and absent from the other. A client that \
             reads it gets a value on one and nothing on the other, with no error to tell them \
             apart."
        },
        "shadow.rule.hdr.value" => if zh {
            "{0} 一边是 {1}，另一边是 {2}。"
        } else {
            "{0} is {1} on one side and {2} on the other."
        },
        "shadow.rule.hdr.case" => if zh {
            "只有头名字的大小写不同（{0} 对 {1}）。协议上头名字不区分大小写，规范的客户端不受影响；但用原始 header 字典按精确 key 取值的客户端会取空。"
        } else {
            "The header name differs only in case ({0} vs {1}). Header names are \
             case-insensitive on the wire, so a compliant client is unaffected; one that \
             indexes a raw header dictionary by exact key is not."
        },
        "shadow.rule.ctype.value" => if zh {
            "Content-Type 一边是 {0}，另一边是 {1}。按它分发的客户端——当 JSON 解析，还是当纯文本原样返回——会走不同分支。"
        } else {
            "Content-Type is {0} on one side and {1} on the other. A client that dispatches on \
             it — parse as JSON, or hand back as text — takes a different branch."
        },
        "shadow.rule.etag.value" => if zh {
            "同样的字节被给出了两个不同的 ETag（{0} 对 {1}）。条件请求和客户端完整性校验在跨实现时会失败，同步工具会把所有对象重传一遍。"
        } else {
            "The same bytes come back with two different ETags ({0} vs {1}). Conditional \
             requests and client-side integrity checks fail across implementations, and a sync \
             tool re-uploads everything."
        },
        "shadow.rule.etag.quoting" => if zh {
            "ETag 只差在引号上（{0} 对 {1}）。RFC 9110 要求带引号；把不带引号的值和带引号的值直接做字符串比较的客户端，会认为每个对象都变了。"
        } else {
            "The ETag differs only in its quoting ({0} vs {1}). RFC 9110 requires the quotes; a \
             client that string-compares an unquoted value against a quoted one sees every \
             object as changed."
        },
        "shadow.rule.meta.keycase" => if zh {
            "元数据 key 一边回来是 {0}，另一边是 {1}。在协议层这是同一个头，但把元数据放进区分大小写字典的客户端，会在两套实现上读到两个不同的 key。"
        } else {
            "The metadata key comes back as {0} on one side and {1} on the other. On the wire \
             that is the same header, but a client that keeps metadata in a case-sensitive map \
             reads one key on one implementation and a different key on the other."
        },
        "shadow.rule.meta.missing" => if zh {
            "元数据 {0} 在一套实现上能原样往返，在另一套上被丢掉了。把状态存在对象元数据里的系统，迁移时会直接丢数据。"
        } else {
            "Metadata {0} survives the round trip on one implementation and is dropped by the \
             other. Anything that keeps state in object metadata loses it on migration."
        },
        "shadow.rule.meta.value" => if zh {
            "元数据 {0} 往返之后一边是 {1}，另一边是 {2}。"
        } else {
            "Metadata {0} round-trips as {1} on one side and {2} on the other."
        },
        "shadow.rule.listing.membership" => if zh {
            "有 {0} 个条目只出现在其中一边的列表里（{1}）。同步或备份客户端会因为对接的是哪一边，而复制出不同的对象集合。"
        } else {
            "{0} entries are listed by one implementation and not the other ({1}). A sync or \
             backup client copies a different set of objects depending on which it reached."
        },
        "shadow.rule.listing.order" => if zh {
            "两边列出的都是同样的 {0} 个条目，但顺序不同，第一处差异在第 {1} 位。基于 marker 的分页会按不同顺序遍历容器，可能整页重复或整页漏掉。"
        } else {
            "Both list the same {0} entries but in a different order, first differing at \
             position {1}. Marker-based pagination walks the container in a different sequence \
             and can repeat or skip a whole page."
        },
        "shadow.rule.listing.field" => if zh {
            "条目 {1} 的 {0} 一边是 {2}，另一边是 {3}。"
        } else {
            "{0} on entry {1} is {2} on one side and {3} on the other."
        },
        "shadow.rule.listing.count" => if zh {
            "两边的名字集合相同，条目数却不同（{0} 对 {1}）：有一边把某个条目列了两次，分页会因此错位。"
        } else {
            "The two listings name the same objects but hold {0} and {1} entries: one side \
             lists an entry twice, which throws pagination off by a row."
        },
        "shadow.rule.range.status" => if zh {
            "同一个字节区间，一边返回 {0}，另一边返回 {1}。断点续传要么真的续上，要么悄悄从头再来，取决于它连的是哪一边。"
        } else {
            "The same byte range answers {0} on one implementation and {1} on the other. A \
             resumable download either resumes or silently restarts from zero, depending on \
             which it reached."
        },
        "shadow.rule.range.boundary" => if zh {
            "同一个区间一边返回 {0} 字节，另一边返回 {1} 字节（Content-Range 为 {2} 对 {3}）。按分片拼回来的文件会直接损坏，而且全程不报错。"
        } else {
            "The same range returns {0} bytes on one side and {1} on the other (Content-Range \
             {2} vs {3}). A download reassembled from parts is corrupt without ever reporting \
             an error."
        },
        "shadow.rule.body.error" => if zh {
            "两边拒绝的方式一致，只是提示语不同（{0} 对 {1}）。凡是按提示文本匹配、而不是按状态码判断的代码都会失效。"
        } else {
            "Both refuse the request the same way; only the wording differs ({0} vs {1}). \
             Anything that matches on the message text rather than the status code breaks."
        },
        "shadow.rule.body.bytes" => if zh {
            "两边的响应体不是同一份内容：{0} 字节对 {1} 字节，摘要 {2} 对 {3}。"
        } else {
            "The response bodies are not the same content: {0} vs {1} bytes, digest {2} vs {3}."
        },
        "shadow.rule.conv.gap" => if zh {
            "删除之后列表停止提到该对象，一边用了 {0}，另一边用了 {1}。删完立刻回读的客户端，在两边看到的是不同的世界。"
        } else {
            "The listing stops naming the deleted object after {0} on one side and {1} on the \
             other. A client that reads back straight after a delete sees a different world on \
             each."
        },
        "shadow.rule.conv.stuck" => if zh {
            "有一边在 {0} 之后仍然把已删除的对象列在里面。这不是收敛慢，这是在观测窗口内根本没有收敛。"
        } else {
            "One implementation still lists the deleted object after {0}. That is not slow \
             convergence; that is a listing that did not converge inside the window measured."
        },

        // ---- Agent-Native Object Warehouse ----
        "wh.head.scanned" => if zh {
            "扫描于 {when} · 存储策略 {policy}"
        } else {
            "Scanned {when} · storage policy {policy}"
        },
        "wh.unknown" => if zh { "未测量" } else { "not measured" },
        "wh.u.d" => if zh { "天" } else { "d" },
        "wh.u.h" => if zh { "小时" } else { "h" },
        "wh.u.m" => if zh { "分" } else { "m" },
        "wh.u.s" => if zh { "秒" } else { "s" },

        "wh.v.scale" => if zh {
            "{jobs} 个任务，共 {objects} 个对象、{bytes}。"
        } else {
            "{jobs} jobs hold {objects} objects and {bytes}."
        },
        "wh.v.lineage.ok" => if zh {
            "全部 {n} 个 artifact 都记录了自己是从哪些输入做出来的，所以就算这个控制台被换掉，来源依然查得到。"
        } else {
            "All {n} artifacts name the inputs they were built from, so provenance survives this console being replaced."
        },
        "wh.v.lineage.gap" => if zh {
            "有 {n} 个 artifact 没记录输入 —— 对它们来说，这份数据从哪来，已经没法只靠存储回答了。"
        } else {
            "{n} artifacts do not name their inputs — for those, where the data came from can no longer be answered from the store alone."
        },
        "wh.v.lineage.none" => if zh {
            "还没有发布过 artifact，暂时没有血缘可查。"
        } else {
            "No artifacts have been published yet, so there is no lineage to check."
        },
        "wh.v.lineage.unread" => if zh {
            "有 {n} 个 artifact，但这次扫描一个都没读到，所以它们的血缘是未知，而不是没问题。"
        } else {
            "{n} artifacts exist but none were read in this scan, so their lineage is unknown, not clean."
        },
        "wh.v.expiry.ok" => if zh {
            "{n} 个 working 文件已在倒计时，最早的一个在 {when} 消失，还剩 {in}。"
        } else {
            "{n} working files are on the clock; the first one goes at {when}, in {in}."
        },
        "wh.v.expiry.none" => if zh {
            "当前没有 working 文件，也就没有东西会被自动清掉。"
        } else {
            "There are no working files, so nothing is scheduled to disappear."
        },
        "wh.v.expiry.bad" => if zh {
            "有 {n} 个 working 文件根本没设过期时间，除非有人手动删，它们会一直占着空间。"
        } else {
            "{n} working files carry no expiry at all — they will sit here until someone deletes them by hand."
        },
        "wh.v.nojobs" => if zh {
            "warehouse 容器已经在了，但里面还没有任何任务。"
        } else {
            "The warehouse container exists but holds no jobs yet."
        },
        "wh.v.nowarehouse" => if zh {
            "这个账户下还没有 warehouse：没有任何东西创建过它。"
        } else {
            "There is no warehouse on this account yet: nothing has created one."
        },
        "wh.v.unreadable" => if zh { "读不到 warehouse。" } else { "The warehouse could not be read." },

        "wh.f.nolineage.t" => if zh { "缺少输入记录的 artifact" } else { "Artifacts with no recorded inputs" },
        "wh.f.nolineage.d" => if zh {
            "这些对象发布时没有写入输入列表，它们怎么来的只存在于集群之外。用 promote 重新发布一次，血缘就会和数据写在一起。"
        } else {
            "These were published without an input list, so the only record of how they were made sits outside the cluster. Republish them through promote and the lineage is written next to the bytes."
        },
        "wh.f.noexpiry.t" => if zh { "没有过期时间的 working 文件" } else { "Working files with no expiry" },
        "wh.f.noexpiry.d" => if zh {
            "临时文件本来应该由集群自己回收。这几个写入时没带过期时间，不会有人来清理。"
        } else {
            "Scratch files are meant to be removed by the cluster itself. These were written without an expiry, so nothing will clean them up."
        },
        "wh.f.overdue.t" => if zh { "已过期但仍列在这里" } else { "Past their expiry but still listed" },
        "wh.f.overdue.d" => if zh {
            "标注的删除时间已经过去。这些对象已经读不出来了，只是容器列表还没跟上。"
        } else {
            "The stated delete time has passed. The objects are no longer readable; the container listing has simply not caught up."
        },
        "wh.f.layout.t" => if zh { "任务目录不完整" } else { "Incomplete job layout" },
        "wh.f.layout.d" => if zh {
            "一个任务应该有全部四个目录。少一个，下一个写入的人就得猜文件该放哪儿。"
        } else {
            "A job should carry all four directories. A missing one means the next writer has to guess where its files belong."
        },
        "wh.f.capped.t" => if zh { "并非每个对象的血缘都读过" } else { "Lineage was not read for every object" },
        "wh.f.capped.d" => if zh {
            "这次扫描最多读取 {n} 个对象的血缘，超出的部分一律记为未知，不会默认当成没问题。"
        } else {
            "This scan reads lineage for at most {n} objects. Anything past that is reported as unknown rather than assumed clean."
        },

        "wh.sec.lineage" => if zh { "数据从哪来、到哪去" } else { "Where data came from and went" },
        "wh.sec.expiry" => if zh { "即将过期的中间文件" } else { "Working files about to expire" },
        "wh.sec.jobs" => if zh { "任务一览" } else { "Jobs" },
        "wh.sec.actions" => if zh { "在这里建一个任务" } else { "Create a job here" },
        "wh.sec.mcp" => if zh { "给 agent 用的 MCP 接口" } else { "MCP endpoint for agents" },
        "wh.sec.mcp.sum" => if zh {
            "展开查看端点、协议和工具列表（人用本页即可，不必先读这些）"
        } else {
            "Endpoint, protocol, and tool list — people can use this page without opening this"
        },
        "wh.card.inputs" => if zh { "输入" } else { "inputs" },
        "wh.card.working" => if zh { "中间" } else { "working" },
        "wh.card.arts" => if zh { "产出" } else { "artifacts" },
        "wh.graph.note" => if zh {
            "下图只画有内容的任务：左输入 → 中任务 → 右产出。空任务见上方卡片。点击文件可在线预览。"
        } else {
            "The graph only draws jobs that hold objects: inputs left, job centre, outputs right. \
             Empty jobs are listed in the cards above. Click a file to preview."
        },

        "wh.st.published" => if zh { "已发布" } else { "published" },
        "wh.st.working" => if zh { "进行中" } else { "in progress" },
        "wh.st.staged" => if zh { "输入已就位" } else { "inputs staged" },
        "wh.st.empty" => if zh { "仅有目录" } else { "layout only" },

        "wh.th.job" => if zh { "任务" } else { "Job" },
        "wh.th.state" => if zh { "状态" } else { "State" },
        "wh.th.created" => if zh { "创建时间（UTC）" } else { "Created (UTC)" },
        "wh.th.goal" => if zh { "目标" } else { "Goal" },
        "wh.th.inputs" => if zh { "输入" } else { "Inputs" },
        "wh.th.working" => if zh { "中间文件" } else { "Working" },
        "wh.th.artifacts" => if zh { "产出 artifact" } else { "Artifacts" },
        "wh.th.bytes" => if zh { "占用空间" } else { "Stored" },
        "wh.th.artifact" => if zh { "产出 artifact" } else { "Artifact" },
        "wh.th.from" => if zh { "来自" } else { "Built from" },
        "wh.th.producer" => if zh { "产出方" } else { "Produced by" },
        "wh.th.size" => if zh { "大小" } else { "Size" },
        "wh.th.when" => if zh { "时间（UTC）" } else { "When (UTC)" },
        "wh.th.object" => if zh { "对象" } else { "Object" },
        "wh.th.expires" => if zh { "过期时间（UTC）" } else { "Expires (UTC)" },
        "wh.th.left" => if zh { "剩余" } else { "Time left" },
        "wh.th.promote" => if zh { "提升为 artifact" } else { "Promote into artifacts/" },
        "wh.th.tool" => if zh { "工具" } else { "Tool" },
        "wh.th.does" => if zh { "作用" } else { "What it does" },
        "wh.th.args" => if zh { "参数（粗体为必填）" } else { "Arguments (bold is required)" },

        "wh.empty.nojobs" => if zh {
            "还没有任务。创建一个任务，会在集群上真正建出 inputs/、working/、artifacts/、report/ 四个目录并写入 manifest，agent 才有地方放东西。"
        } else {
            "No jobs yet. Creating one lays inputs/, working/, artifacts/ and report/ down on the cluster for real and writes a manifest, so an agent has somewhere to put its work."
        },
        "wh.empty.nolineage" => if zh {
            "还没有 artifact 被提升上来。把一个 working 文件 promote 之后，它会被复制进 artifacts/，同时把来源输入写进元数据 —— 这张表就是这么填起来的。"
        } else {
            "Nothing has been promoted yet. Promoting a working file copies it into artifacts/ and writes the inputs it came from into its metadata; that is what fills this table."
        },
        "wh.empty.noexpiry" => if zh {
            "现在没有 working 文件。任何写进 working/ 的东西都会由集群加上删除时间，然后带着确切时刻出现在这里。"
        } else {
            "There are no working files right now. Anything written into working/ is given a delete time by the cluster and appears here with the exact moment it goes."
        },
        "wh.empty.nopromote" => if zh {
            "没有可提升的内容：当前没有 working 文件。先通过 agent 端点或某个任务写入一个。"
        } else {
            "Nothing to promote: there are no working files. Write one through the agent endpoint first."
        },
        "wh.exp.intro" => if zh {
            "过期时间在写入时设置，并从存储对象上回读，所以这里显示的是集群的说法，不是本页面的一厢情愿。"
        } else {
            "Expiry is set on the write and read back off the stored object, so this is what the cluster says, not what this page hoped for."
        },
        "wh.exp.never" => if zh { "不过期" } else { "no expiry" },

        "wh.g.alt" => if zh {
            "血缘图：左边是输入，中间是任务，右边是它产出的东西。"
        } else {
            "Lineage graph: inputs on the left, the job in the middle, what it produced on the right."
        },
        "wh.g.cap" => if zh {
            "图上只画了最新的 {n} 个任务；下面的表格是全部。"
        } else {
            "The graph shows the {n} newest jobs; the table below has every one."
        },
        "wh.g.nogoal" => if zh { "未记录目标" } else { "no goal recorded" },
        "wh.g.noinputs" => if zh { "无输入" } else { "no inputs" },
        "wh.g.nooutputs" => if zh { "尚无产出" } else { "nothing produced yet" },
        "wh.g.more" => if zh { "另有 {n} 个" } else { "+{n} more" },
        "wh.g.persist" => if zh { "长期保留" } else { "kept" },
        "wh.g.expires" => if zh { "{in}后消失" } else { "goes in {in}" },
        "wh.g.overdue" => if zh { "已过期" } else { "past its expiry" },
        "wh.g.noexp" => if zh { "无过期时间" } else { "no expiry" },
        "wh.g.ref" => if zh { "输入" } else { "input" },
        "wh.g.gone" => if zh { "输入，已不存在" } else { "input, now missing" },
        "wh.g.l.input" => if zh { "输入" } else { "input" },
        "wh.g.l.job" => if zh { "任务" } else { "job" },
        "wh.g.l.art" => if zh { "产出" } else { "artifact" },
        "wh.g.l.work" => if zh { "中间文件" } else { "working" },

        "wh.lin.none" => if zh { "未记录输入" } else { "no inputs recorded" },
        "wh.lin.live" => if zh { "仍在" } else { "present" },
        "wh.lin.gone" => if zh { "已消失" } else { "gone" },

        "wh.act.goal" => if zh { "这个任务要做什么？" } else { "What is this job for?" },
        "wh.act.goalp" => if zh { "按地区汇总昨天的订单" } else { "aggregate yesterday's orders by region" },
        "wh.act.agent" => if zh { "执行方" } else { "Run by" },
        "wh.act.ttl" => if zh { "working 文件多久后过期" } else { "Working files expire after" },
        "wh.act.create" => if zh { "创建任务" } else { "Create the job" },
        "wh.act.promote" => if zh { "提升" } else { "Promote" },
        "wh.act.dest" => if zh { "artifacts/ 下的名称" } else { "Name under artifacts/" },
        "wh.act.promotehint" => if zh {
            "提升在集群内部完成复制，去掉过期时间，并把输入来源重新写到副本上。"
        } else {
            "Promoting copies the file inside the cluster, drops its expiry, and re-states its inputs on the copy."
        },
        "wh.msg.done" => if zh { "已完成" } else { "Done" },
        "wh.msg.failed" => if zh { "操作没有成功" } else { "That did not work" },

        "wh.mcp.intro" => if zh {
            "把 agent 指向这个端点，它就能发现数据集、读懂一个对象是什么、检索元数据、不下载整份文件就取样，并把结果写回某个任务。"
        } else {
            "Point an agent at this endpoint and it can find datasets, read what an object is, search metadata, sample a file without downloading it, and write results back into a job."
        },
        "wh.mcp.endpoint" => if zh { "端点" } else { "Endpoint" },
        "wh.mcp.protocol" => if zh { "协议" } else { "Protocol" },
        "wh.mcp.auth" => if zh { "鉴权" } else { "Authentication" },
        "wh.mcp.authv" => if zh {
            "使用控制台的会话 cookie。agent 和人用同一种方式登录，没有单独的 agent 凭据。"
        } else {
            "The console session cookie. An agent signs in the same way a person does; there is no separate agent credential."
        },
        "wh.mcp.impl" => if zh { "已实现" } else { "Implemented" },
        "wh.mcp.notimpl" => if zh { "未实现" } else { "Not implemented" },
        "wh.mcp.notimplv" => if zh {
            "resources、prompts、sampling、logging、流式响应、批量请求均未实现。一次 POST 只处理一个 JSON 对象。"
        } else {
            "resources, prompts, sampling, logging, streamed responses, batched requests. One POST carries one JSON object."
        },
        "wh.mcp.instructions" => if zh {
            "所有写入都落在某个任务里。先用 job_create 建任务，用 result_write 把中间结果写进 working/（会自动过期），值得留下的再用 artifact_publish 发布，发布时会记录它的输入来源。"
        } else {
            "Every write lands inside a job. Create one with job_create, put intermediate results into working/ with result_write (they expire on their own), and publish the ones worth keeping with artifact_publish, which records the inputs they came from."
        },

        "wh.t.datasets" => if zh {
            "列出本工作区的数据集及其对象数和大小；可选地一并列出 warehouse 任务和各自的产出。"
        } else {
            "List the datasets in this workspace with object counts and size; optionally include warehouse jobs and what each produced."
        },
        "wh.t.describe" => if zh {
            "描述单个对象：大小、类型、ETag、自定义元数据、已记录的血缘，以及从开头几 KiB 推断出的列名或字段名。"
        } else {
            "Describe one object: size, type, ETag, custom metadata, recorded lineage, and a column or key list read from the first few KiB."
        },
        "wh.t.search" => if zh {
            "在整个工作区里按名称、类型、大小和自定义元数据检索对象，复用控制台已有的索引。"
        } else {
            "Search objects by name, type, size and custom metadata across the workspace, using the index the console already maintains."
        },
        "wh.t.sample" => if zh {
            "只读取对象开头的若干字节，不拉取整个文件。"
        } else {
            "Read the leading bytes of an object without fetching the whole thing."
        },
        "wh.t.job" => if zh {
            "创建一个任务：在集群上真正建出四个目录、写入 manifest，并可选地把输入文件放进 inputs/。"
        } else {
            "Create a job: four real directories on the cluster, a manifest, and optional input files staged into inputs/."
        },
        "wh.t.result" => if zh {
            "把中间结果写进 working/，由集群负责到期删除，同时记录它是从哪些输入推导出来的。"
        } else {
            "Write an intermediate result into working/ with an expiry the cluster enforces, recording which inputs it was derived from."
        },
        "wh.t.publish" => if zh {
            "把一个 working 文件提升成 artifacts/ 下的正式产出，血缘一并带过去，也可以单独给它设置存活时间。"
        } else {
            "Promote a working file into artifacts/ with its lineage intact, optionally with a TTL of its own."
        },

        // ---- Chaos Arcade: the experiment and its report ----
        "chaos.f.drop_copy" => if zh { "删掉一份副本" } else { "Drop one copy" },
        "chaos.f.corrupt_copy" => if zh { "改坏一份副本" } else { "Corrupt one copy" },
        "chaos.f.drop_durable" => if zh { "去掉 durability marker" } else { "Strip the durability marker" },
        "chaos.f.stale_timestamp" => if zh { "把副本改成旧时间戳" } else { "Restamp a copy into the past" },

        "chaos.u.replica" => if zh { "副本" } else { "replicas" },
        "chaos.u.fragment" => if zh { "分片" } else { "fragments" },
        "chaos.yes" => if zh { "能" } else { "yes" },
        "chaos.no" => if zh { "不能" } else { "no" },
        "chaos.right" => if zh { "猜对" } else { "right" },
        "chaos.wrong" => if zh { "猜错" } else { "wrong" },
        "chaos.unknown" => if zh { "未测量" } else { "not measured" },
        "chaos.by.replicator" => if zh { "replicator" } else { "the replicator" },
        "chaos.by.reconstructor" => if zh { "reconstructor" } else { "the reconstructor" },
        "chaos.by.none" => if zh { "没有守护进程会修" } else { "nobody — it stays broken" },
        "chaos.by.unknown" => if zh { "无法归因" } else { "not attributed" },
        "chaos.pol.replicated" => if zh { "多副本" } else { "replicated" },

        "chaos.armed" => if zh {
            "故障注入已启用，沙箱根目录 {root}，每个故障都带 {ttl} 秒 TTL；控制台即使崩溃，扫描器也会自动回滚。"
        } else {
            "Fault injection is armed. Sandbox root {root}; every fault carries a {ttl} s TTL, so \
             the sweeper reverts it even if this console dies mid-experiment."
        },
        "chaos.busy" => if zh {
            "已有一个实验在跑。同一时刻只允许一个，否则两份故障会互相解释不清。"
        } else {
            "An experiment is already running. Only one at a time — two faults at once and neither \
             result explains anything."
        },
        "chaos.recover" => if zh { "立刻回滚全部故障" } else { "Undo every fault now" },
        "chaos.recoverh" => if zh {
            "不等 TTL，直接把本工具还欠着的所有 undo 都执行一遍。"
        } else {
            "Run every undo this tool still owes, without waiting for the TTL."
        },
        "chaos.live" => if zh { "实验进行中：{step}。" } else { "Experiment in flight: {step}." },
        "chaos.live.noscript" => if zh {
            "（没有开脚本，页面不会自动更新，点上面的链接刷新。）"
        } else {
            "(With scripting off this page will not update itself; use the link above.)"
        },

        "chaos.form.h" => if zh { "先下判断，再放故障" } else { "Call it first, then break it" },
        "chaos.form.intro" => if zh {
            "预测在故障落地之前就被记下来，事后改不了——这份工具的价值就在于你和集群不一致的那一行。"
        } else {
            "The prediction is recorded before the fault lands and cannot be revised afterwards. The \
             line where you and the cluster disagree is the whole point."
        },
        "chaos.form.predh" => if zh { "你的预测" } else { "Your prediction" },
        "chaos.form.fault" => if zh { "故障" } else { "Fault" },
        "chaos.form.policy" => if zh { "存储策略" } else { "Storage policy" },
        "chaos.form.readable" => if zh { "对象还读得出来吗" } else { "Will it still read" },
        "chaos.form.by" => if zh { "谁来修" } else { "Who repairs it" },
        "chaos.form.secs" => if zh { "多少秒收敛" } else { "Converges in (s)" },
        "chaos.form.deadline" => if zh { "等多久放弃" } else { "Give up after" },
        "chaos.form.secs_n" => if zh { "{n} 秒" } else { "{n} s" },
        "chaos.form.submit" => if zh { "注入故障并开始观察" } else { "Inject the fault and watch" },
        "chaos.form.drillonly" => if zh { "只做安全演练（不动任何数据）" } else { "Safety drill only (touches nothing)" },

        "chaos.empty.h" => if zh { "还没有跑过实验" } else { "No experiment has been run yet" },
        "chaos.empty.p" => if zh {
            "上面的表单选一个故障、填上你的预测再提交，这里就会出现一份完整报告：结论、评分、带真实时间戳的时间轴、故障前中后的每盘副本清单，以及哪个守护进程真正干了活的 pass 行证据。"
        } else {
            "Pick a fault above, record what you think will happen, and submit. This space then \
             carries the full report: the verdict, the score, a timeline with real timestamps, the \
             per-device copy census before, during and after, and the pass line that proves which \
             daemon did the repair."
        },
        "chaos.empty.census" => if zh {
            "这一刻集群里没有任何一块盘持有该对象——不是没采集到，是确实没有。"
        } else {
            "No disk in the cluster held this object at that instant. That is a measurement, not a \
             missing one."
        },
        "chaos.empty.pass" => if zh {
            "观察窗口内没有读到任何 replicator / reconstructor 的 pass 行。可能是这段时间刚好没有 pass 结束，也可能是日志没送达——两种情况都还没有定论。"
        } else {
            "No replicator or reconstructor pass line was read inside the window. Either no pass \
             finished in that time or the log did not reach here; neither is settled."
        },
        "chaos.empty.drill" => if zh {
            "这次没有跑安全演练，所以本页无法证明防护生效。"
        } else {
            "The safety drill did not run, so this page cannot prove the guard held."
        },

        "chaos.v.repaired" => if zh {
            "故障后 {secs} 秒恢复到 {copies}/{wanted} 份{unit}，是 {who} 修的。"
        } else {
            "Back to {copies} of {wanted} {unit} {secs} s after the fault — {who} did it."
        },
        "chaos.v.repaired_un" => if zh {
            "故障后 {secs} 秒恢复到 {copies}/{wanted} 份{unit}，但窗口内没有任何 pass 行能证明是谁修的。"
        } else {
            "Back to {copies} of {wanted} {unit} {secs} s after the fault, but no pass line in the \
             window proves which daemon did it."
        },
        "chaos.v.stuck" => if zh {
            "等了 {secs} 秒仍然只有 {left}/{wanted} 份{unit}，没有任何进程去补——再坏 {spare} 份这个对象就没了。"
        } else {
            "Still {left} of {wanted} {unit} after {secs} s and nothing rebuilt the missing one — \
             lose {spare} more and this object is gone."
        },
        "chaos.v.dark" => if zh {
            "对象读不出来了（HTTP {status}）：只剩 {left} 份{unit}，这个策略至少要 {need} 份才能服务读请求。"
        } else {
            "The object stopped reading (HTTP {status}): {left} {unit} left, and this policy needs \
             {need} to serve a read at all."
        },
        "chaos.v.failed" => if zh { "实验没能跑完，集群未被改动。" } else { "The experiment did not run, and the cluster was not changed." },
        "chaos.v.running" => if zh { "实验进行中，结论还没有出来。" } else { "The experiment is still running; there is no verdict yet." },
        "chaos.v.drill" => if zh {
            "安全演练：{n}/{m} 次越界尝试被拒绝，没有任何数据被改动。"
        } else {
            "Safety drill: {n} of {m} out-of-bounds attempts were refused, and nothing was touched."
        },

        "chaos.d.running" => if zh {
            "每 5 秒轮询一次：客户端读一次、每个节点的盘点一次、再收一次守护进程的 pass 行。"
        } else {
            "Polling every 5 s: one client read, one directory listing per node, and whatever the \
             daemons have logged since."
        },
        "chaos.d.drillwhy" => if zh {
            "拒绝的理由逐字来自 check_target 本身，不是页面上另写的一句话。"
        } else {
            "Each refusal is quoted verbatim from check_target itself, not re-worded for the page."
        },
        "chaos.d.reads" => if zh {
            "整个窗口里客户端读了 {n} 次，其中 {ok} 次返回 200 且 {size} 的 md5 与写入时一致。"
        } else {
            "The client read {n} times across the window; {ok} of those returned 200 with the {size} \
             checksum matching what was written."
        },
        "chaos.d.margin" => if zh {
            "结束时 primary 上有 {left}/{wanted} 份{unit}，该策略服务一次读最少需要 {need} 份。"
        } else {
            "{left} of {wanted} {unit} sat on primaries at the end; this policy needs {need} to serve \
             one read."
        },
        "chaos.d.attributed" => if zh {
            "归因证据：{node} 的 {who} 在 {at} 记下 suffix_syncs={syncs} reverts={reverts}，是窗口内唯一一条非零 pass。"
        } else {
            "Attribution rests on one line: {who} on {node} logged suffix_syncs={syncs} \
             reverts={reverts} at {at}, the only non-zero pass in the window."
        },
        "chaos.d.unattributed" => if zh {
            "副本确实回来了，但窗口内没有任何一条 pass 行显示做过工作，所以这里不写是谁修的——按策略去猜等于伪造证据。"
        } else {
            "The copy did come back, but no pass line in the window reported any work, so this report \
             names no daemon. Guessing the one the policy implies would be inventing evidence."
        },
        "chaos.d.silent" => if zh {
            "窗口内读到 {passes} 条 pass 行，来自 {nodes} 个节点，全部 suffix_syncs=0 reverts=0：这段时间里没有任何守护进程报告自己干过活。"
        } else {
            "{passes} pass lines were read from {nodes} nodes inside the window, every one of them \
             suffix_syncs=0 reverts=0: no daemon in this cluster reported doing any work at all."
        },
        "chaos.d.nomark" => if zh {
            "{node}/{device} 上这个 partition 的 invalid 后缀表是空的：直接删文件不会让 suffix hash 失效，replicator 比对时两边看起来一样，于是 {suffix} 永远不会被同步回来。"
        } else {
            "The partition's invalid-suffix list on {node}/{device} is empty. Removing a file behind \
             the daemon's back does not invalidate the suffix hash, so both sides still look equal \
             and suffix {suffix} is never synced back."
        },
        "chaos.d.noauditor" => if zh {
            "全部节点都没有跑 object auditor（systemd 报 {state}），所以没有任何进程会主动扫盘发现副本丢失或损坏。"
        } else {
            "No node runs an object auditor (systemd reports {state}), so nothing scans the disks to \
             discover a copy that is missing or wrong."
        },

        "chaos.v.scrubbed" => if zh {
            "被改坏的字节在故障后 {secs} 秒被换回了正确内容，那份{unit}重新可信。"
        } else {
            "The damaged bytes were replaced with the right ones {secs} s after the fault; that copy \
             can be trusted again."
        },
        "chaos.v.rotten" => if zh {
            "等了 {secs} 秒，被改坏的那份还是坏的：{wanted} 份{unit}文件都在，其中一份内容是错的，谁也没发现。读请求还成功，只是因为代理这几次没挑到它。"
        } else {
            "Still damaged after {secs} s: all {wanted} {unit} are present and one of them holds the \
             wrong bytes, and nothing noticed. Reads keep succeeding only because the proxy has not \
             happened to pick it."
        },
        "chaos.d.censusblind" => if zh {
            "这个故障不改文件名也不改大小，所以下面三张盘点表完全一样，窗口内每一条 replicator pass 也都是 suffix_syncs=0。靠比对目录的机制看不见静默损坏，只有重新读回字节做校验才能。"
        } else {
            "This fault changes neither the filename nor the size, so the three censuses below are \
             identical and every replicator pass in the window still reported suffix_syncs=0. Nothing \
             that compares directories can see silent damage; only something that re-reads and \
             checksums the bytes can."
        },
        "chaos.d.digest" => if zh {
            "被改的那个文件自身的 md5：故障前 {before}，结束时 {after}。收敛与否是按这一对值判断的，不是按副本数。"
        } else {
            "The damaged file's own md5: {before} before the fault, {after} at the end. Convergence was \
             judged on that pair, not on a copy count."
        },
        "chaos.d.marked" => if zh {
            "故障落地时，{node}/{device} 上这个 partition 的 invalid 后缀表里已经有 {suffix}——对象刚写进去不久，本来就要重算。这是最容易被发现的情况。一个早已稳定下来的 partition 没有这个标记，同样的损坏可能要久得多才被注意到，也可能永远不会。"
        } else {
            "When the fault landed, {node}/{device} already carried suffix {suffix} on that partition's \
             invalid list, because the object had just been written and its hashes were due to be \
             recomputed anyway. That is the easy case. A partition that has long since settled carries \
             no such marker, so the same damage can take far longer to be noticed, or never be."
        },
        "chaos.rep.sub" => if zh {
            "{fault} · 策略 {policy} · {obj} · partition {part} · hash {hash}"
        } else {
            "{fault} · policy {policy} · {obj} · partition {part} · hash {hash}"
        },
        "chaos.rep.subdrill" => if zh { "只做演练 · 竞技场容器 {arena} · 未写入任何数据" } else { "Drill only · arena container {arena} · nothing was written" },
        "chaos.rep.meta" => if zh { "开始 {start} · 结束 {end} · 实验号 {id}" } else { "started {start} · ended {end} · run {id}" },
        "chaos.rep.score" => if zh { "预测 vs 集群" } else { "Prediction against the cluster" },
        "chaos.rep.tally" => if zh { "项预测猜对" } else { "calls right" },
        "chaos.rep.timeline" => if zh { "逐秒发生了什么" } else { "What happened, second by second" },
        "chaos.rep.timelinep" => if zh {
            "每个节点一条轨道：实线表示这一刻该节点持有当前版本的副本，红色断口表示没有。菱形是那台机器上真正做了工作的 pass。"
        } else {
            "One track per node: a solid segment means that node held a current copy at that poll, a \
             red gap means it did not. A diamond is a pass on that machine that actually did work."
        },
        "chaos.rep.census" => if zh { "每块盘上的副本清单" } else { "Copies, device by device" },
        "chaos.rep.censusp" => if zh {
            "三次盘点都取自同一个目录 {dir}，节点与设备名来自 ring，不是配置文件里的清单。"
        } else {
            "All three censuses list the same directory {dir}. Node and device names come from the \
             ring, not from a hand-maintained config list."
        },
        "chaos.rep.before" => if zh { "故障前" } else { "Before the fault" },
        "chaos.rep.worst" => if zh { "最少的一刻（故障后 {off} 秒）" } else { "At its worst ({off} s after the fault)" },
        "chaos.rep.after" => if zh { "实验结束时" } else { "At the end of the experiment" },
        "chaos.rep.daemon" => if zh { "到底是谁干的活" } else { "Which daemon actually did the work" },
        "chaos.rep.daemonp" => if zh {
            "pass 行是在一趟扫描结束时才写的，所以证明修复的那一行往往比副本回来还晚几十秒；本工具会在收敛后继续等，等不到就直说无法归因。"
        } else {
            "A pass line is written when the pass ends, so the line that proves a repair often lands \
             tens of seconds after the copy is already back. The runner keeps waiting for it, and if \
             it never comes it says so rather than naming a daemon."
        },
        "chaos.rep.auditor" => if zh { "谁在巡盘" } else { "Who is watching the disks" },
        "chaos.rep.auditorwhy" => if zh {
            "object auditor 是唯一会主动读盘、校验并隔离坏副本的进程。它不在，静默损坏就只能等下一次读请求撞上。"
        } else {
            "The object auditor is the only process that reads disks on its own, checksums what it \
             finds and quarantines what is wrong. Without it, silent damage waits for a read to hit it."
        },
        "chaos.rep.safety" => if zh { "防护是否真的生效" } else { "Whether the guard actually held" },
        "chaos.rep.unreachable" => if zh { "这次盘点里 {nodes} 没有应答，它们盘上有什么属于未知，不能当成空。" } else { "{nodes} did not answer this census. What those disks hold is unknown, which is not the same as empty." },
        "chaos.rep.board" => if zh { "历史战绩" } else { "Previous rounds" },
        "chaos.rep.boardp" => if zh { "本次控制台进程内保留的实验：一共猜对 {n}/{m} 项。" } else { "Experiments kept in this console process: {n} of {m} calls right overall." },

        "chaos.what.readable" => if zh { "还读得出来吗" } else { "Still readable" },
        "chaos.what.repaired_by" => if zh { "谁来修" } else { "Repaired by" },
        "chaos.what.converge" => if zh { "多久收敛" } else { "Convergence" },
        "chaos.cmp.predicted" => if zh { "你的预测" } else { "You said" },
        "chaos.cmp.actual" => if zh { "实测" } else { "Measured" },
        "chaos.cmp.never" => if zh { "{secs} 秒内没有收敛" } else { "never, within {secs} s" },
        "chaos.cmp.notconverged" => if zh { "没有收敛" } else { "did not converge" },

        "chaos.mark.seed" => if zh { "写入竞技场对象" } else { "arena object written" },
        "chaos.mark.fault" => if zh { "注入故障" } else { "fault applied" },
        "chaos.mark.gone" => if zh { "副本消失" } else { "copy gone" },
        "chaos.mark.back" => if zh { "副本回来" } else { "copy back" },
        "chaos.mark.read_ok" => if zh { "客户端读成功" } else { "client read ok" },
        "chaos.mark.read_bad" => if zh { "客户端读失败" } else { "client read failed" },
        "chaos.mark.converged" => if zh { "收敛" } else { "converged" },
        "chaos.mark.undo" => if zh { "回滚完成" } else { "fault undone" },
        "chaos.mark.other" => if zh { "其他" } else { "other" },

        "chaos.lane.client" => if zh { "客户端" } else { "client" },
        "chaos.lane.copies" => if zh { "副本数" } else { "copies" },
        "chaos.lane.wanted" => if zh { "份为满" } else { "wanted" },

        // The English terms stay in the Chinese strings because that is what
        // operators here say out loud; only the surrounding word is translated.
        "chaos.role.primary" => if zh { "主位 primary" } else { "primary" },
        "chaos.role.handoff" => if zh { "handoff 位" } else { "handoff" },
        "chaos.st.current" => if zh { "当前版本" } else { "current" },
        "chaos.st.stale" => if zh { "旧版本" } else { "older version" },
        "chaos.st.nondurable" => if zh { "缺 durability marker" } else { "not durable" },
        "chaos.st.handoff" => if zh { "handoff 上的遗留" } else { "left on a handoff" },
        "chaos.st.other" => if zh { "非数据文件" } else { "not a data file" },
        "chaos.pass.before" => if zh { "故障前" } else { "before" },
        "chaos.pass.after" => if zh { "故障后" } else { "after" },

        "chaos.col.role" => if zh { "角色" } else { "Role" },
        "chaos.col.node" => if zh { "节点" } else { "Node" },
        "chaos.col.device" => if zh { "设备" } else { "Device" },
        "chaos.col.file" => if zh { "文件" } else { "File" },
        "chaos.col.size" => if zh { "大小" } else { "Size" },
        "chaos.col.version" => if zh { "版本" } else { "Version" },
        "chaos.col.frag" => if zh { "分片" } else { "Fragment" },
        "chaos.col.state" => if zh { "状态" } else { "State" },
        "chaos.col.at" => if zh { "时刻" } else { "Clock" },
        "chaos.col.off" => if zh { "相对秒" } else { "T+" },
        "chaos.col.lane" => if zh { "在哪" } else { "Where" },
        "chaos.col.what" => if zh { "发生了什么" } else { "What" },
        "chaos.col.detail" => if zh { "细节" } else { "Detail" },
        "chaos.col.daemon" => if zh { "守护进程" } else { "Daemon" },
        "chaos.col.window" => if zh { "窗口" } else { "Window" },
        "chaos.col.question" => if zh { "问题" } else { "Question" },
        "chaos.col.predicted" => if zh { "你说" } else { "You said" },
        "chaos.col.actual" => if zh { "实际" } else { "Actually" },
        "chaos.col.verdict" => if zh { "结果" } else { "Call" },
        "chaos.col.rightof" => if zh { "猜对" } else { "Right" },
        "chaos.col.attempt" => if zh { "尝试破坏的目标" } else { "Attempted target" },
        "chaos.col.path" => if zh { "路径" } else { "Path" },
        "chaos.col.guard" => if zh { "防护" } else { "Guard" },
        "chaos.col.reason" => if zh { "拒绝理由（原文）" } else { "Reason, verbatim" },

        "chaos.drill.object" => if zh { "竞技场外的真实对象 {obj}" } else { "A real object outside the arena: {obj}" },
        "chaos.drill.conf" => if zh { "集群配置文件" } else { "A cluster config file" },
        "chaos.drill.traversal" => if zh { "带 .. 的路径穿越" } else { "A path traversal" },
        "chaos.drill.outside" => if zh { "竞技场外的真实对象" } else { "A real object outside the arena" },
        "chaos.drill.refused" => if zh { "已拒绝" } else { "refused" },
        "chaos.drill.allowed" => if zh { "放行了（这是缺陷）" } else { "ALLOWED — this is a defect" },
        "chaos.note.labroot" => if zh {
            "lab_root 是必要条件，但它不是真正的防线：集群里每一份副本都在同一个根目录下面，光比前缀等于放行所有人的数据。真正的防线是 check_target 会把路径里的 hash 目录和 ring 为竞技场对象算出的 hash 对齐，对不上就拒绝。下面这几行是本次实验开始前，拿集群里真实存在的别人的副本试出来的。"
        } else {
            "lab_root is necessary and nowhere near sufficient: every replica in the cluster lives \
             under that same root, so a prefix check alone would authorise deleting anyone's data. \
             The real guard is that check_target matches the hash directory in the path against the \
             hash the ring computes for the arena object. The rows below were produced before this \
             experiment, against a real copy of somebody else's object."
        },
        "chaos.undo.node" => if zh { "回滚在哪台机器执行" } else { "Undo runs on" },
        "chaos.undo.ttl" => if zh { "TTL（到点自动回滚）" } else { "TTL before auto-undo" },
        "chaos.undo.script" => if zh { "回滚脚本（注入之前就写好了）" } else { "Undo script, written before the fault" },
        "chaos.undo.state" => if zh { "回滚状态" } else { "Undo state" },
        "chaos.undo.done" => if zh { "已执行，集群已复原" } else { "done — the cluster is back as it was" },
        "chaos.undo.pending" => if zh { "尚未确认，等 TTL 扫描器兜底" } else { "not confirmed; the TTL sweeper is the backstop" },

        // ---- Lab reports: RingScope / Policy Economist / Object Capsule /
        // Tombstone Museum. Every sentence these four render goes through here,
        // so a Chinese console never wraps an English report.  [lab-reports]

        "rsx.summary" => if zh {
            "{policy} · {kind} · {parts} 个 partition（part power {pp}）· ring 版本 {ver}"
        } else {
            "{policy} · {kind} · {parts} partitions (part power {pp}) · ring version {ver}"
        },
        "rsx.summary.bare" => if zh {
            "{policy} —— 无法读取 ring"
        } else {
            "{policy} — the ring could not be read"
        },
        "rsx.kind.repl" => if zh { "{n} 副本" } else { "{n}× replication" },
        "rsx.kind.ec" => if zh { "EC 纠删码 {k}+{m}" } else { "erasure coded {k}+{m}" },
        "rsx.f.change" => if zh { "变更类型" } else { "Change" },
        "rsx.f.target" => if zh { "目标" } else { "Target" },
        "rsx.f.value" => if zh { "参数" } else { "Value" },
        "rsx.f.nochange" => if zh { "—— 不添加变更 ——" } else { "— no change —" },
        "rsx.f.notarget" => if zh { "—— 选择磁盘或 zone ——" } else { "— pick a disk or a zone —" },
        "rsx.f.zoneopt" => if zh { "整个 zone {zone}" } else { "whole zone {zone}" },
        "rsx.f.placeholder" => if zh {
            "权重，或 region,zone,ip,device,weight"
        } else {
            "weight, or region,zone,ip,device,weight"
        },
        "rsx.f.hint" => if zh {
            "整个场景都写在地址栏里，这个页面可以原样贴进工单。"
        } else {
            "The whole scenario is in the address bar, so this page can be pasted into a ticket exactly as it stands."
        },
        "rsx.staged.none" => if zh {
            "暂无变更 —— 显示 ring 的当前状态"
        } else {
            "no changes — showing the ring as it stands"
        },
        "rsx.staged.n" => if zh { "已暂存 {n} 项变更" } else { "staged: {n}" },
        "rsx.chip.remove" => if zh { "移除这项变更" } else { "Remove this change" },
        "rsx.chip.fail_node" => if zh { "让 {node} 下线" } else { "take {node} offline" },
        "rsx.chip.fail_device" => if zh { "拔掉 {dev}" } else { "pull {dev}" },
        "rsx.chip.remove_device" => if zh { "永久退役 {dev}" } else { "retire {dev}" },
        "rsx.chip.fail_zone" => if zh { "失去 zone {zone}" } else { "lose zone {zone}" },
        "rsx.chip.set_weight" => if zh { "{dev} 权重改为 {w}" } else { "weight {dev} → {w}" },
        "rsx.chip.add_device" => if zh { "在 {zone} 增加 {dev}" } else { "add {dev} in {zone}" },
        "rsx.v.lost.h" => if zh {
            "{total} 个 partition 中将有 {n} 个没有任何可读副本"
        } else {
            "{n} of {total} partitions would have no readable copy left"
        },
        "rsx.v.lost.d" => if zh {
            "占整个 ring 的 {pct}。落在这些 partition 上的对象读取会直接失败：存活副本少于读取所需的 {min} 份，集群里也没有任何东西能重建它们。不要执行这项变更。"
        } else {
            "That is {pct} of the ring. A read of any object in those partitions fails outright: fewer than the {min} copies a read needs survive, and nothing on this cluster can rebuild them. Do not apply this change."
        },
        "rsx.v.noquorum.h" => if zh {
            "{total} 个 partition 中将有 {n} 个无法写入"
        } else {
            "Writes stop for {n} of {total} partitions"
        },
        "rsx.v.noquorum.d" => if zh {
            "读取仍然正常，但一次写入需要 {q} 个副本槽接受，而 {n} 个 partition 已经凑不齐。客户端看到的现象是 PUT 失败而 GET 全部成功 —— 这种形态最容易被误判成客户端的问题。"
        } else {
            "Reads still work, but a write needs {q} replica slots to accept it and {n} partitions no longer have that many. Clients see PUT fail while every GET keeps succeeding, which is the shape that gets misdiagnosed as a client problem."
        },
        "rsx.v.degraded.h" => if zh {
            "{total} 个 partition 中将有 {n} 个低于完整冗余"
        } else {
            "{n} of {total} partitions would run below full redundancy"
        },
        "rsx.v.degraded.d" => if zh {
            "对象仍然可读可写 —— 最差的 partition 仍有 {min} 份 —— 但在复制追平之前已经没有余量。请把这次变更安排在没有其他故障的时间窗口。"
        } else {
            "Every object stays readable and writable — the worst partition still holds {min} copies — but the margin is gone until replication catches up. Schedule this for a window with nothing else failing."
        },
        "rsx.v.churn.h" => if zh {
            "这项变更会迁移 {slots} 个副本槽中的 {moved} 个 —— 占 ring 的 {pct}，而实际只需要 {need} 个"
        } else {
            "This change moves {moved} of {slots} replica slots — {pct} of the ring, where {need} would have sufficed"
        },
        "rsx.v.move.h" => if zh {
            "这项变更会迁移 {slots} 个副本槽中的 {moved} 个（{pct}），接近必须迁移的 {need} 个"
        } else {
            "This change moves {moved} of {slots} replica slots ({pct}), close to the {need} it has to"
        },
        "rsx.v.move.d" => if zh {
            "即通过复制网络传输 {bytes}，而下限是 {floorbytes} —— 是布局真正强制迁移量的 {x} 倍。变更完成后集群可容忍 {tol} 个节点故障。"
        } else {
            "That is {bytes} across the replication network against a floor of {floorbytes} — {x}× the traffic the placement actually forces. After the change the cluster tolerates losing {tol} nodes."
        },
        "rsx.v.nomove.h" => if zh { "这项变更不会迁移任何数据" } else { "This change moves nothing" },
        "rsx.v.nomove.d" => if zh {
            "ring 已经处于该场景描述的状态，没有 partition 易主，也没有数据跨网络传输。"
        } else {
            "The ring is already in the state this scenario describes, so no partition changes hands and no bytes cross the network."
        },
        "rsx.v.overlap.h" => if zh {
            "{total} 个 partition 中有 {n} 个把两份副本放在同一个 zone"
        } else {
            "{n} of {total} partitions keep two replicas in one zone"
        },
        "rsx.v.overlap.d" => if zh {
            "一旦失去那个 zone，这些 partition 会一次丢两份而不是一份，集群的实际容错能力低于副本数看起来的样子。这是当前 ring 本身的属性，与上面暂存的变更无关。"
        } else {
            "Losing that zone costs those partitions two copies at once rather than one, so the cluster tolerates less than its replica count suggests. This is a property of the ring as it stands, not of anything staged above."
        },
        "rsx.v.base.h" => if zh {
            "当前 ring 可以在丢失 {tol} 个节点的情况下，保持全部 {total} 个 partition 可读"
        } else {
            "The ring as it stands survives losing {tol} nodes with all {total} partitions still readable"
        },
        "rsx.v.base.d" => if zh {
            "没有任何设备偏离其权重应得份额超过 {bal}，zone 容错为 {zl}，最先耗尽的故障域是 {dom}。在上面暂存一项变更即可看到它的代价。"
        } else {
            "No device sits more than {bal} off the share its weight entitles it to, zone tolerance is {zl}, and the first failure domain to run out is the {dom}. Stage a change above to see what it would cost."
        },
        "rsx.tier.region" => if zh { "region 级" } else { "region" },
        "rsx.tier.zone" => if zh { "zone 级" } else { "zone" },
        "rsx.tier.node" => if zh { "节点级" } else { "node" },
        "rsx.tier.device" => if zh { "设备级" } else { "device" },
        "rsx.tier.unknown" => if zh { "未知故障域" } else { "unknown domain" },
        "rsx.card.readable" => if zh { "可读 partition" } else { "Readable" },
        "rsx.card.all" => if zh { "全部 {n} 个" } else { "all {n}" },
        "rsx.card.readable.ok" => if zh {
            "最差的 partition 仍有 {n} 份"
        } else {
            "worst partition still keeps {n} copies"
        },
        "rsx.card.readable.bad" => if zh {
            "{n} 个 partition 已无可读副本"
        } else {
            "{n} partitions have nothing left to read from"
        },
        "rsx.card.writable" => if zh { "可写 partition" } else { "Writable" },
        "rsx.card.writable.ok" => if zh {
            "各处都满足写入法定数 {q}"
        } else {
            "write quorum of {q} met everywhere"
        },
        "rsx.card.writable.bad" => if zh { "低于写入法定数 {q}" } else { "below the write quorum of {q}" },
        "rsx.card.slots" => if zh { "迁移副本槽" } else { "Replica slots moving" },
        "rsx.card.slots.n" => if zh {
            "占 ring 的 {pct} · 下限为 {need}"
        } else {
            "{pct} of the ring · floor is {need}"
        },
        "rsx.card.bytes" => if zh { "迁移数据量" } else { "Data to move" },
        "rsx.card.tolerance" => if zh { "容错能力" } else { "Failure tolerance" },
        "rsx.card.tolerance.v" => if zh { "{n} 个节点" } else { "{n} nodes" },
        "rsx.card.tolerance.n" => if zh {
            "zone 容错 {zb} → {za} · 受限于 {dom}"
        } else {
            "zones {zb} → {za} · limited by the {dom}"
        },
        "rsx.eta.rate" => if zh { "按当前 {r}/s 约需 {t}" } else { "about {t} at the current {r}/s" },
        "rsx.eta.idle" => if zh {
            "无法估算 —— 复制平面当前空闲"
        } else {
            "no estimate — the replication plane is idle"
        },
        "rsx.eta.none" => if zh { "没有数据需要迁移" } else { "nothing to move" },
        "rsx.dur.s" => if zh { "{n} 秒" } else { "{n} s" },
        "rsx.dur.m" => if zh { "{n} 分钟" } else { "{n} min" },
        "rsx.dur.h" => if zh { "{n} 小时" } else { "{n} h" },
        "rsx.map.title" => if zh { "Partition 分布图" } else { "Partition map" },
        "rsx.map.empty" => if zh {
            "模拟器没有返回逐 partition 的明细，因此画不出分布图。上面的统计仍然有效。"
        } else {
            "The simulator returned no per-partition detail, so there is nothing to map. The counts above still hold."
        },
        "rsx.map.k0" => if zh { "未变动" } else { "unchanged" },
        "rsx.map.k1" => if zh { "移动 1 个副本" } else { "one replica moved" },
        "rsx.map.k2" => if zh { "移动多个副本" } else { "several moved" },
        "rsx.map.k3" => if zh { "全部迁移" } else { "fully relocated" },
        "rsx.map.exact" => if zh {
            "每个方块代表 1 个 partition，共 {n} 个"
        } else {
            "one mark per partition, {n} in all"
        },
        "rsx.map.aggregated" => if zh {
            "每个方块代表 {n} 个 partition，显示其中最严重的状态"
        } else {
            "each mark covers {n} partitions and shows the worst state in the block"
        },
        "rsx.budget.title" => if zh { "迁移预算" } else { "Movement budget" },
        "rsx.budget.moved" => if zh { "迁移 {n} 个槽 · {b}" } else { "moving {n} slots · {b}" },
        "rsx.budget.total" => if zh { "ring 共 {n} 个副本槽" } else { "{n} replica slots in the ring" },
        "rsx.budget.floor" => if zh { "下限：{n} 个槽 · {b}" } else { "floor: {n} slots · {b}" },
        "rsx.zones.title" => if zh { "各 zone 的副本槽" } else { "Replica slots per zone" },
        "rsx.zones.ideal" => if zh { "权重应得的份额" } else { "the share the weights entitle it to" },
        "rsx.dev.title" => if zh { "设备" } else { "Devices" },
        "rsx.dev.note" => if zh {
            "变更前 → 变更后，对照各设备权重应得的份额"
        } else {
            "before → after, against the share each device's weight entitles it to"
        },
        "rsx.dev.nousage" => if zh { "未测得" } else { "not measured" },
        "rsx.dev.ok" => if zh { "在役" } else { "in service" },
        "rsx.dev.down" => if zh { "已下线" } else { "down" },
        "rsx.dev.removed" => if zh { "已退役" } else { "retired" },
        "rsx.dev.added" => if zh { "新增" } else { "new" },
        "rsx.dev.c.device" => if zh { "节点 / 设备" } else { "Node / device" },
        "rsx.dev.c.zone" => if zh { "所在 zone" } else { "Zone" },
        "rsx.dev.c.weight" => if zh { "权重" } else { "Weight" },
        "rsx.dev.c.ideal" => if zh { "理想值" } else { "Ideal" },
        "rsx.dev.c.before" => if zh { "变更前" } else { "Before" },
        "rsx.dev.c.after" => if zh { "变更后" } else { "After" },
        "rsx.dev.c.delta" => if zh { "增减" } else { "Change" },
        "rsx.dev.c.balance" => if zh { "偏差" } else { "Balance" },
        "rsx.dev.c.disk" => if zh { "磁盘用量" } else { "Disk in use" },
        "rsx.dev.c.state" => if zh { "状态" } else { "State" },
        "rsx.dev.chart.parts" => if zh { "副本槽（灰=变更前，色=变更后；竖线=理想值）" } else { "Replica slots (grey=before, color=after; tick=ideal)" },
        "rsx.dev.chart.meta" => if zh { "增减 · 偏差 · 磁盘 · 状态" } else { "Δ · balance · disk · state" },
        "rsx.flow.title" => if zh { "数据流向" } else { "Where the data goes" },
        "rsx.flow.note" => if zh {
            "共 {n} 对设备之间交换数据，按迁移量从大到小排列"
        } else {
            "{n} device pairs exchange data; the busiest are first"
        },
        "rsx.flow.hint" => if zh {
            "带宽表示迁移副本槽数量；悬停可看估计数据量。图中最多展示各端 16 台设备，完整列表见下方数据表。"
        } else {
            "Ribbon width is replica-slot count; hover for estimated bytes. Up to 16 endpoints per side; the full list is in the table below."
        },
        "rsx.flow.c.from" => if zh { "源设备" } else { "From" },
        "rsx.flow.c.to" => if zh { "目标设备" } else { "To" },
        "rsx.flow.c.slots" => if zh { "副本槽" } else { "Replica slots" },
        "rsx.flow.c.bytes" => if zh { "估计数据量" } else { "Estimated bytes" },
        "rsx.table.toggle" => if zh { "查看数据表" } else { "Show data table" },
        "rsx.part.title" => if zh { "查看单个 partition" } else { "Inspect one partition" },
        "rsx.part.label" => if zh { "Partition 号" } else { "Partition" },
        "rsx.part.go" => if zh { "查询" } else { "Look it up" },
        "rsx.part.empty" => if zh {
            "输入一个 partition 号，即可看到当前 ring 把它放在哪些设备上。上面的图是整个 ring，这里是其中一格。"
        } else {
            "Enter a partition number to see which devices the live ring puts it on. The map above is the whole ring; this is one square of it."
        },
        "rsx.part.cap" => if zh {
            "当前 ring 中的 partition {p}"
        } else {
            "Partition {p} in the live ring"
        },
        "rsx.part.none" => if zh {
            "ring 没有为 partition {p} 分配任何位置，这不应该发生；在相信本页其他内容之前，请先重新读取 ring。"
        } else {
            "The ring places partition {p} nowhere, which should not happen; re-read the ring before trusting anything else on this page."
        },
        "rsx.part.primary" => if zh { "主副本" } else { "primary" },
        "rsx.part.handoff" => if zh { "handoff 接管" } else { "handoff" },
        "rsx.part.c.role" => if zh { "角色" } else { "Role" },
        "rsx.part.c.node" => if zh { "节点" } else { "Node" },
        "rsx.part.c.device" => if zh { "设备" } else { "Device" },
        "rsx.method.title" => if zh { "这些数字是怎么来的" } else { "How these numbers were reached" },
        "rsx.method.slot" => if zh {
            "一个副本槽平均 {b}：集群已用 {used}，摊到 {slots} 个副本槽上。各 partition 并不完全等大，所以单条流向是近似值，总量不是。"
        } else {
            "One replica slot averages {b}: {used} in use across the cluster spread over {slots} slots. Partitions are not exactly equal, so a single flow is approximate; the totals are not."
        },
        "rsx.method.eta.rate" => if zh {
            "传输时间是按复制平面当前速率外推的。真实的 rebalance 受磁盘与链路限制，而不是取决于此刻的速率。"
        } else {
            "The transfer estimate extrapolates the replication plane's current rate. A real rebalance is limited by disks and links, not by what the plane happens to be doing now."
        },
        "rsx.method.eta.idle" => if zh {
            "这里不给出传输时间估计：复制平面当前空闲，用每秒几字节外推会得出以年计的结果。这是没有测到，而不是 rebalance 很快。"
        } else {
            "No transfer estimate is offered: the replication plane is idle, and extrapolating from a few bytes per second would give an answer in years. That is a measurement not taken, not a fast rebalance."
        },
        "rsx.method.eta.none" => if zh {
            "该场景不会迁移任何数据，因此没有传输时间可估。"
        } else {
            "Nothing moves under this scenario, so there is no transfer to estimate."
        },
        "rsx.method.sim" => if zh {
            "布局结果来自对 ring 文件副本运行真实的 ring builder。本页不做任何写入，也不会改动集群上的任何 ring。"
        } else {
            "Placement comes from the real ring builder, run against a copy of the ring file. Nothing on this page writes, and no ring on this cluster is touched."
        },
        "rsx.note.unfaithful" => if zh {
            "模拟器无法读取 ring 的原始分配，迁移量是对照它重新推导的基线计算的。方向可信，具体数值请视为近似。"
        } else {
            "The simulator could not read the ring's original assignment, so movement is measured against a baseline it re-derived. Treat the direction as sound and the exact counts as approximate."
        },
        "rsx.err.h" => if zh { "这个场景没有跑起来" } else { "This scenario did not run" },
        "rsx.err.d" => if zh {
            "没有任何东西被修改，也没有触碰任何 ring。下面的信息来自 ring 工具链；请修正上面的场景后重试。"
        } else {
            "Nothing was changed and no ring was touched. The message below comes from the ring tooling; correct the scenario above and run it again."
        },
        "rsx.err.nopolicies" => if zh {
            "没有配置任何存储策略"
        } else {
            "no storage policies are configured"
        },
        "rsx.err.dropped" => if zh {
            "地址栏里有 {n} 项暂存变更无法解析，已被忽略。"
        } else {
            "{n} staged changes in the address bar could not be read and were dropped."
        },
        "rsx.err.badop" => if zh {
            "这项变更缺少目标或参数，没有被暂存。"
        } else {
            "That change is missing a target or a value, so nothing was staged."
        },
        "rsx.err.toomany" => if zh {
            "一个场景最多包含 {n} 项变更；这一项没有被加入。"
        } else {
            "A scenario holds at most {n} changes; this one was not added."
        },

        "pol.label.repl" => if zh { "{n} 副本" } else { "{n}× replication" },
        "pol.cluster" => if zh {
            "本集群：{nodes} 个节点、{devices} 块设备分布在 {zones} 个 zone，单块 {dev}，裸容量合计 {cap}，当前已存逻辑数据 {stored}。"
        } else {
            "This cluster: {nodes} nodes, {devices} devices across {zones} zones, {dev} per device, {cap} raw in total, {stored} of logical data stored today."
        },
        "pol.cluster.unknown" => if zh {
            "本集群：{nodes} 个节点、{devices} 块设备分布在 {zones} 个 zone。没有设备回应容量探测，因此下面所有容量数字都来自你填写的输入，而不是实测。"
        } else {
            "This cluster: {nodes} nodes, {devices} devices across {zones} zones. No device answered a capacity probe, so every capacity figure below comes from what you type in rather than from measurement."
        },
        "pol.f.data" => if zh { "需要存储的数据量（TB）" } else { "Data to store (TB)" },
        "pol.f.cost" => if zh { "磁盘成本（每 TB·年）" } else { "Disk cost per TB-year" },
        "pol.f.bw" => if zh { "重建可用带宽（Gbps）" } else { "Rebuild bandwidth (Gbps)" },
        "pol.f.nines" => if zh { "耐久性目标（几个 9）" } else { "Durability target (nines)" },
        "pol.f.repair" => if zh { "修复必须在多少小时内完成" } else { "Repair must finish within (hours)" },
        "pol.f.loss" => if zh { "允许同时损失的设备数" } else { "Devices that may be lost" },
        "pol.f.years" => if zh { "规划年限（年）" } else { "Planning horizon (years)" },
        "pol.f.compare" => if zh { "重新计算" } else { "Recalculate" },
        "pol.rec.pick.h" => if zh {
            "建议采用 {name}：它满足你设定的全部目标，{years} 年成本 {cost} —— 是达标方案里最便宜的。"
        } else {
            "Use {name}: it clears every target you set and costs {cost} over {years} years — the cheapest that does."
        },
        "pol.rec.compromise.h" => if zh {
            "没有任何方案能满足全部目标。最接近的是 {name}，成本 {cost}，代价是放弃{miss}。"
        } else {
            "Nothing here clears every target. The closest is {name} at {cost}, and it gives up {miss}."
        },
        "pol.rec.none.h" => if zh {
            "没有任何候选方案能放进这个集群"
        } else {
            "No candidate scheme fits on this cluster"
        },
        "pol.rec.none.d" => if zh {
            "所有候选方案要求的独立故障域设备数，都超过本集群在 {zones} 个 zone 中的 {devices} 块设备。要么加硬件，要么接受分片数比这里更少的方案。"
        } else {
            "Every scheme offered needs more devices in distinct failure domains than the {devices} this cluster has across {zones} zones. Add hardware, or accept a scheme with fewer fragments than any listed here."
        },
        "pol.rec.why" => if zh {
            "{name} 的写入放大是 {amp} 倍，因此 {data} 逻辑数据需要 {raw} 裸容量。损失 {loss} 块设备后仍可读，模型给出 {nines} 个 9，更换一块设备需要读取 {repair}。"
        } else {
            "{name} writes {amp}× the data it stores, so {data} of logical data needs {raw} of raw disk. It keeps reading after {loss} devices are lost, models out at {nines} nines, and replacing one device reads for {repair}."
        },
        "pol.rec.nomargin" => if zh {
            "它的写入法定数是 {n} 中的 {q} —— 也就是全部分片 —— 因此只要有一个节点下线，写入就完全停止，尽管读取还在继续。"
        } else {
            "Its write quorum is {q} of {n} — every fragment — so one node down stops writes to it entirely, even while reads carry on."
        },
        "pol.rec.caveat" => if zh {
            "在本集群上还有一点需要注意：{why}。"
        } else {
            "One caveat on this cluster: {why}."
        },
        "pol.rec.runner.dearer" => if zh {
            "下一个选项是 {name}，要多花 {delta}；多花的钱买到的是 {margin} 的写入余量，以及容忍 {loss} 次损失。"
        } else {
            "{name} is the next option and costs {delta} more; what that buys is a write margin of {margin} and tolerance for {loss} losses."
        },
        "pol.rec.runner.cheaper" => if zh {
            "{name} 便宜 {delta}，但写入余量降到 {margin}，只能容忍 {loss} 次损失。"
        } else {
            "{name} is {delta} cheaper, but drops to a write margin of {margin} and tolerance for {loss} losses."
        },
        "pol.unmet.durability" => if zh { "耐久性目标" } else { "the durability target" },
        "pol.unmet.repair" => if zh { "修复时间上限" } else { "the repair-time limit" },
        "pol.unmet.loss" => if zh { "容错要求" } else { "the loss tolerance" },
        "pol.unmet.join" => if zh { "、" } else { " and " },
        "pol.chart.title" => if zh { "成本与耐久性" } else { "Cost against durability" },
        "pol.chart.axes" => if zh {
            "横轴是成本，纵轴是耐久性；圆点大小表示更换一块磁盘需要读取的数据量。"
        } else {
            "Money along the bottom, durability up the side; the size of each mark is how much one disk replacement has to read."
        },
        "pol.chart.target" => if zh { "目标 {n} 个 9" } else { "target {n} nines" },
        "pol.chart.nines" => if zh { "{n} 个 9" } else { "{n} nines" },
        "pol.chart.rebuild" => if zh { "重建读取 {v}" } else { "rebuild reads {v}" },
        "pol.chart.k.ok" => if zh { "满足全部目标" } else { "clears every target" },
        "pol.chart.k.miss" => if zh { "有目标未达成" } else { "misses a target" },
        "pol.chart.k.out" => if zh { "放不进本集群" } else { "does not fit here" },
        "pol.u.min" => if zh { "{n} 分钟" } else { "{n} min" },
        "pol.u.h" => if zh { "{n} 小时" } else { "{n} h" },
        "pol.u.d" => if zh { "{n} 天" } else { "{n} d" },
        "pol.u.inf" => if zh { "无法完成" } else { "never finishes" },
        "pol.repair.title" => if zh { "更换一块设备所需时间" } else { "Time to replace one device" },
        "pol.repair.limit" => if zh { "你设定的上限：{n}" } else { "your limit: {n}" },
        "pol.repair.note" => if zh {
            "纠删码重建一个分片要读取另外 k 个分片，所以再快的磁盘也救不了宽方案的修复速度。"
        } else {
            "Erasure coding rebuilds a fragment by reading k others, so a wide scheme heals slowly however fast the disks are."
        },
        "pol.table.title" => if zh { "全部候选方案对照" } else { "Every candidate, side by side" },
        "pol.table.metric" => if zh { "指标" } else { "Metric" },
        "pol.dir.higher" => if zh { "越高越好" } else { "higher is better" },
        "pol.dir.lower" => if zh { "越低越好" } else { "lower is better" },
        "pol.chart.infeasible" => if zh { "本集群不可行" } else { "infeasible here" },
        "pol.chart.pick" => if zh { "推荐" } else { "pick" },
        "pol.chart.best" => if zh { "可行方案中的最优值" } else { "best of the feasible candidates" },
        "pol.cons.title" => if zh { "是否满足设定约束" } else { "Meets the stated constraints" },
        "pol.m.amp" => if zh { "存储放大率" } else { "Storage amplification" },
        "pol.m.raw" => if zh { "所需裸容量" } else { "Raw capacity needed" },
        "pol.m.devices" => if zh { "最少设备数" } else { "Devices needed" },
        "pol.m.fanout" => if zh { "写入扇出" } else { "Write fanout" },
        "pol.m.quorum" => if zh { "写入法定数" } else { "Write quorum" },
        "pol.m.margin" => if zh { "写入余量" } else { "Write margin" },
        "pol.m.readmin" => if zh { "一次读取涉及的设备" } else { "Devices a read touches" },
        "pol.m.survives" => if zh { "可损失设备数" } else { "Devices it can lose" },
        "pol.m.rebuild" => if zh { "重建读取量" } else { "Rebuild reads" },
        "pol.m.repair" => if zh { "修复时间" } else { "Repair time" },
        "pol.m.nines" => if zh { "耐久性（几个 9）" } else { "Durability (nines)" },
        "pol.m.cost" => if zh { "规划期内磁盘成本" } else { "Disk cost over the horizon" },
        "pol.m.meets.dur" => if zh { "满足耐久目标" } else { "Meets durability" },
        "pol.m.meets.repair" => if zh { "满足修复时间" } else { "Meets repair time" },
        "pol.m.meets.loss" => if zh { "满足容错要求" } else { "Meets loss tolerance" },
        "pol.m.why" => if zh { "注意事项" } else { "Caveat" },
        "pol.yes" => if zh { "是" } else { "yes" },
        "pol.no" => if zh { "否" } else { "no" },
        "pol.why.none" => if zh { "无" } else { "none" },
        "pol.why.devices" => if zh {
            "需要 {need} 块分处不同故障域的设备，本集群只有 {have} 块"
        } else {
            "needs {need} devices in distinct failure domains; this cluster has {have}"
        },
        "pol.why.zones" => if zh {
            "分片数（{need}）多于 zone 数（{zones}），部分 zone 会放多个分片"
        } else {
            "more fragments ({need}) than zones ({zones}), so some zones hold several"
        },
        "pol.why.margin" => if zh {
            "写入法定数等于扇出 —— 一个节点下线就无法写入"
        } else {
            "write quorum equals the fanout — one node down stops writes"
        },
        "pol.method.title" => if zh {
            "这个模型知道什么、不知道什么"
        } else {
            "What this model does and does not know"
        },
        "pol.method.model" => if zh {
            "耐久性来自修复窗口模型：n 份副本中可以丢 f 份，且每一份都必须在重建上一份的窗口内失效。它用于横向比较方案，不是保证书。"
        } else {
            "Durability comes from a repair-window model: with n copies, f may be lost, and each must fail inside the window it takes to rebuild the previous one. It compares candidates; it is not a warranty."
        },
        "pol.method.afr" => if zh {
            "模型假设设备年化故障率 {afr}%，且填写带宽中有 {util}% 可用于重建流量。这两项都没有在本集群实测。"
        } else {
            "It assumes {afr}% annualised device failure and that {util}% of the stated bandwidth is available for rebuild traffic. Neither was measured on this cluster."
        },
        "pol.method.quorum" => if zh {
            "纠删码的写入法定数是 k 加上后端最少校验分片数，而不是 k。这正是 2+1 方案必须凑齐三个分片才能写入的原因。"
        } else {
            "Write quorum for erasure coding is k plus the backend's minimum parity, not k. That is why a 2+1 scheme needs all three fragments to accept a write."
        },
        "pol.method.unknown" => if zh {
            "相关性故障 —— 同一个机架、同一路供电、同一批坏固件 —— 才是通常真正搞垮集群的原因，而这个模型完全没有把它算进去。"
        } else {
            "Correlated failure — one rack, one power feed, one bad firmware batch — is usually what actually kills a cluster, and it is not in this model at all."
        },

        "cap.intro" => if zh {
            "一个对象究竟存在哪里、是否健康：容器使用的存储策略、该策略的 ring 把它放进哪个 partition、此刻每块磁盘上究竟有什么，以及集群是否还愿意把字节交回来。"
        } else {
            "Where one object actually lives and whether it is healthy: the container's storage policy, the partition that policy's ring puts it in, what is on each of those disks right now, and whether the cluster still hands the bytes back."
        },
        "cap.f.account" => if zh { "账户" } else { "Account" },
        "cap.f.container" => if zh { "容器" } else { "Container" },
        "cap.f.object" => if zh { "对象" } else { "Object" },
        "cap.f.open" => if zh { "打开胶囊" } else { "Open the capsule" },
        "cap.err.h" => if zh { "无法检查这个对象" } else { "This object could not be examined" },
        "cap.err.required" => if zh { "必须填写{what}" } else { "{what} is required" },
        "cap.err.toolong" => if zh { "{what}过长" } else { "{what} is too long" },
        "cap.err.control" => if zh {
            "{what}包含控制字符"
        } else {
            "{what} contains a control character"
        },
        "cap.err.slash" => if zh { "{what}不能包含斜杠" } else { "{what} cannot contain a slash" },
        "cap.err.otheraccount" => if zh {
            "当前会话登录的是 {mine}，无法读取 {other}。下面所有探测都以登录用户的身份执行，针对其他账户的报告只能靠猜。"
        } else {
            "This session is signed in to {mine} and cannot read {other}. Every probe below runs as the signed-in user, so a report about another account would be guesswork."
        },
        "cap.err.nocontainer" => if zh {
            "本账户下没有名为 {c} 的容器。"
        } else {
            "There is no container named {c} in this account."
        },
        "cap.err.container" => if zh {
            "无法读取容器（{s}），因此存储策略未知 —— 而之后的每一步都依赖这个策略。"
        } else {
            "The container could not be read ({s}), so the storage policy is unknown — and every step after it depends on the policy."
        },
        "cap.err.baddevice" => if zh {
            "ring 给出的设备名不符合安全要求，本工具拒绝把它拼进远程命令。"
        } else {
            "The ring named a device this tool refuses to put in a remote command."
        },
        "cap.err.noobject" => if zh {
            "{c} 中没有名为 {o} 的对象：集群返回 404，而且 ring 指定的 {n} 个位置里都没有文件。"
        } else {
            "There is no object named {o} in {c}: the cluster returns 404 and none of the {n} places the ring puts it holds a file."
        },
        "cap.src.container" => if zh { "读自容器本身" } else { "read from the container" },
        "cap.src.default" => if zh {
            "集群默认策略 —— 容器指定的策略本集群并不认识"
        } else {
            "the cluster default — the container named no policy this cluster knows"
        },
        "cap.read.refused" => if zh {
            "集群拒绝了这次读取（{s}）"
        } else {
            "the cluster refused the read ({s})"
        },
        "cap.read.broke" => if zh { "读到 {n} 时中断：{e}" } else { "the read broke off after {n}: {e}" },
        "cap.read.sampled" => if zh {
            "读到 {n} 时达到诊断上限而停止，因此没有校验 ETag"
        } else {
            "read {n} before stopping at the diagnostic's cap, so the ETag was not checked"
        },
        "cap.read.match" => if zh {
            "完整读取 {n}；字节与存储的 ETag 一致"
        } else {
            "read {n} in full; the bytes match the stored ETag"
        },
        "cap.read.mismatch" => if zh {
            "完整读取 {n}，但字节与存储的 ETag 不一致 —— 这个对象已经损坏"
        } else {
            "read {n} in full, but the bytes do NOT match the stored ETag — this object is corrupt"
        },
        "cap.read.noetag" => if zh {
            "完整读取 {n}；没有可用于比对的普通 ETag"
        } else {
            "read {n} in full; there is no plain ETag to check it against"
        },
        "cap.read.skipped" => if zh {
            "未执行 —— 集群表示这个对象不存在"
        } else {
            "not attempted — the cluster says this object does not exist"
        },
        "cap.v.unknown1" => if zh {
            "有 1 个位置无法读取，因此这个数字是下限，而不是全貌。"
        } else {
            "1 placement could not be read, so this count is a floor, not the whole story."
        },
        "cap.v.unknownN" => if zh {
            "有 {n} 个位置无法读取，因此这个数字是下限，而不是全貌。"
        } else {
            "{n} placements could not be read, so this count is a floor, not the whole story."
        },
        "cap.v.deleted.h" => if zh { "已删除" } else { "Deleted" },
        "cap.v.deleted.d" => if zh {
            "磁盘上只剩墓碑文件：这个对象已被删除，墓碑会保留到过期，因此不会因为某份副本回来而复活。这里没有任何东西可以恢复。"
        } else {
            "Every file on disk is a tombstone: this object was deleted, and the tombstones stay until they age out, so the delete cannot be undone by a replica coming back. Nothing here is recoverable."
        },
        "cap.v.gone.h" => if zh { "磁盘上什么都没有" } else { "Nothing on disk" },
        "cap.v.gone.d" => if zh {
            "没有任何位置持有这个对象的文件 —— 要么从未写入，要么每一份都已消失。读取会失败，集群上也没有任何可用于修复的来源。"
        } else {
            "No placement holds a file for this object — it was either never written or every copy is gone. A read will fail and there is nothing on this cluster to repair from."
        },
        "cap.v.ec.below.h" => if zh {
            "只有 {present} 个分片，而读取需要 {k} 个"
        } else {
            "{present} of the {k} fragments a read needs"
        },
        "cap.v.ec.below.d" => if zh {
            "低于读取门限。重建这个对象需要 {k} 个不同的分片，而现存只有 {present} 个（{idx}），因此读取会失败，也无法用剩下的分片重建。请从其他备份恢复。"
        } else {
            "Below the read threshold. Reconstructing this object takes {k} distinct fragments and only {present} exist ({idx}), so reads fail and no repair can rebuild it from what is left. Restore it from another copy."
        },
        "cap.v.ec.exact.h" => if zh {
            "{want} 个分片中只剩 {present} 个 —— 已无冗余"
        } else {
            "{present} of {want} fragments — no redundancy left"
        },
        "cap.v.ec.exact.d" => if zh {
            "对象仍然可读，但它现有的每个分片（{idx}）都已是承重件：再丢任意一个就会低于 {k} 个分片的读取门限，且无法重建。请在下一次故障之前，把缺失的 {gone} 个重建回来。"
        } else {
            "The object still reads, but every fragment it has ({idx}) is now load-bearing: lose any one of them and it drops below the {k}-fragment read threshold and cannot be rebuilt. Get the missing {gone} reconstructed before anything else fails."
        },
        "cap.v.ec.short.h" => if zh {
            "{want} 个分片中有 {present} 个"
        } else {
            "{present} of {want} fragments"
        },
        "cap.v.ec.short.d" => if zh {
            "可读且仍有余量 —— 现有 {present} 个分片（{idx}），读取门限是 {k} —— 但策略要求 {want} 个。reconstructor 应当补齐其余分片；如果数量迟迟不恢复，那是 reconstructor 的问题，而不是对象的问题。"
        } else {
            "Readable with redundancy to spare — {present} fragments present ({idx}) against a read threshold of {k} — but the policy wants {want}. The reconstructor should rebuild the rest; if the count does not recover, that is a reconstructor problem rather than an object problem."
        },
        "cap.v.ec.full.h" => if zh { "{want} 个分片齐全" } else { "All {want} fragments present" },
        "cap.v.ec.full.d" => if zh {
            "纠删码冗余完整：{want} 个不同分片（{idx}），读取门限 {k}，因此任意丢失 {m} 个它都还活着。"
        } else {
            "Full erasure-coded redundancy: {want} distinct fragments ({idx}) against a read threshold of {k}, so this object survives losing any {m} of them."
        },
        "cap.v.rep.full.h" => if zh { "{want} 份副本齐全" } else { "All {want} replicas present" },
        "cap.v.rep.full.d" => if zh {
            "ring 指派的每个节点都持有当前版本的完整副本，因此任意丢失 {n} 个它仍然安全。"
        } else {
            "Every node the ring assigns holds a full copy of the current version, so this object survives losing any {n} of them."
        },
        "cap.v.rep.one.h" => if zh {
            "{want} 份副本中只剩 1 份 —— 已无冗余"
        } else {
            "1 of {want} replicas — no redundancy left"
        },
        "cap.v.rep.one.d" => if zh {
            "对象仍然可读，但它只存在于一个地方。一次磁盘或节点故障就会彻底失去它。这本该由 replicator 处理；如果份数迟迟回不到 {want}，请先去查 replicator。"
        } else {
            "The object still reads, but it exists in exactly one place. One disk or node failure loses it outright. This is the replicator's job; if the count does not climb back to {want}, look at the replicator before anything else."
        },
        "cap.v.rep.short.h" => if zh {
            "{want} 份副本中有 {present} 份"
        } else {
            "{present} of {want} replicas"
        },
        "cap.v.rep.short.d" => if zh {
            "可读且仍有冗余，但少于策略要求的 {want} 份。replicator 应当补回缺失的 {gone} 份；如果它没有，那是 replicator 的问题，而不是对象的问题。"
        } else {
            "Readable and still redundant, but short of the {want} copies the policy asks for. The replicator should restore the missing {gone}; if it does not, that is a replicator problem rather than an object problem."
        },
        "cap.v.corrupt.h" => if zh {
            "返回的字节与存储的 ETag 不一致"
        } else {
            "The bytes served do not match the stored ETag"
        },
        "cap.v.corrupt.d" => if zh {
            "集群返回了 {n}，其摘要与写入时记录的并不相同。这个对象在原地被损坏了，在 auditor 检查过之前，下面列出的每一份都不可信。不要把这次读取当成好副本。"
        } else {
            "The cluster handed back {n} whose digest is not the one it recorded at write time. Something has corrupted this object in place, and every copy listed below is suspect until an auditor has been over them. Do not treat this read as a good copy."
        },
        "cap.v.service.h" => if zh {
            "数据在盘上，但集群对读取返回了 {status}"
        } else {
            "On disk, but the cluster answered the read with {status}"
        },
        "cap.v.service.d" => if zh {
            "盘上有 {present} {unit}，而读取只需要 {need}，也就是说提供这个对象所需的字节是存在的 —— 集群却仍然拒绝提供。因此这是服务故障而不是持久性故障：数据就在下面列出的节点上，出问题的是它们与客户端之间的某个环节。请从那里开始查，而不是去做恢复。"
        } else {
            "{present} {unit} are on disk and a read needs {need}, so the bytes to serve this object exist — and the cluster refused to serve them anyway. That makes this a service fault rather than a durability one: the data is on the nodes listed below and something between them and the client is failing. Start there, not with a restore."
        },
        "cap.unit.frag" => if zh { "个分片" } else { "fragments" },
        "cap.unit.rep" => if zh { "份副本" } else { "replicas" },
        "cap.k.durability" => if zh { "持久性 —— 磁盘上有什么" } else { "Durability — what the disks hold" },
        "cap.k.service" => if zh { "服务 —— 集群返回什么" } else { "Service — what the cluster returns" },
        "cap.svc.ok" => if zh { "{ms} 毫秒内返回 {n}" } else { "Served {n} in {ms} ms" },
        "cap.svc.bad" => if zh { "读取被拒绝，状态码 {s}" } else { "The read was refused with {s}" },
        "cap.svc.none" => if zh { "没有发起读取" } else { "No read was attempted" },
        "cap.card.policy" => if zh { "存储策略" } else { "Policy" },
        "cap.card.policy.n" => if zh { "策略 {i} · {src}" } else { "policy {i} · {src}" },
        "cap.card.partition" => if zh { "所在 partition" } else { "Partition" },
        "cap.card.partition.n" => if zh { "哈希 {h}" } else { "hash {h}" },
        "cap.card.frags" => if zh { "分片" } else { "Fragments" },
        "cap.card.reps" => if zh { "副本" } else { "Replicas" },
        "cap.card.nothing" => if zh { "磁盘上没有内容" } else { "nothing on disk" },
        "cap.card.version" => if zh { "盘上版本 {v}" } else { "on disk at version {v}" },
        "cap.card.readable" => if zh { "可读性" } else { "Readable" },
        "cap.card.readable.n" => if zh { "{ms} 毫秒内 {n}" } else { "{n} in {ms} ms" },
        "cap.card.leftovers" => if zh { "遗留副本" } else { "Leftovers" },
        "cap.card.leftovers.n" => if zh { "仍持有数据的 handoff" } else { "handoffs still holding data" },
        "cap.matrix.title" => if zh { "落点矩阵" } else { "Placement matrix" },
        "cap.matrix.note" => if zh {
            "ring 涉及的每个节点与设备各占一格。主副本那一行的空缺就是缺失的副本；handoff 上被填满的格子则是还没回家的副本。"
        } else {
            "One cell per node and device the ring touched. A gap in a primary's row is a missing copy; a filled cell on a handoff is a copy that has not gone home yet."
        },
        "cap.matrix.empty" => if zh {
            "ring 没有为这个对象返回任何落点，因此画不出矩阵。"
        } else {
            "The ring returned no placement for this object, so there is no matrix to draw."
        },
        "cap.matrix.primary" => if zh { "主副本" } else { "primary" },
        "cap.matrix.handoff" => if zh { "handoff 接管" } else { "handoff" },
        "cap.cell.current" => if zh { "当前版本" } else { "current" },
        "cap.cell.stale" => if zh { "旧版本" } else { "older version" },
        "cap.cell.tombstone" => if zh { "墓碑" } else { "tombstone" },
        "cap.cell.empty" => if zh { "空" } else { "empty" },
        "cap.cell.unknown" => if zh { "无响应" } else { "no answer" },
        "cap.policy.repl" => if zh { "{n} 副本" } else { "{n}× replication" },
        "cap.took" => if zh { "耗时 {ms} 毫秒采集" } else { "gathered in {ms} ms" },
        "cap.h.where" => if zh { "它存在哪里" } else { "Where it lives" },
        "cap.dirnote" => if zh {
            "每个落点都把这个对象放在 {dir}。"
        } else {
            "Every placement keeps this object at {dir}."
        },
        "cap.c.role" => if zh { "角色" } else { "Role" },
        "cap.c.node" => if zh { "节点" } else { "Node" },
        "cap.c.device" => if zh { "设备" } else { "Device" },
        "cap.c.zone" => if zh { "Zone 号" } else { "Zone" },
        "cap.c.file" => if zh { "文件" } else { "File" },
        "cap.c.size" => if zh { "大小" } else { "Size" },
        "cap.c.version" => if zh { "版本" } else { "Version" },
        "cap.c.fragment" => if zh { "分片" } else { "Fragment" },
        "cap.c.state" => if zh { "状态" } else { "State" },
        "cap.row.noanswer" => if zh { "无响应" } else { "no answer" },
        "cap.row.empty" => if zh { "空目录" } else { "empty" },
        "cap.st.current" => if zh { "当前版本" } else { "current" },
        "cap.st.stale" => if zh { "旧版本" } else { "older version" },
        "cap.st.leftover" => if zh { "遗留" } else { "leftover" },
        "cap.st.tombstone" => if zh { "墓碑" } else { "tombstone" },
        "cap.st.meta" => if zh { "元数据" } else { "metadata" },
        "cap.st.durable" => if zh { "提交标记" } else { "commit marker" },
        "cap.st.other" => if zh { "其他" } else { "other" },
        "cap.leftover1" => if zh {
            "下面有 1 个 handoff 仍持有这个对象的数据。当 primary 不可用时写入会落到 handoff；replicator 本应把它搬回 primary 再删除。数据还留在那里，说明这件事还没发生。"
        } else {
            "1 handoff below still holds data for this object. A handoff is where a write lands when a primary is unavailable; the replicator is supposed to move it back to the primary and remove it. Data sitting there means that has not happened yet."
        },
        "cap.leftoverN" => if zh {
            "下面有 {n} 个 handoff 仍持有这个对象的数据。当 primary 不可用时写入会落到 handoff；replicator 本应把它搬回 primary 再删除。数据还留在那里，说明这件事还没发生。"
        } else {
            "{n} handoffs below still hold data for this object. A handoff is where a write lands when a primary is unavailable; the replicator is supposed to move it back to the primary and remove it. Data sitting there means that has not happened yet."
        },
        "cap.stale1" => if zh {
            "有 1 个位置仍持有这个对象的旧版本。那些字节并不是 API 今天返回内容的副本。"
        } else {
            "1 placement still holds an older version of this object. Those bytes are not a copy of what the API serves today."
        },
        "cap.staleN" => if zh {
            "有 {n} 个位置仍持有这个对象的旧版本。那些字节并不是 API 今天返回内容的副本。"
        } else {
            "{n} placements still hold an older version of this object. Those bytes are not a copy of what the API serves today."
        },
        "cap.unreachable" => if zh {
            "有 {n} 个位置没有响应。它们持有什么是未知的，因此本页所有计数都是下限而非总数。"
        } else {
            "{n} placements did not answer. Whatever they hold is unknown, so every count on this page is a floor rather than a total."
        },
        "cap.h.meta" => if zh { "元数据" } else { "Metadata" },
        "cap.h.read" => if zh { "可读性检查" } else { "Readability" },
        "cap.meta.size" => if zh { "大小" } else { "Size" },
        "cap.meta.etag" => if zh { "ETag 摘要" } else { "ETag" },
        "cap.meta.type" => if zh { "类型" } else { "Type" },
        "cap.meta.modified" => if zh { "修改时间" } else { "Modified" },
        "cap.meta.version" => if zh { "版本" } else { "Version" },
        "cap.meta.custom" => if zh { "自定义" } else { "Custom" },
        "cap.meta.nocustom" => if zh { "无" } else { "none" },
        "cap.meta.request" => if zh { "请求" } else { "Request" },
        "cap.meta.badstatus" => if zh {
            "元数据请求返回 {s}"
        } else {
            "the metadata request returned {s}"
        },
        "cap.r.status" => if zh { "状态码" } else { "Status" },
        "cap.r.read" => if zh { "读取量" } else { "Read" },
        "cap.r.took" => if zh { "耗时" } else { "Took" },
        "cap.r.sampled" => if zh { "是否截断" } else { "Sampled" },
        "cap.r.sampled.yes" => if zh { "是 —— 在上限处停止" } else { "yes — stopped at the cap" },
        "cap.r.sampled.no" => if zh { "否 —— 完整读取" } else { "no — read in full" },
        "cap.r.etag.ok" => if zh { "与返回的字节一致" } else { "matches the bytes served" },
        "cap.r.etag.bad" => if zh { "与返回的字节不一致" } else { "DOES NOT match the bytes served" },
        "cap.r.etag.unchecked" => if zh { "未校验" } else { "not checked" },

        "tmb.intro" => if zh {
            "一个对象的一生一死，直接从磁盘上读回来：客户端要求了什么、每个节点实际什么时候拿到、现在还剩下什么。"
        } else {
            "An object's whole life and death, read back off the disks: what the client asked for, when each node actually got it, and what is still there."
        },
        "tmb.f.account" => if zh { "账户" } else { "Account" },
        "tmb.f.container" => if zh { "容器" } else { "Container" },
        "tmb.f.object" => if zh { "对象" } else { "Object" },
        "tmb.f.open" => if zh { "打开档案" } else { "Open the record" },
        "tmb.err.h" => if zh { "无法打开这份档案" } else { "This record could not be opened" },
        "tmb.err.required" => if zh {
            "账户、容器和对象都必须填写"
        } else {
            "account, container and object are all required"
        },
        "tmb.unit.frag" => if zh { "分片" } else { "fragment" },
        "tmb.unit.copy" => if zh { "副本" } else { "copy" },
        "tmb.a.incomplete.h" => if zh {
            "删除只到达了 {want} 份副本中的 {got} 份"
        } else {
            "The delete reached {got} of {want} copies"
        },
        "tmb.a.incomplete.d" => if zh {
            "{t} 的这次删除在 {where} 上没有留下墓碑。在墓碑落地之前，那份副本仍可能被返回给读取者，或者再次向外复制。"
        } else {
            "No tombstone for the delete at {t} on {where}. Until one lands there, that copy can be handed back to a reader or replicated outwards again."
        },
        "tmb.a.resurrection.h" => if zh {
            "存在一个比自己的墓碑还新的对象"
        } else {
            "An object exists that is newer than its own tombstone"
        },
        "tmb.a.resurrection.d" => if zh {
            "{del} 被删除，随后在 {wrote} 于 {where} 又被写入。要么是客户端删完又写，要么是某份陈旧副本带着被向前伪造的时钟回来了。"
        } else {
            "Deleted at {del}, then written again at {wrote} on {where}. Either the client wrote after deleting, or a stale copy came back with a forged-forward clock."
        },
        "tmb.a.lag.h" => if zh {
            "{node} 在写入 {dur}之后才拿到自己那份{unit}"
        } else {
            "{node} took its {unit} {dur} after the write"
        },
        "tmb.a.lag.d" => if zh {
            "客户端在 {wrote} 写入；{node}/{dev} 直到 {got} 才拿到文件。在这段空档里，集群持有的份数少于策略规定。"
        } else {
            "The client wrote at {wrote}; {node}/{dev} did not have the file until {got}. For that gap the cluster held fewer copies than the policy says."
        },
        "tmb.a.lag.rest" => if zh { "（共有 {n} 个文件迟到）" } else { "({n} files in all landed late)" },
        "tmb.a.offline.during.h" => if zh {
            "删除发生时 {node} 已经离线，并持续离线 {dur}"
        } else {
            "{node} was already offline when the delete happened, and stayed down for {dur}"
        },
        "tmb.a.offline.after.h" => if zh {
            "删除之后 {node} 离线了 {dur}"
        } else {
            "{node} was offline for {dur} after the delete"
        },
        "tmb.a.offline.d" => if zh {
            "离线时段 {from} 至 {to}。删除的时间戳是 {del}。"
        } else {
            "Down from {from} to {to}. The delete is timestamped {del}."
        },
        "tmb.a.offline.caught" => if zh {
            "墓碑最终还是送到了它那里 —— 复制把它追平了。"
        } else {
            "The tombstone did reach it — replication caught it up."
        },
        "tmb.a.offline.missed" => if zh {
            "它从未见过这次删除；它手上那份就是活过删除的那一份。"
        } else {
            "It never saw the delete; the copy it holds is the one that outlived it."
        },
        "tmb.a.handoff.ts.h" => if zh {
            "删除记录停在了一个本不该持有它的节点上"
        } else {
            "The delete is being held on a node that should not hold it"
        },
        "tmb.a.handoff.data.h" => if zh {
            "有一份副本停在了本不该持有它的节点上"
        } else {
            "A copy is parked on a node that should not hold it"
        },
        "tmb.a.handoff.d" => if zh {
            "{where} 不是这个对象的主副本节点。当主副本拒收时写入会落到 handoff，并一直停留到 replicator 能把它交回去为止。"
        } else {
            "{where} is not a primary for this object. A handoff is written when a primary refuses, and it stays there until the replicator can hand it back."
        },
        "tmb.a.handoff.tail.ts" => if zh {
            "当还有一个节点没收到删除时，删除看起来就是这个样子。"
        } else {
            "That is what a delete looks like while one node is still missing it."
        },
        "tmb.a.handoff.tail.plain" => if zh {
            "在那之前，它是一份 ring 并不知道的副本。"
        } else {
            "Until then it is a copy the ring does not know about."
        },
        "tmb.a.frag.h" => if zh {
            "{want} 个分片中现存 {got} 个"
        } else {
            "{got} of {want} fragments present"
        },
        "tmb.a.frag.d" => if zh {
            "策略要求 {k} 个数据分片和 {m} 个校验分片；磁盘上有 {got} 个不同的分片序号。"
        } else {
            "The policy stores {k} data and {m} parity fragments; {got} distinct indexes are on disk."
        },
        "tmb.a.frag.readable" => if zh {
            "对象仍然可读，但已经没有备用分片了。"
        } else {
            "The object still reads, but there is no spare left."
        },
        "tmb.a.frag.unreadable" => if zh {
            "低于数据分片数量，因此这个对象无法重建。"
        } else {
            "Below the data-fragment count, so the object cannot be rebuilt."
        },
        "tmb.a.under.h" => if zh {
            "{want} 份副本中现存 {got} 份"
        } else {
            "{got} of {want} copies present"
        },
        "tmb.a.under.d" => if zh {
            "写入于 {t}，目前磁盘上是 {where}。在 replicator 追平之前，再来一次故障的代价会超出策略的预算。"
        } else {
            "Written at {t}, and {where} on disk now. Until the replicator catches up, one more failure costs more than the policy budgeted for."
        },
        "tmb.state.present" => if zh { "仍然存在" } else { "Present" },
        "tmb.state.deleted_clean" => if zh { "已干净删除" } else { "Deleted, cleanly" },
        "tmb.state.deleted_incomplete" => if zh {
            "已删除，但并非每个位置"
        } else {
            "Deleted, but not everywhere"
        },
        "tmb.state.resurrected" => if zh { "删除后又复活" } else { "Resurrected after a delete" },
        "tmb.state.lost" => if zh { "磁盘上已无残留" } else { "Nothing left on disk" },
        "tmb.cod.clean" => if zh {
            "客户端在 {t} 发起 DELETE。全部 {n} 个主副本在 {spread} 内都收到了墓碑，磁盘上没有更新的数据文件。"
        } else {
            "A client DELETE at {t}. All {n} primaries took the tombstone within {spread}, and no newer data file remains on disk."
        },
        "tmb.cod.incomplete" => if zh {
            "客户端在 {t} 发起 DELETE，但只到达了 {want} 个主副本中的 {got} 个。{where} 仍持有数据，可能把它返回给读取者，或者再次向外复制。"
        } else {
            "A client DELETE at {t} reached only {got} of {want} primaries. {where} still holds data and can serve it to a reader or replicate it outwards again."
        },
        "tmb.cod.nowhere" => if zh { "没有任何位置" } else { "no placement" },
        "tmb.cod.resurrected" => if zh {
            "这个对象在 {t} 被删除，又在 {wrote} 被重新写入。新写入的时间戳比墓碑更新，因此读取者拿到的是删除之后的那份数据。"
        } else {
            "Deleted at {t}, then written again at {wrote}. The new write outranks the tombstone, so readers get the post-delete data."
        },
        "tmb.cod.lost" => if zh {
            "ring 指派的 {n} 个位置里没有任何一个持有文件，也没有墓碑。要么这个对象从未写入这里，要么删除已超过 reclaim_age、连墓碑都被回收了。"
        } else {
            "Not one of the {n} placements the ring assigns holds a file, and there is no tombstone. Either the object was never written here, or the delete is past reclaim_age and even its tombstones have been reclaimed."
        },
        "tmb.cod.alive" => if zh {
            "对象仍然存在：写入于 {t}，目前磁盘上有 {n} 份，没有记录到任何删除。"
        } else {
            "The object is present: written at {t}, {n} copies are on disk now, and no delete is recorded for it."
        },
        "tmb.cod.unknown" => if zh { "未知时间" } else { "an unknown time" },
        "tmb.dur.s" => if zh { "{n} 秒" } else { "{n} seconds" },
        "tmb.dur.m" => if zh { "{n} 分钟" } else { "{n} minutes" },
        "tmb.dur.h" => if zh { "{n} 小时" } else { "{n} hours" },
        "tmb.policy.ec" => if zh { "EC 纠删码 {k}+{m}" } else { "erasure coded {k}+{m}" },
        "tmb.policy.repl" => if zh { "{n} 份副本" } else { "{n} replicas" },
        "tmb.partline" => if zh { "partition {p} · 哈希 {h}" } else { "partition {p} · {h}" },
        "tmb.h.what" => if zh { "发生了什么" } else { "What happened" },
        "tmb.h.timeline" => if zh { "时间线（UTC）" } else { "Timeline (UTC)" },
        "tmb.h.ondisk" => if zh { "磁盘上的文件" } else { "On disk" },
        "tmb.h.offline" => if zh { "该时间窗内离线的节点" } else { "Nodes offline in this window" },
        "tmb.h.logs" => if zh { "服务日志" } else { "Service log" },
        "tmb.find.none" => if zh {
            "没有异常：ring 要求的每一份都在磁盘上、都准时到达，而且这个对象变化期间没有节点缺席。"
        } else {
            "Nothing anomalous: every copy the ring asks for is on disk, on time, and no node was missing while this object changed."
        },
        "tmb.files.none" => if zh {
            "任何节点的任何设备上都没有这个对象的文件。要么它从未写在这里，要么删除已超过 reclaim_age（本集群为 7 天）—— replicator 会在那之后清除墓碑本身，于是磁盘上什么都不剩。"
        } else {
            "No file for this object on any device of any node. Either it was never written here, or the delete is older than reclaim_age (7 days on this cluster) — past that the replicator removes the tombstones themselves, leaving nothing on disk."
        },
        "tmb.offline.none" => if zh {
            "在这个时间窗内所有节点都有响应 —— 没有节点缺席，也就没有因此错过的写入或删除。"
        } else {
            "Every node answered throughout this window — none was absent, so nothing was missed because of an outage."
        },
        "tmb.events.none" => if zh {
            "没有事件：磁盘上没有这个对象的任何内容。"
        } else {
            "No events: nothing for this object is on disk."
        },
        "tmb.logs.none" => if zh {
            "该时间窗内没有日志提到这个对象或它的 partition。日志后端只保留最近一段时间：对更早的写入或删除，这里查不到当时的记录。"
        } else {
            "No log lines named this object or its partition in this window. The log store keeps a limited history: for older writes or deletes the lines from that time are gone."
        },
        "tmb.logs.bypart" => if zh {
            "没有日志直接提到这个对象；下面这些提到了 partition {p}。"
        } else {
            "No line named the object itself; these mention partition {p}."
        },
        "tmb.unreachable" => if zh {
            "{n} 没有响应 —— 它持有什么是未知的，因此下面所有计数都是下限而非总数。"
        } else {
            "No answer from {n} — anything it holds is unknown, so every count below is a floor rather than a total."
        },
        "tmb.truncated" => if zh {
            "这个对象比可用性数据窗口更老，因此窗口之前的离线不会出现在这里。"
        } else {
            "This object is older than the availability window, so an outage before that window would not appear here."
        },
        "tmb.uncommitted" => if zh { "未提交" } else { "uncommitted" },
        "tmb.samesecond" => if zh { "同一秒内" } else { "same second" },
        "tmb.handoff" => if zh { "handoff 接管" } else { "handoff" },
        "tmb.k.data" => if zh { "数据" } else { "data" },
        "tmb.k.tombstone" => if zh { "墓碑" } else { "tombstone" },
        "tmb.k.meta" => if zh { "元数据" } else { "metadata" },
        "tmb.k.durable" => if zh { "提交标记" } else { "commit marker" },
        "tmb.ev.write" => if zh { "写入" } else { "write" },
        "tmb.ev.delete" => if zh { "删除" } else { "delete" },
        "tmb.ev.meta" => if zh { "元数据变更" } else { "metadata" },
        "tmb.lane.title" => if zh { "泳道图" } else { "Swimlane" },
        "tmb.lane.note" => if zh {
            "最上面一条是客户端的时钟；下面每条泳道是该节点实际拿到文件的时刻。上下两个标记之间的距离就是延迟。"
        } else {
            "The top lane is the client's clock; every lane below it is when that node actually had the file. The gap between a mark above and the same file below is the lag."
        },
        "tmb.lane.empty" => if zh {
            "没有可绘制的内容：这个对象在任何磁盘上都没有文件，因此每条泳道上都没有事件。"
        } else {
            "Nothing to draw: this object has no file on any disk, so there are no events on any lane."
        },
        "tmb.lane.client" => if zh { "客户端" } else { "client" },
        "tmb.lane.delete" => if zh { "删除" } else { "delete" },
        "tmb.lane.offline" => if zh {
            "{node} 离线 {from}–{to}"
        } else {
            "{node} offline {from}–{to}"
        },
        "tmb.lane.k.write" => if zh { "写入" } else { "write" },
        "tmb.lane.k.delete" => if zh { "删除" } else { "delete" },
        "tmb.lane.k.meta" => if zh { "元数据" } else { "metadata" },
        "tmb.lane.k.offline" => if zh { "节点离线" } else { "node offline" },
        "tmb.c.node" => if zh { "节点" } else { "Node" },
        "tmb.c.device" => if zh { "设备" } else { "Device" },
        "tmb.c.kind" => if zh { "类型" } else { "Kind" },
        "tmb.c.wrote" => if zh { "客户端写入" } else { "Client wrote" },
        "tmb.c.took" => if zh { "节点收到" } else { "Node took it" },
        "tmb.c.gap" => if zh { "延迟" } else { "Gap" },
        "tmb.c.size" => if zh { "大小" } else { "Size" },
        "tmb.c.fragment" => if zh { "分片" } else { "Fragment" },
        "tmb.c.from" => if zh { "起" } else { "From" },
        "tmb.c.to" => if zh { "止" } else { "To" },
        "tmb.c.downfor" => if zh { "离线时长" } else { "Down for" },
        "tmb.c.when" => if zh { "时间" } else { "When" },
        "tmb.c.lane" => if zh { "泳道" } else { "Lane" },
        "tmb.c.what" => if zh { "内容" } else { "What" },
        "tmb.c.service" => if zh { "服务" } else { "Service" },
        "tmb.c.line" => if zh { "日志行" } else { "Line" },

        // ---- shared ----
        "common.cancel" => if zh { "取消" } else { "Cancel" },
        "common.save" => if zh { "保存" } else { "Save" },
        "common.delete" => if zh { "删除" } else { "Delete" },
        "common.refresh" => if zh { "刷新" } else { "Refresh" },
        "common.error" => if zh { "出错了" } else { "Something went wrong" },
        "common.back" => if zh { "返回文件" } else { "Back to Files" },
        "common.none" => if zh { "无" } else { "none" },
        "common.close" => if zh { "关闭" } else { "Close" },
        "common.copy" => if zh { "复制" } else { "Copy" },
        "common.edit" => if zh { "编辑" } else { "Edit" },
        "common.remove" => if zh { "移除" } else { "Remove" },
        "common.savechanges" => if zh { "保存更改" } else { "Save changes" },

        // ---- monitor ----
        "mon.title" => if zh { "监控" } else { "Monitor" },
        "mon.range15" => if zh { "最近 15 分钟" } else { "Last 15m" },
        "mon.range1h" => if zh { "最近 1 小时" } else { "Last 1h" },
        "mon.range6h" => if zh { "最近 6 小时" } else { "Last 6h" },
        "mon.range24h" => if zh { "最近 24 小时" } else { "Last 24h" },
        "mon.rangelabel" => if zh { "时间范围" } else { "Time range" },
        // Dashboard and panel titles are served as data to the browser, so they
        // are keyed here and resolved before they leave the server.
        "mon.d.overview" => if zh { "集群总览" } else { "Cluster overview" },
        "mon.d.nodes" => if zh { "存储节点" } else { "Storage nodes" },
        "mon.d.replication" => if zh { "副本复制" } else { "Replication" },
        "mon.d.logs" => if zh { "日志" } else { "Logs" },
        "mon.p.nodes_up" => if zh { "在线节点" } else { "Nodes up" },
        "mon.p.reqs" => if zh { "请求数 / 秒" } else { "Requests / s" },
        "mon.p.err5xx" => if zh { "5xx 比例" } else { "5xx ratio" },
        "mon.p.p99" => if zh { "P99 延迟" } else { "P99 latency" },
        "mon.p.reqs_method" => if zh { "各方法请求数 / 秒" } else { "Requests / s by method" },
        "mon.p.latency" => if zh { "代理延迟分位数" } else { "Proxy latency quantiles" },
        "mon.p.err_ratio" => if zh { "错误比例" } else { "Error ratio" },
        "mon.p.fs_used" => if zh { "文件系统使用率" } else { "Filesystem used" },
        "mon.p.cpu" => if zh { "各节点 CPU 使用率" } else { "CPU utilisation per node" },
        "mon.p.net_storage" => if zh { "存储平面吞吐" } else { "Storage plane throughput" },
        "mon.p.net_repl" => if zh { "复制平面吞吐" } else { "Replication plane throughput" },
        "mon.p.net_public" => if zh { "客户端平面吞吐" } else { "Client plane throughput" },
        "mon.p.load" => if zh { "负载均值（1 分钟）" } else { "Load average (1m)" },
        "mon.p.repl_kind" => if zh { "各类复制活动" } else { "Replicator activity by kind" },
        "mon.p.repl_sf" => if zh { "成功与失败" } else { "Successes vs failures" },
        "mon.p.repl_fail_node" => if zh { "各节点复制失败数" } else { "Replication failures per node" },
        "mon.p.log_vol" => if zh { "各服务日志量" } else { "Log volume by unit" },
        "mon.p.log_err" => if zh { "最近的错误" } else { "Recent errors" },
        "mon.d.backends" => if zh { "后端服务" } else { "Backend services" },
        "mon.d.storage" => if zh { "磁盘与设备" } else { "Disks & devices" },
        "mon.d.services" => if zh { "服务健康" } else { "Service health" },
        "mon.d.node" => if zh { "节点详情" } else { "Node detail" },
        "mon.p.reqs_status" => if zh { "各状态码请求数 / 秒" } else { "Requests / s by status class" },
        "mon.p.backend_reqs" => if zh { "各后端请求数 / 秒" } else { "Backend requests / s by service" },
        "mon.p.backend_p99" => if zh { "各服务 P99 延迟" } else { "P99 latency by service" },
        "mon.p.backend_err" => if zh { "各服务 5xx / 秒" } else { "5xx / s by service" },
        "mon.p.backend_status" => if zh { "后端各状态码请求数 / 秒" } else { "Backend requests / s by status class" },
        "mon.p.mem" => if zh { "各节点内存使用率" } else { "Memory used per node" },
        "mon.p.dev_used" => if zh { "各盘容量使用率" } else { "Device capacity used" },
        "mon.p.dev_inodes" => if zh { "各盘 inode 使用率" } else { "Device inodes used" },
        "mon.p.disk_read" => if zh { "磁盘读吞吐" } else { "Disk read throughput" },
        "mon.p.disk_write" => if zh { "磁盘写吞吐" } else { "Disk write throughput" },
        "mon.p.disk_iops" => if zh { "磁盘 IOPS" } else { "Disk IOPS" },
        "mon.p.disk_util" => if zh { "磁盘繁忙度" } else { "Disk busy" },
        "mon.p.repl_node" => if zh { "各节点复制活动" } else { "Replicator activity per node" },
        "mon.p.svc_grid" => if zh { "各节点服务状态" } else { "Service state per node" },
        "mon.p.svc_events" => if zh { "服务启停事件" } else { "Service start/stop events" },
        "mon.range7d" => if zh { "最近 7 天" } else { "Last 7d" },
        "mon.allnodes" => if zh { "全部节点" } else { "All nodes" },
        "mon.back" => if zh { "返回总览" } else { "Back to overview" },
        "chaos.pc.size" => if zh { "点的大小 = 同步 + 回收的活动量" } else { "Mark size = suffix syncs + reverts" },
        "chaos.pc.worked" => if zh { "带圈的点 = 完成修复的那次 pass" } else { "Ringed mark = the pass that did the repair" },
        "chaos.pc.fail" => if zh { "橙色点 = 该次 pass 有失败" } else { "Amber mark = the pass logged failures" },
        "chaos.pc.base" => if zh { "空心点 = 故障前的基线 pass" } else { "Hollow mark = baseline pass before the fault" },
        "chaos.pc.table" => if zh { "查看数据表" } else { "Data table" },

        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn hdr(cookie: Option<&str>, accept: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(c) = cookie {
            h.insert(axum::http::header::COOKIE, HeaderValue::from_str(c).unwrap());
        }
        if let Some(a) = accept {
            h.insert(
                axum::http::header::ACCEPT_LANGUAGE,
                HeaderValue::from_str(a).unwrap(),
            );
        }
        h
    }

    #[test]
    fn cookie_wins_over_browser_preference() {
        assert_eq!(lang(&hdr(Some("sc_lang=en"), Some("zh-CN,zh;q=0.9"))), "en");
        assert_eq!(lang(&hdr(Some("sc_lang=zh"), Some("en-US"))), "zh");
    }

    #[test]
    fn falls_back_to_the_browser_then_english() {
        assert_eq!(lang(&hdr(None, Some("zh-CN,zh;q=0.9"))), "zh");
        assert_eq!(lang(&hdr(None, Some("en-GB,en;q=0.9"))), "en");
        assert_eq!(lang(&hdr(None, None)), "en");
    }

    /// Every key the console renders. A key added to a page but forgotten here
    /// is the failure this list exists to catch, so it is exhaustive on
    /// purpose rather than a sample.
    const SHIPPED: &[&str] = &[
        "chaos.v.repaired_un",
        "chaos.v.scrubbed", "chaos.v.rotten", "chaos.d.censusblind",
        "chaos.d.digest", "chaos.d.marked",
        "nav.files", "nav.deploy", "nav.monitor", "nav.lab", "nav.test",
        "shell.signout", "shell.signedin", "shell.cluster", "shell.language",
        "theme.label", "theme.light", "theme.dark",
            "lab.soon", "lab.notbuilt", "chaos.disarmed",
            "chaos.q.drop_copy", "chaos.q.corrupt_copy",
            "chaos.q.drop_durable", "chaos.q.stale_timestamp",
            "lab.tool.policy.title", "lab.tool.policy.blurb",
            "lab.tool.capsule.title", "lab.tool.capsule.blurb",
            "lab.tool.tombstone.title", "lab.tool.tombstone.blurb",
            "lab.tool.shadow.title", "lab.tool.shadow.blurb",
            "lab.tool.chaos.title", "lab.tool.chaos.blurb",
            "lab.tool.warehouse.title", "lab.tool.warehouse.blurb",
            "lab.tool.debt.title", "lab.tool.debt.blurb",
            "debt.proxy_note", "debt.k.debt", "debt.k.interest", "debt.k.tti",
            "debt.tti.none", "debt.tti.insolvent", "debt.h.top", "debt.h.bars",
            "debt.h.feed", "debt.c.backlog", "debt.c.balance", "debt.c.disk",
            "debt.c.failures", "debt.c.unhealthy",
        "chaos.armed", "chaos.busy", "chaos.by.none", "chaos.by.reconstructor",
        "chaos.by.replicator", "chaos.by.unknown", "chaos.cmp.actual",
        "chaos.cmp.never", "chaos.cmp.notconverged", "chaos.cmp.predicted",
        "chaos.col.actual", "chaos.col.at", "chaos.col.attempt",
        "chaos.col.daemon", "chaos.col.detail", "chaos.col.device",
        "chaos.col.file", "chaos.col.frag", "chaos.col.guard", "chaos.col.lane",
        "chaos.col.node", "chaos.col.off", "chaos.col.path", "chaos.col.predicted",
        "chaos.col.question", "chaos.col.reason", "chaos.col.rightof",
        "chaos.col.role", "chaos.col.size", "chaos.col.state", "chaos.col.verdict",
        "chaos.col.version", "chaos.col.what", "chaos.col.window",
        "chaos.d.attributed", "chaos.d.drillwhy", "chaos.d.margin",
        "chaos.d.noauditor", "chaos.d.nomark", "chaos.d.reads", "chaos.d.running",
        "chaos.d.silent", "chaos.d.unattributed", "chaos.drill.allowed",
        "chaos.drill.conf", "chaos.drill.object", "chaos.drill.outside",
        "chaos.drill.refused", "chaos.drill.traversal", "chaos.empty.census",
        "chaos.empty.drill", "chaos.empty.h", "chaos.empty.p", "chaos.empty.pass",
        "chaos.f.corrupt_copy", "chaos.f.drop_copy", "chaos.f.drop_durable",
        "chaos.f.stale_timestamp", "chaos.form.by", "chaos.form.deadline",
        "chaos.form.drillonly", "chaos.form.fault", "chaos.form.h",
        "chaos.form.intro", "chaos.form.policy", "chaos.form.predh",
        "chaos.form.readable", "chaos.form.secs", "chaos.form.secs_n",
        "chaos.form.submit", "chaos.lane.client", "chaos.lane.copies",
        "chaos.lane.wanted", "chaos.live", "chaos.live.noscript",
        "chaos.mark.back", "chaos.mark.converged", "chaos.mark.fault",
        "chaos.mark.gone", "chaos.mark.other", "chaos.mark.read_bad",
        "chaos.mark.read_ok", "chaos.mark.seed", "chaos.mark.undo", "chaos.no",
        "chaos.note.labroot", "chaos.pass.after", "chaos.pass.before",
        "chaos.pol.replicated", "chaos.recover", "chaos.recoverh",
        "chaos.rep.after", "chaos.rep.auditor", "chaos.rep.auditorwhy",
        "chaos.rep.before", "chaos.rep.board", "chaos.rep.boardp",
        "chaos.rep.census", "chaos.rep.censusp", "chaos.rep.daemon",
        "chaos.pc.size", "chaos.pc.worked", "chaos.pc.fail", "chaos.pc.base", "chaos.pc.table",
        "chaos.rep.daemonp", "chaos.rep.meta", "chaos.rep.safety",
        "chaos.rep.score", "chaos.rep.sub", "chaos.rep.subdrill",
        "chaos.rep.tally", "chaos.rep.timeline", "chaos.rep.timelinep",
        "chaos.rep.unreachable", "chaos.rep.worst", "chaos.right",
        "chaos.role.handoff", "chaos.role.primary", "chaos.st.current",
        "chaos.st.handoff", "chaos.st.nondurable", "chaos.st.other",
        "chaos.st.stale", "chaos.u.fragment", "chaos.u.replica", "chaos.undo.done",
        "chaos.undo.node", "chaos.undo.pending", "chaos.undo.script",
        "chaos.undo.state", "chaos.undo.ttl", "chaos.unknown", "chaos.v.dark",
        "chaos.v.drill", "chaos.v.failed", "chaos.v.repaired", "chaos.v.running",
        "chaos.v.stuck", "chaos.what.converge", "chaos.what.readable",
        "chaos.what.repaired_by", "chaos.wrong", "chaos.yes",
        "login.tenant", "login.user", "login.key", "login.submit", "login.title",
        "login.note", "login.bad", "login.failed",
        "files.title", "files.newbucket", "files.buckets", "files.bucket",
        "files.objects", "files.size", "files.nobuckets", "files.search",
        "files.trash", "files.account", "files.users", "files.noquota",
        "files.used", "files.name", "files.type", "files.modified",
        "files.folder", "files.system", "files.stat", "files.quota",
        "files.nobucketshint", "files.namehint", "files.createbucket",
        "files.bucketsettings", "files.deletebucket", "files.filter",
        "files.pager.range", "files.pager.per", "files.pager.prev",
        "files.pager.next", "files.pager.page",
        "files.settings", "files.upload", "files.zip", "files.ziptitle",
        "files.emptyfolder", "files.trunc", "files.dlzip", "files.trashfolder",
        "files.delfolder", "files.details", "files.download", "files.share",
        "files.trashobj", "files.newfolder", "files.foldername",
        "files.createfolder", "files.uploadfiles", "files.uploadhint",
        "files.startupload", "files.object", "files.contenttype",
        "files.mimetype", "files.metadata", "files.addrow", "files.expiry",
        "files.deleteat", "files.clearexpiry", "files.expiryhint",
        "files.publiclink", "files.danger", "files.delsegments",
        "files.delperm", "files.templink", "files.validfor", "files.hour1",
        "files.day1", "files.day7", "files.custom", "files.seconds",
        "files.genlink", "files.linkhint", "files.publichint", "files.access",
        "files.private", "files.publicread", "files.aclhint", "files.readacl",
        "files.writeacl", "files.quotasec", "files.maxbytes",
        "files.maxobjects", "files.emptynone", "files.trashnote",
        "files.emptytrash", "files.trashempty", "files.restore",
        "files.restoreall", "files.deleteall", "files.item", "files.deleted",
        "files.items",
        "acct.stat", "acct.quota", "acct.quotabytes", "acct.savequota",
        "acct.quotahint", "acct.tempkey", "acct.keyset", "acct.keynone",
        "acct.newkey", "acct.keyrandom", "acct.setkey", "acct.defexp",
        "acct.savedefault", "acct.keyhint", "acct.meta", "acct.savemeta",
        "acct.nometa", "acct.users", "acct.noaccounts", "acct.usershint",
        "acct.ratelimits", "acct.ratehint",
        "users.add", "users.edit", "users.intro", "users.rostererr",
        "users.none", "users.noaccess", "users.tenant", "users.user", "users.roles",
        "users.groups", "users.reseller", "users.admin", "users.member",
        "users.key", "users.keyph", "users.keyhint", "users.adminrole",
        "users.resellerrole", "users.groupsfld", "users.save", "users.busy",
        "search.allcontainers", "search.deep", "search.reindex",
        "search.indexed", "search.deepnote", "search.truncnote",
        "search.noindex", "search.name", "search.container", "search.ctype",
        "search.metakey", "search.metaval", "search.minsize", "search.maxsize",
        "lab.title", "lab.intro", "lab.soon", "lab.reachable", "lab.slowest",
        "lab.nonodes", "lab.noanswer",
        "ring.title", "policy.title", "ring.simulate", "ring.reset", "ring.rebalance",
        "ring.policy", "ring.scenario", "ring.nochanges", "ring.reading",
        "ring.simulating", "ring.add", "ring.op.fail_node",
        "ring.op.fail_device", "ring.op.fail_zone", "ring.op.remove_device",
        "ring.op.set_weight", "ring.op.add_device",
        "test.title", "test.intro", "test.run", "test.stop", "test.running",
        "test.size", "test.op", "test.workers", "test.duration", "test.read",
        "test.write", "test.mixed", "test.results", "test.noruns",
        "test.table", "test.chart", "test.export", "test.throughput",
        "test.bandwidth", "test.latency", "test.errors", "test.started",
        "test.ops", "test.busy",
        "common.cancel", "common.save", "common.delete", "common.refresh",
        "common.error", "common.back", "common.none", "common.close",
        "common.copy", "common.edit", "common.remove", "common.savechanges",
        "mon.title", "mon.range15", "mon.range1h", "mon.range6h",
        "mon.range24h", "mon.range7d", "mon.rangelabel", "mon.allnodes", "mon.back",
        "mon.d.overview", "mon.d.nodes", "mon.d.replication", "mon.d.logs",
        "mon.d.backends", "mon.d.storage", "mon.d.services", "mon.d.node",
        "mon.p.nodes_up", "mon.p.reqs", "mon.p.err5xx", "mon.p.p99",
        "mon.p.reqs_method", "mon.p.latency", "mon.p.err_ratio", "mon.p.reqs_status",
        "mon.p.backend_reqs", "mon.p.backend_p99", "mon.p.backend_err", "mon.p.backend_status",
        "mon.p.fs_used", "mon.p.cpu", "mon.p.mem", "mon.p.net_storage", "mon.p.net_repl",
        "mon.p.net_public", "mon.p.load", "mon.p.repl_kind", "mon.p.repl_sf",
        "mon.p.repl_fail_node", "mon.p.repl_node", "mon.p.log_vol", "mon.p.log_err",
        "mon.p.dev_used", "mon.p.dev_inodes", "mon.p.disk_read", "mon.p.disk_write",
        "mon.p.disk_iops", "mon.p.disk_util", "mon.p.svc_grid", "mon.p.svc_events",
        // ---- API Parity ----
        "shadow.intro", "shadow.cap.parity.t", "shadow.cap.parity.d",
        "shadow.cap.compat.t", "shadow.cap.compat.d", "shadow.cap.response.t", "shadow.cap.response.d",
        "shadow.act.capture", "shadow.act.replay", "shadow.act.mutate", "shadow.act.mutate_seed",
        "shadow.why.crange", "shadow.noise.rangeonly",
        "shadow.why.replayacct", "shadow.why.clen", "shadow.noise.listingonly",
        "shadow.h.limits", "shadow.limits.d", "shadow.limits.case",
        "shadow.limits.order", "shadow.limits.dup", "shadow.limits.body",
        "shadow.limits.window", "shadow.limits.scope",
        "shadow.act.hint", "shadow.empty.h", "shadow.empty.d",
        "shadow.mode.single", "shadow.mode.dual", "shadow.mode.single.h",
        "shadow.mode.single.d", "shadow.mode.dual.h", "shadow.verdict.single",
        "shadow.verdict.clean", "shadow.verdict.diff", "shadow.denom.single",
        "shadow.denom.dual", "shadow.olderrun", "shadow.h.matrix",
        "shadow.h.surface", "shadow.h.findings", "shadow.h.cases",
        "shadow.h.replay", "shadow.h.noise", "shadow.h.corpus",
        "shadow.class.identical", "shadow.class.cosmetic", "shadow.class.semantic",
        "shadow.class.breaking", "shadow.class.unpaired", "shadow.fam.listing",
        "shadow.fam.meta", "shadow.fam.etag", "shadow.fam.range",
        "shadow.fam.error", "shadow.fam.convergence", "shadow.famd.listing",
        "shadow.famd.meta", "shadow.famd.etag", "shadow.famd.range",
        "shadow.famd.error", "shadow.famd.convergence", "shadow.col.family",
        "shadow.col.case", "shadow.col.status", "shadow.col.ms",
        "shadow.col.findings", "shadow.col.class", "shadow.col.header",
        "shadow.col.why", "shadow.col.scope", "shadow.col.verdict",
        "shadow.col.evidence", "shadow.col.run", "shadow.col.when",
        "shadow.col.mode", "shadow.col.cases", "shadow.col.probes",
        "shadow.matrix.d", "shadow.surface.d", "shadow.surface.compared",
        "shadow.surface.suppressed", "shadow.surface.differing", "shadow.findings.none",
        "shadow.findings.none.single", "shadow.cases.rawa", "shadow.cases.nob",
        "shadow.cases.trunc", "shadow.conv.ok", "shadow.conv.stuck",
        "shadow.replay.none", "shadow.replay.verdict", "shadow.replay.holds",
        "shadow.replay.drifted", "shadow.replay.error", "shadow.replay.same",
        "shadow.corpus.d", "shadow.corpus.span", "shadow.noise.d",
        "shadow.noise.always", "shadow.noise.replayonly", "shadow.why.date",
        "shadow.why.transid", "shadow.why.reqid", "shadow.why.transidextra",
        "shadow.why.server", "shadow.why.hopbyhop", "shadow.why.via",
        "shadow.why.backend", "shadow.why.token", "shadow.why.replayts",
        "shadow.why.replaymod", "shadow.rule.status.class", "shadow.rule.status.code",
        "shadow.rule.hdr.missing", "shadow.rule.hdr.value", "shadow.rule.hdr.case",
        "shadow.rule.ctype.value", "shadow.rule.etag.value", "shadow.rule.etag.quoting",
        "shadow.rule.meta.keycase", "shadow.rule.meta.missing", "shadow.rule.meta.value",
        "shadow.rule.listing.membership", "shadow.rule.listing.order", "shadow.rule.listing.field",
        "shadow.rule.listing.count", "shadow.rule.range.status", "shadow.rule.range.boundary",
        "shadow.rule.body.error", "shadow.rule.body.bytes", "shadow.rule.conv.gap",
        "shadow.rule.conv.stuck",
        // ---- Agent-Native Object Warehouse ----
        "wh.head.scanned", "wh.unknown", "wh.u.d", "wh.u.h",
        "wh.u.m", "wh.u.s", "wh.v.scale", "wh.v.lineage.ok",
        "wh.v.lineage.gap", "wh.v.lineage.none", "wh.v.lineage.unread", "wh.v.expiry.ok",
        "wh.v.expiry.none", "wh.v.expiry.bad", "wh.v.nojobs", "wh.v.nowarehouse",
        "wh.v.unreadable", "wh.f.nolineage.t", "wh.f.nolineage.d", "wh.f.noexpiry.t",
        "wh.f.noexpiry.d", "wh.f.overdue.t", "wh.f.overdue.d", "wh.f.layout.t",
        "wh.f.layout.d", "wh.f.capped.t", "wh.f.capped.d", "wh.sec.lineage",
        "wh.sec.expiry", "wh.sec.jobs", "wh.sec.actions", "wh.sec.mcp",
        "wh.st.published", "wh.st.working", "wh.st.staged", "wh.st.empty",
        "wh.th.job", "wh.th.state", "wh.th.created", "wh.th.goal",
        "wh.th.inputs", "wh.th.working", "wh.th.artifacts", "wh.th.bytes",
        "wh.th.artifact", "wh.th.from", "wh.th.producer", "wh.th.size",
        "wh.th.when", "wh.th.object", "wh.th.expires", "wh.th.left",
        "wh.th.promote", "wh.th.tool", "wh.th.does", "wh.th.args",
        "wh.empty.nojobs", "wh.empty.nolineage", "wh.empty.noexpiry", "wh.empty.nopromote",
        "wh.exp.intro", "wh.exp.never", "wh.g.alt", "wh.g.cap",
        "wh.g.nogoal", "wh.g.noinputs", "wh.g.nooutputs", "wh.g.more",
        "wh.g.persist", "wh.g.expires", "wh.g.overdue", "wh.g.noexp",
        "wh.g.ref", "wh.g.gone", "wh.g.l.input", "wh.g.l.job",
        "wh.g.l.art", "wh.g.l.work", "wh.lin.none", "wh.lin.live",
        "wh.lin.gone", "wh.act.goal", "wh.act.goalp", "wh.act.agent",
        "wh.preview.title", "wh.preview.close", "wh.preview.loading", "wh.preview.hint",
        "nodes.state.up", "nodes.state.down", "nodes.state.degraded", "nodes.state.unreachable",
        "nodes.act.take", "nodes.act.bring", "nodes.act.confirm", "nodes.act.stopping",
        "nodes.act.starting", "nodes.act.down_ok", "nodes.act.up_ok",
        "wh.act.ttl", "wh.act.create", "wh.act.promote", "wh.act.dest",
        "wh.act.promotehint", "wh.msg.done", "wh.msg.failed", "wh.mcp.intro",
        "wh.mcp.endpoint", "wh.mcp.protocol", "wh.mcp.auth", "wh.mcp.authv",
        "wh.mcp.impl", "wh.mcp.notimpl", "wh.mcp.notimplv", "wh.mcp.instructions",
        "wh.t.datasets", "wh.t.describe", "wh.t.search", "wh.t.sample",
        "wh.t.job", "wh.t.result", "wh.t.publish",
        // ---- Lab reports  [lab-reports] ----
        "rsx.summary", "rsx.summary.bare", "rsx.kind.repl", "rsx.kind.ec", "rsx.f.change",
        "rsx.f.target", "rsx.f.value", "rsx.f.nochange", "rsx.f.notarget", "rsx.f.zoneopt",
        "rsx.f.placeholder", "rsx.f.hint", "rsx.staged.none", "rsx.staged.n",
        "rsx.chip.remove", "rsx.chip.fail_node", "rsx.chip.fail_device",
        "rsx.chip.remove_device", "rsx.chip.fail_zone", "rsx.chip.set_weight",
        "rsx.chip.add_device", "rsx.v.lost.h", "rsx.v.lost.d", "rsx.v.noquorum.h",
        "rsx.v.noquorum.d", "rsx.v.degraded.h", "rsx.v.degraded.d", "rsx.v.churn.h",
        "rsx.v.move.h", "rsx.v.move.d", "rsx.v.nomove.h", "rsx.v.nomove.d",
        "rsx.v.overlap.h", "rsx.v.overlap.d", "rsx.v.base.h", "rsx.v.base.d",
        "rsx.tier.region", "rsx.tier.zone", "rsx.tier.node", "rsx.tier.device",
        "rsx.tier.unknown", "rsx.card.readable", "rsx.card.all", "rsx.card.readable.ok",
        "rsx.card.readable.bad", "rsx.card.writable", "rsx.card.writable.ok",
        "rsx.card.writable.bad", "rsx.card.slots", "rsx.card.slots.n", "rsx.card.bytes",
        "rsx.card.tolerance", "rsx.card.tolerance.v", "rsx.card.tolerance.n",
        "rsx.eta.rate", "rsx.eta.idle", "rsx.eta.none", "rsx.dur.s", "rsx.dur.m",
        "rsx.dur.h", "rsx.map.title", "rsx.map.empty", "rsx.map.k0", "rsx.map.k1",
        "rsx.map.k2", "rsx.map.k3", "rsx.map.exact", "rsx.map.aggregated",
        "rsx.budget.title", "rsx.budget.moved", "rsx.budget.total", "rsx.budget.floor",
        "rsx.zones.title", "rsx.zones.ideal", "rsx.dev.title", "rsx.dev.note",
        "rsx.dev.nousage", "rsx.dev.ok", "rsx.dev.down", "rsx.dev.removed", "rsx.dev.added",
        "rsx.dev.c.device", "rsx.dev.c.zone", "rsx.dev.c.weight", "rsx.dev.c.ideal",
        "rsx.dev.c.before", "rsx.dev.c.after", "rsx.dev.c.delta", "rsx.dev.c.balance",
        "rsx.dev.c.disk", "rsx.dev.c.state", "rsx.dev.chart.parts", "rsx.dev.chart.meta",
        "rsx.flow.title", "rsx.flow.note", "rsx.flow.hint",
        "rsx.flow.c.from", "rsx.flow.c.to", "rsx.flow.c.slots", "rsx.flow.c.bytes",
        "rsx.table.toggle",
        "rsx.part.title", "rsx.part.label", "rsx.part.go", "rsx.part.empty", "rsx.part.cap",
        "rsx.part.none", "rsx.part.primary", "rsx.part.handoff", "rsx.part.c.role",
        "rsx.part.c.node", "rsx.part.c.device", "rsx.method.title", "rsx.method.slot",
        "rsx.method.eta.rate", "rsx.method.eta.idle", "rsx.method.eta.none",
        "rsx.method.sim", "rsx.note.unfaithful", "rsx.err.h", "rsx.err.d",
        "rsx.err.nopolicies", "rsx.err.dropped", "rsx.err.badop", "rsx.err.toomany",
        "pol.label.repl", "pol.cluster", "pol.cluster.unknown", "pol.f.data", "pol.f.cost",
        "pol.f.bw", "pol.f.nines", "pol.f.repair", "pol.f.loss", "pol.f.years",
        "pol.f.compare", "pol.rec.pick.h", "pol.rec.compromise.h", "pol.rec.none.h",
        "pol.rec.none.d", "pol.rec.why", "pol.rec.nomargin", "pol.rec.runner.dearer",
        "pol.rec.runner.cheaper", "pol.rec.caveat", "pol.unmet.durability", "pol.unmet.repair",
        "pol.unmet.loss", "pol.unmet.join", "pol.chart.title", "pol.chart.axes",
        "pol.chart.target", "pol.chart.nines", "pol.chart.rebuild", "pol.chart.k.ok",
        "pol.chart.k.miss", "pol.chart.k.out", "pol.u.min", "pol.u.h", "pol.u.d", "pol.u.inf",
        "pol.repair.title", "pol.repair.limit",
        "pol.repair.note", "pol.table.title", "pol.table.metric",
        "pol.dir.higher", "pol.dir.lower", "pol.chart.infeasible", "pol.chart.pick",
        "pol.chart.best", "pol.cons.title", "pol.m.amp", "pol.m.raw",
        "pol.m.devices", "pol.m.fanout", "pol.m.quorum", "pol.m.margin", "pol.m.readmin",
        "pol.m.survives", "pol.m.rebuild", "pol.m.repair", "pol.m.nines", "pol.m.cost",
        "pol.m.meets.dur", "pol.m.meets.repair", "pol.m.meets.loss", "pol.m.why", "pol.yes",
        "pol.no", "pol.why.none", "pol.why.devices", "pol.why.zones", "pol.why.margin",
        "pol.method.title", "pol.method.model", "pol.method.afr", "pol.method.quorum",
        "pol.method.unknown", "cap.intro", "cap.f.account", "cap.f.container",
        "cap.f.object", "cap.f.open", "cap.err.h", "cap.err.required", "cap.err.toolong",
        "cap.err.control", "cap.err.slash", "cap.err.otheraccount", "cap.err.nocontainer",
        "cap.err.container", "cap.err.baddevice", "cap.err.noobject", "cap.src.container",
        "cap.src.default", "cap.read.refused", "cap.read.broke", "cap.read.sampled",
        "cap.read.match", "cap.read.mismatch", "cap.read.noetag", "cap.read.skipped",
        "cap.v.unknown1", "cap.v.unknownN", "cap.v.deleted.h", "cap.v.deleted.d",
        "cap.v.gone.h", "cap.v.gone.d", "cap.v.ec.below.h", "cap.v.ec.below.d",
        "cap.v.ec.exact.h", "cap.v.ec.exact.d", "cap.v.ec.short.h", "cap.v.ec.short.d",
        "cap.v.ec.full.h", "cap.v.ec.full.d", "cap.v.rep.full.h", "cap.v.rep.full.d",
        "cap.v.rep.one.h", "cap.v.rep.one.d", "cap.v.rep.short.h", "cap.v.rep.short.d",
        "cap.v.corrupt.h", "cap.v.corrupt.d", "cap.v.service.h", "cap.v.service.d",
        "cap.unit.frag", "cap.unit.rep", "cap.k.durability", "cap.k.service", "cap.svc.ok",
        "cap.svc.bad", "cap.svc.none", "cap.card.policy", "cap.card.policy.n",
        "cap.card.partition", "cap.card.partition.n", "cap.card.frags", "cap.card.reps",
        "cap.card.nothing", "cap.card.version", "cap.card.readable", "cap.card.readable.n",
        "cap.card.leftovers", "cap.card.leftovers.n", "cap.matrix.title", "cap.matrix.note",
        "cap.matrix.empty", "cap.matrix.primary", "cap.matrix.handoff", "cap.cell.current",
        "cap.cell.stale", "cap.cell.tombstone", "cap.cell.empty", "cap.cell.unknown",
        "cap.policy.repl", "cap.took", "cap.h.where", "cap.dirnote", "cap.c.role",
        "cap.c.node", "cap.c.device", "cap.c.zone", "cap.c.file", "cap.c.size",
        "cap.c.version", "cap.c.fragment", "cap.c.state", "cap.row.noanswer",
        "cap.row.empty", "cap.st.current", "cap.st.stale", "cap.st.leftover",
        "cap.st.tombstone", "cap.st.meta", "cap.st.durable", "cap.st.other",
        "cap.leftover1", "cap.leftoverN", "cap.stale1", "cap.staleN", "cap.unreachable",
        "cap.h.meta", "cap.h.read", "cap.meta.size", "cap.meta.etag", "cap.meta.type",
        "cap.meta.modified", "cap.meta.version", "cap.meta.custom", "cap.meta.nocustom",
        "cap.meta.request", "cap.meta.badstatus", "cap.r.status", "cap.r.read",
        "cap.r.took", "cap.r.sampled", "cap.r.sampled.yes", "cap.r.sampled.no",
        "cap.r.etag.ok", "cap.r.etag.bad", "cap.r.etag.unchecked", "tmb.intro",
        "tmb.f.account", "tmb.f.container", "tmb.f.object", "tmb.f.open", "tmb.err.h",
        "tmb.err.required", "tmb.unit.frag", "tmb.unit.copy", "tmb.a.incomplete.h",
        "tmb.a.incomplete.d", "tmb.a.resurrection.h", "tmb.a.resurrection.d", "tmb.a.lag.h",
        "tmb.a.lag.d", "tmb.a.lag.rest", "tmb.a.offline.during.h", "tmb.a.offline.after.h",
        "tmb.a.offline.d", "tmb.a.offline.caught", "tmb.a.offline.missed",
        "tmb.a.handoff.ts.h", "tmb.a.handoff.data.h", "tmb.a.handoff.d",
        "tmb.a.handoff.tail.ts", "tmb.a.handoff.tail.plain", "tmb.a.frag.h", "tmb.a.frag.d",
        "tmb.a.frag.readable", "tmb.a.frag.unreadable", "tmb.a.under.h", "tmb.a.under.d",
        "tmb.state.present", "tmb.state.deleted_clean", "tmb.state.deleted_incomplete",
        "tmb.state.resurrected", "tmb.state.lost", "tmb.cod.clean", "tmb.cod.incomplete",
        "tmb.cod.nowhere", "tmb.cod.resurrected", "tmb.cod.lost", "tmb.cod.alive",
        "tmb.cod.unknown", "tmb.dur.s", "tmb.dur.m", "tmb.dur.h", "tmb.policy.ec",
        "tmb.policy.repl", "tmb.partline", "tmb.h.what", "tmb.h.timeline", "tmb.h.ondisk",
        "tmb.h.offline", "tmb.h.logs", "tmb.find.none", "tmb.files.none",
        "tmb.offline.none", "tmb.events.none", "tmb.logs.none", "tmb.logs.bypart",
        "tmb.unreachable", "tmb.truncated", "tmb.uncommitted", "tmb.samesecond",
        "tmb.handoff", "tmb.k.data", "tmb.k.tombstone", "tmb.k.meta", "tmb.k.durable",
        "tmb.ev.write", "tmb.ev.delete", "tmb.ev.meta", "tmb.lane.title", "tmb.lane.note",
        "tmb.lane.empty", "tmb.lane.client", "tmb.lane.delete", "tmb.lane.offline",
        "tmb.lane.k.write", "tmb.lane.k.delete", "tmb.lane.k.meta", "tmb.lane.k.offline",
        "tmb.c.node", "tmb.c.device", "tmb.c.kind", "tmb.c.wrote", "tmb.c.took",
        "tmb.c.gap", "tmb.c.size", "tmb.c.fragment", "tmb.c.from", "tmb.c.to",
        "tmb.c.downfor", "tmb.c.when", "tmb.c.lane", "tmb.c.what", "tmb.c.service",
        "tmb.c.line",
    ];

    #[test]
    fn both_languages_resolve_for_every_shipped_key() {
        // A key that resolves to itself never got a translation.
        for key in SHIPPED {
            for l in ["en", "zh"] {
                assert_ne!(t(l, key), *key, "{key} missing for {l}");
            }
        }
    }

    /// The one key that is deliberately the same in both languages is a product
    /// name; everything else differing proves no arm quietly returns English
    /// for Chinese.
    #[test]
    fn chinese_actually_differs_from_english() {
        for key in SHIPPED {
            if *key == "ring.title" {
                continue;
            }
            assert_ne!(t("zh", key), t("en", key), "{key} is not translated");
        }
    }

    /// Interpolated phrases carry the same placeholders in both languages, or
    /// one language silently drops a value.
    #[test]
    fn placeholders_survive_translation() {
        for (key, holders) in [
            ("files.stat", &["{n}", "{used}", "{quota}"][..]),
            ("files.quota", &["{q}"][..]),
            ("files.items", &["{n}"][..]),
            ("acct.stat", &["{who}", "{used}", "{containers}", "{objects}"][..]),
            ("users.intro", &["{cluster}"][..]),
            ("users.rostererr", &["{e}"][..]),
            ("search.indexed", &["{n}", "{ago}"][..]),
            ("login.failed", &["{e}"][..]),
        ] {
            for l in ["en", "zh"] {
                for h in holders {
                    assert!(t(l, key).contains(h), "{key} lost {h} in {l}");
                }
            }
        }
    }

    #[test]
    fn unknown_keys_surface_loudly() {
        assert_eq!(t("zh", "no.such.key"), "no.such.key");
    }

    #[test]
    fn html_lang_tag() {
        assert_eq!(html_lang("zh"), "zh-CN");
        assert_eq!(html_lang("en"), "en");
    }
}
