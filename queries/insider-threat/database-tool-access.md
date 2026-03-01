# Database Tool Access Outside Normal Scope

## Description

Detects execution of database management and query tools — such as DBeaver, HeidiSQL, SQLite Browser, MySQL Workbench, pgAdmin, and `sqlcmd` — especially from non-DBA endpoints or outside normal business hours. Insiders can use these tools to dump entire databases, export customer records, financial data, or credentials stored in databases. The combination of tool execution, large query activity, and subsequent file writes (CSV, SQL dump files) is the key signal chain.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Collection |
| **Technique** | T1005 — Data from Local System |
| **Sub-technique** | T1213 — Data from Information Repositories |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `ProcessRollup2`, `FileWritten`, `NetworkConnectIP4` |

## Severity

**Medium** — Severity depends on the database being accessed; customer PII, financial records, or credential databases elevate to High.

## Query

```logscale
// Database GUI tool execution — identify who is running DB clients and from where
#event_simpleName=ProcessRollup2
| in(FileName, values=[
    "DBeaver.exe", "dbeaver-ce.exe",
    "HeidiSQL.exe",
    "SQLiteBrowser.exe", "DB Browser for SQLite.exe",
    "MySQLWorkbench.exe",
    "pgAdmin4.exe", "pgAdmin3.exe",
    "Toad.exe", "TOADforOracle.exe",
    "DataGrip.exe",
    "TablePlus.exe",
    "Sequel Pro.exe",
    "RazorSQL.exe",
    "AquaDataStudio.exe",
    "dbvis.exe"
  ])
| table([ComputerName, UserName, FileName, FilePath, ParentBaseFileName, @timestamp], limit=200)
```

**Variant: Command-line database clients and dump utilities**

```logscale
// CLI DB tools — often used for scripted data exports (mysqldump, pg_dump, sqlcmd, etc.)
#event_simpleName=ProcessRollup2
| in(FileName, values=[
    "sqlcmd.exe", "osql.exe", "bcp.exe",
    "mysql.exe", "mysqldump.exe", "mysqladmin.exe",
    "psql.exe", "pg_dump.exe", "pg_dumpall.exe",
    "sqlite3.exe", "sqlite.exe",
    "mongodump.exe", "mongoexport.exe", "mongo.exe",
    "redis-cli.exe",
    "exp.exe", "expdp.exe"
  ])
| table([ComputerName, UserName, FileName, CommandLine, ParentBaseFileName, @timestamp], limit=200)
```

**Variant: Database dump files written to disk**

```logscale
// Database export/dump files created — data ready for exfiltration
#event_simpleName=FileWritten
| FileName=/\.(sql|dump|dmp|bak|mdf|ldf|db|sqlite|sqlite3|accdb|mdb|csv|json)$/i
| FilePath=/(\\Desktop\\|\\Downloads\\|\\Temp\\|\\Public\\|\\Users\\Public)/i
| table([ComputerName, UserName, FileName, FilePath, @timestamp], limit=200)
```

**Variant: Database client connecting to non-standard or external hosts**

```logscale
// DB tool making outbound connection to external or unusual IP — potential rogue DB or cloud DB access
#event_simpleName=NetworkConnectIP4
| in(FileName, values=[
    "DBeaver.exe", "HeidiSQL.exe", "MySQLWorkbench.exe",
    "pgAdmin4.exe", "sqlcmd.exe", "mysql.exe", "psql.exe"
  ])
| RemoteAddressIP4!=/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)/
| table([ComputerName, UserName, FileName, RemoteAddressIP4, RemotePort, @timestamp], limit=200)
```

**Variant: DB tool run by non-standard users (anomaly)**

```logscale
// DB tools run on non-DBA workstations — anomaly for most environments
#event_simpleName=ProcessRollup2
| in(FileName, values=["DBeaver.exe","HeidiSQL.exe","MySQLWorkbench.exe","pgAdmin4.exe","sqlcmd.exe","mysqldump.exe","pg_dump.exe"])
| groupBy([ComputerName, UserName, FileName], function=count(as=run_count))
| sort(run_count, order=desc)
| table([ComputerName, UserName, FileName, run_count])
```

## Response Notes

**Triage steps:**
1. Identify the database host being connected to — is this an authorized data source for this user?
2. Check for `.sql`, `.csv`, or `.dump` files written to disk in the same session window
3. Review `UserName` role — DBA team access is expected; marketing, sales, or HR access to production DBs is not
4. Look for subsequent compression or upload activity following DB tool use
5. Check the size and content of any dump files written — row counts in the millions indicate full table exports

**False positives:**
- DBA and developer teams legitimately use these tools daily
- DevOps workflows may run `pg_dump` / `mysqldump` for automated backups — filter service accounts
- Data science teams may extract datasets for analysis — assess whether this is authorized and within scope

## References

- https://attack.mitre.org/techniques/T1005/
- https://attack.mitre.org/techniques/T1213/
