using System;
using System.IO;
using System.Diagnostics;
using System.Collections.Generic;
using System.Collections.Concurrent; // Added for thread-safe queuing
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json;
using System.Linq;
using System.Text;
using System.Net.Http;
using System.Runtime.InteropServices;

namespace VaultWare.Shield.Models
{
    // ==========================================
    // 1. DATA MODELS
    // ==========================================

    public class ScanResult
    {
        public string ScanType { get; set; }
        public int FilesChecked { get; set; }
        public int ThreatsFound { get; set; }
        public string Duration { get; set; }
        public DateTime CompletedAt { get; set; }
        public string Status { get; set; }
    }

    public class QuarantineItem
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string ThreatName { get; set; }
        public string OriginalPath { get; set; }
        public string StoragePath { get; set; }
        public string FileHash { get; set; }
        public DateTime DateCaptured { get; set; }
        public string Severity { get; set; }
        public string Status { get; set; } = "Quarantined";
        public string CloudResult { get; set; } = "Not Analyzed";
    }

    public class AuditItem
    {
        public string Action { get; set; }
        public string FileName { get; set; }
        public string Details { get; set; }
        public DateTime Timestamp { get; set; }
        public string ColorClass { get; set; }
    }

    public class AppSettings
    {
        public List<string> Whitelist { get; set; } = new List<string>();
        public List<string> Blacklist { get; set; } = new List<string>();
        public bool RealTimeProtection { get; set; } = true;
        public bool RansomwareProtection { get; set; } = false;
        public bool Firewall { get; set; } = true;
        public bool WebProtection { get; set; } = true;
        public string CustomReportPath { get; set; } = "";
    }

    // *** NEW MODELS FOR ADVISOR & GRAPHS ***
    public class HealthStatus
    {
        public int SecurityScore { get; set; } // 0 to 100
        public string StatusLabel { get; set; } // "Secure", "At Risk", "Critical"
        public List<string> Recommendations { get; set; } = new List<string>();
    }

    public class GraphData
    {
        public List<string> Labels { get; set; } = new List<string>();
        public List<int> Threats { get; set; } = new List<int>();
        public List<int> Scans { get; set; } = new List<int>();
    }

    // ==========================================
    // 2. THE SECURITY ENGINE (CORE)
    // ==========================================

    public class SecurityEngine
    {
        private const string VirusTotalApiKey = "d17f5791ce17b4e0c37cc0c6226560b9a05e21e99b4157912455219418fa4903";
        private const string EICAR_STRING = @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

        // *** GLOBAL STATE ***
        public static bool IsActive { get; set; } = true;
        public static bool IsRansomwareActive { get; set; } = false;
        public static bool IsFirewallActive { get; set; } = true;
        public static bool IsWebActive { get; set; } = true;

        // *** RANSOMWARE HEURISTICS ***
        private static readonly HashSet<string> SuspiciousExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".locked", ".enc", ".crpt", ".crypto", ".ransom", ".crypted", ".vault", ".zepto", ".onion"
        };

        // *** SCANNER STATE ***
        public static bool IsScanning = false;
        public static string CurrentScanType = "";
        public static int ScanProgress = 0;
        public static string CurrentFile = "Ready";
        public static string ScanDuration = "00:00";
        public static int FilesScanned = 0;
        public static int ThreatsFoundInScan = 0;
        public static int TotalFiles = 0;

        // *** DATA STORAGE ***
        public static List<QuarantineItem> QuarantineHistory = new List<QuarantineItem>();
        public static List<AuditItem> AuditHistory = new List<AuditItem>();
        public static List<ScanResult> ScanLogHistory = new List<ScanResult>();
        public static HashSet<string> BlacklistedHashes = new HashSet<string>();
        public static HashSet<string> WhitelistedPaths = new HashSet<string>();

        // *** PATHS ***
        private static string _vaultFolder;
        public static string ReportsFolder;
        private static string _dbPath_Quarantine;
        private static string _dbPath_Audit;
        private static string _dbPath_ScanLogs;
        private static string _dbPath_Settings;

        // *** ENGINE INTERNALS ***
        private static List<FileSystemWatcher> _watchers = new List<FileSystemWatcher>();
        private static Stopwatch _scanTimer = new Stopwatch();
        private static CancellationTokenSource _scanToken;
        private static int _scanDelay = 0;
        private static bool _isInitialized = false;

        // *** CONCURRENCY CONTROL (Debounce Logic) ***
        private static ConcurrentDictionary<string, DateTime> _pendingScans = new ConcurrentDictionary<string, DateTime>();
        private static CancellationTokenSource _monitorTokenSource;
        private static readonly object _quarantineLock = new object();

        // *** ALERTS ***
        public static bool AlertUnread = false;
        public static string LatestThreat = "";
        public static string LastAlert = "System Secure";

        // ==========================================
        // 3. INITIALIZATION & DATABASE
        // ==========================================

        public static void Initialize()
        {
            if (_isInitialized) return;
            _isInitialized = true;

            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

            // 1. Setup Vault
            _vaultFolder = Path.Combine(userProfile, "VaultWare_Quarantine_Vault");
            if (!Directory.Exists(_vaultFolder))
            {
                Directory.CreateDirectory(_vaultFolder);
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    File.SetAttributes(_vaultFolder, File.GetAttributes(_vaultFolder) | FileAttributes.Hidden);
                }
            }

            // 2. Setup Database Folder
            string appData = Path.Combine(userProfile, "VaultWare_Data");
            if (!Directory.Exists(appData)) Directory.CreateDirectory(appData);

            _dbPath_Quarantine = Path.Combine(appData, "quarantine_db.json");
            _dbPath_Audit = Path.Combine(appData, "audit_log_db.json");
            _dbPath_ScanLogs = Path.Combine(appData, "scan_logs_db.json");
            _dbPath_Settings = Path.Combine(appData, "settings_db.json");

            // 3. Load Settings
            LoadDatabase();

            // 4. Setup Reports Folder
            if (string.IsNullOrEmpty(ReportsFolder))
            {
                ReportsFolder = Path.Combine(docs, "VaultWare_Reports");
            }
            if (!Directory.Exists(ReportsFolder)) Directory.CreateDirectory(ReportsFolder);

            // 5. Start Background Monitoring (Queue Debouncer)
            StartMonitoringLoop();

            if (IsActive)
            {
                StartProtection();
            }
        }

        private static void SaveDatabase()
        {
            try
            {
                var options = new JsonSerializerOptions { WriteIndented = true };

                List<QuarantineItem> qCopy;
                List<AuditItem> aCopy;
                List<ScanResult> sCopy;

                lock (QuarantineHistory) qCopy = new List<QuarantineItem>(QuarantineHistory);
                lock (AuditHistory) aCopy = new List<AuditItem>(AuditHistory);
                lock (ScanLogHistory) sCopy = new List<ScanResult>(ScanLogHistory);

                File.WriteAllText(_dbPath_Quarantine, JsonSerializer.Serialize(qCopy, options));
                File.WriteAllText(_dbPath_Audit, JsonSerializer.Serialize(aCopy, options));
                File.WriteAllText(_dbPath_ScanLogs, JsonSerializer.Serialize(sCopy, options));

                var settings = new AppSettings
                {
                    Whitelist = WhitelistedPaths.ToList(),
                    Blacklist = BlacklistedHashes.ToList(),
                    RealTimeProtection = IsActive,
                    RansomwareProtection = IsRansomwareActive,
                    Firewall = IsFirewallActive,
                    WebProtection = IsWebActive,
                    CustomReportPath = ReportsFolder
                };
                File.WriteAllText(_dbPath_Settings, JsonSerializer.Serialize(settings, options));
            }
            catch { }
        }

        private static void LoadDatabase()
        {
            var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };

            T SafeLoad<T>(string path) where T : new()
            {
                try
                {
                    if (!File.Exists(path)) return new T();
                    string content = File.ReadAllText(path);
                    return JsonSerializer.Deserialize<T>(content, options) ?? new T();
                }
                catch { return new T(); }
            }

            QuarantineHistory = SafeLoad<List<QuarantineItem>>(_dbPath_Quarantine);
            AuditHistory = SafeLoad<List<AuditItem>>(_dbPath_Audit);
            ScanLogHistory = SafeLoad<List<ScanResult>>(_dbPath_ScanLogs);

            try
            {
                if (File.Exists(_dbPath_Settings))
                {
                    var settings = JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(_dbPath_Settings), options);
                    if (settings != null)
                    {
                        WhitelistedPaths = new HashSet<string>(settings.Whitelist ?? new List<string>());
                        BlacklistedHashes = new HashSet<string>(settings.Blacklist ?? new List<string>());
                        IsActive = settings.RealTimeProtection;
                        IsRansomwareActive = settings.RansomwareProtection;
                        IsFirewallActive = settings.Firewall;
                        IsWebActive = settings.WebProtection;

                        if (!string.IsNullOrEmpty(settings.CustomReportPath))
                        {
                            ReportsFolder = settings.CustomReportPath;
                        }
                    }
                }
            }
            catch { }
        }

        // ==========================================
        // 4. ROBUST SYSTEM OPTIMIZER
        // ==========================================

        public static string OptimizeRam()
        {
            try
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();

                string osMsg = "Standard GC";

                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    try
                    {
                        Process.GetCurrentProcess().MinWorkingSet = (IntPtr)300000;
                        osMsg = "Windows Working Set Trimmed";
                    }
                    catch { }
                }

                LogOptimization("RAM Boost", $"{osMsg} - Memory Freed");
                return "RAM Freed & Optimized";
            }
            catch (Exception ex) { return "Error: " + ex.Message; }
        }

        public static int CleanSystemJunk()
        {
            int deleted = 0;
            var pathsToClean = new List<string>();

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                pathsToClean.Add(Path.GetTempPath());
                pathsToClean.Add(@"C:\Windows\Temp");
            }
            else
            {
                pathsToClean.Add("/tmp");
                pathsToClean.Add("/var/tmp");
                string home = Environment.GetEnvironmentVariable("HOME");
                if (!string.IsNullOrEmpty(home))
                {
                    pathsToClean.Add(Path.Combine(home, ".cache"));
                }
            }

            foreach (var path in pathsToClean)
            {
                if (Directory.Exists(path))
                {
                    deleted += ForceDeleteDirectoryContents(path);
                }
            }

            LogOptimization("Junk Clean", $"{deleted} Files/Folders Purged");
            return deleted;
        }

        private static int ForceDeleteDirectoryContents(string rootPath)
        {
            int count = 0;
            try
            {
                DirectoryInfo di = new DirectoryInfo(rootPath);
                foreach (FileInfo file in di.GetFiles())
                {
                    try { file.Delete(); count++; } catch { }
                }
                foreach (DirectoryInfo dir in di.GetDirectories())
                {
                    try
                    {
                        count += ForceDeleteDirectoryContents(dir.FullName);
                        dir.Delete(true);
                        count++;
                    }
                    catch { }
                }
            }
            catch { }
            return count;
        }

        public static string ClearBrowserCache()
        {
            int count = 0;
            string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var cachePaths = new List<string>();

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                cachePaths.Add(Path.Combine(home, @"AppData\Local\Google\Chrome\User Data\Default\Cache\Cache_Data"));
                cachePaths.Add(Path.Combine(home, @"AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data"));
                cachePaths.Add(Path.Combine(home, @"AppData\Local\Mozilla\Firefox\Profiles"));
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                cachePaths.Add(Path.Combine(home, ".cache", "google-chrome"));
                cachePaths.Add(Path.Combine(home, ".cache", "mozilla"));
                // Added Mac path
                cachePaths.Add(Path.Combine(home, "Library", "Caches", "Google", "Chrome"));
            }

            foreach (string p in cachePaths)
            {
                if (Directory.Exists(p)) count += ForceDeleteDirectoryContents(p);
            }

            LogOptimization("Browser Cache", $"{count} Web Cache Files Wiped");
            return $"{count} Browser Files Removed";
        }

        private static void LogOptimization(string type, string details)
        {
            lock (AuditHistory)
            {
                AuditHistory.Insert(0, new AuditItem
                {
                    Action = "OPTIMIZED",
                    FileName = type,
                    Details = details,
                    Timestamp = DateTime.Now,
                    ColorClass = "text-success"
                });
            }
            GenerateActionReport("OPTIMIZATION", type, details);
            SaveDatabase();
        }

        // ==========================================
        // 5. CACHE & MAINTENANCE
        // ==========================================

        public static void ClearSystemCache()
        {
            try
            {
                if (Directory.Exists(ReportsFolder))
                {
                    var files = Directory.GetFiles(ReportsFolder);
                    foreach (var f in files) { try { File.Delete(f); } catch { } }
                }
                CleanLogs(0);
                CleanSystemJunk();
            }
            catch { }
        }

        public static void SetCustomReportPath(string newPath)
        {
            try
            {
                if (!Directory.Exists(newPath)) Directory.CreateDirectory(newPath);
                ReportsFolder = newPath;
                SaveDatabase();
            }
            catch { }
        }

        // ==========================================
        // 6. REAL-TIME MONITORING (UPDATED & FIXED)
        // ==========================================

        public static void StartProtection()
        {
            Initialize();

            if (_watchers.Count == 0 || !_watchers.Any(w => w.EnableRaisingEvents))
            {
                SetupWatcher();
            }

            foreach (var w in _watchers)
            {
                try { w.EnableRaisingEvents = true; } catch { }
            }

            IsActive = true;
            LastAlert = "System Secure - Monitoring Active";
            SaveDatabase();

            Task.Run(() => PerformStartupSweep());
        }

        public static void StopProtection()
        {
            foreach (var w in _watchers)
            {
                try { w.EnableRaisingEvents = false; } catch { }
            }
            IsActive = false;
            LastAlert = "⚠️ PROTECTION PAUSED";
            SaveDatabase();
        }

        // *** THE CROSS-PLATFORM TOGGLE ***
        public static void ToggleSystemFeature(string feature, bool enable)
        {
            switch (feature)
            {
                case "RealTime": IsActive = enable; break;
                case "Web": IsWebActive = enable; break;
                case "Ransomware": IsRansomwareActive = enable; break;
                case "Firewall": IsFirewallActive = enable; break;
            }

            if (feature == "Firewall")
            {
                try
                {
                    ProcessStartInfo psi = null;
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        string state = enable ? "on" : "off";
                        psi = new ProcessStartInfo("netsh", $"advfirewall set allprofiles state {state}") { Verb = "runas", UseShellExecute = true, WindowStyle = ProcessWindowStyle.Hidden };
                    }
                    else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                    {
                        string cmd = enable ? "enable" : "disable";
                        psi = new ProcessStartInfo("ufw", cmd) { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                    }
                    else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                    {
                        string cmd = enable ? "--setglobalstate on" : "--setglobalstate off";
                        psi = new ProcessStartInfo("/usr/libexec/ApplicationFirewall/socketfilterfw", cmd) { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                    }

                    if (psi != null) Process.Start(psi);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Firewall Error: " + ex.Message);
                }
            }
            else if (feature == "RealTime")
            {
                if (enable) StartProtection(); else StopProtection();
            }
            SaveDatabase();
        }

        private static void PerformStartupSweep()
        {
            var criticalPaths = new List<string>
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads")
            };

            foreach (var path in criticalPaths)
            {
                if (Directory.Exists(path))
                {
                    try
                    {
                        var files = Directory.GetFiles(path);
                        foreach (var file in files) { if (!IsActive) return; CheckFileForVirus(file); }
                    }
                    catch { }
                }
            }
        }

        private static void SetupWatcher()
        {
            try
            {
                foreach (var w in _watchers) { w.Dispose(); }
                _watchers.Clear();

                var foldersToWatch = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    foreach (DriveInfo drive in DriveInfo.GetDrives())
                        if (drive.IsReady && drive.DriveType == DriveType.Fixed) foldersToWatch.Add(drive.Name);
                }
                else
                {
                    // Ubuntu/Mac: Watch User Home only. Do NOT watch Root /.
                    string userHome = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                    if (Directory.Exists(userHome)) foldersToWatch.Add(userHome);

                    if (Directory.Exists("/tmp")) foldersToWatch.Add("/tmp");
                }

                foreach (var path in foldersToWatch)
                {
                    if (Directory.Exists(path))
                    {
                        try
                        {
                            var w = new FileSystemWatcher(path);
                            w.Filter = "*.*";
                            w.IncludeSubdirectories = true;
                            w.InternalBufferSize = 65536;

                            w.NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.LastWrite | NotifyFilters.CreationTime;

                            w.Created += OnFileEvent;
                            w.Changed += OnFileEvent;
                            w.Renamed += OnFileRenamed;
                            w.Error += OnWatcherError;

                            _watchers.Add(w);
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        private static void OnWatcherError(object sender, ErrorEventArgs e)
        {
            Task.Run(() =>
            {
                StopProtection();
                Thread.Sleep(2000);
                StartProtection();
            });
        }

        // *** DEBOUNCE LOGIC (FIX FOR DUMMY VIRUS / LOCKED FILES) ***
        private static void StartMonitoringLoop()
        {
            _monitorTokenSource = new CancellationTokenSource();
            Task.Factory.StartNew(async () =>
            {
                while (!_monitorTokenSource.Token.IsCancellationRequested)
                {
                    try
                    {
                        var now = DateTime.Now;
                        var readyToScan = _pendingScans.Where(x => (now - x.Value).TotalMilliseconds > 500).ToList();

                        foreach (var item in readyToScan)
                        {
                            if (_pendingScans.TryRemove(item.Key, out _))
                            {
                                if (IsActive) ProcessFileChange(item.Key);
                            }
                        }
                    }
                    catch { }
                    await Task.Delay(250);
                }
            }, _monitorTokenSource.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }

        private static void OnFileEvent(object sender, FileSystemEventArgs e)
        {
            _pendingScans.AddOrUpdate(e.FullPath, DateTime.Now, (key, oldValue) => DateTime.Now);
        }

        private static void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            string newExt = Path.GetExtension(e.FullPath).ToLower();
            if (IsRansomwareActive && SuspiciousExtensions.Contains(newExt))
            {
                ProcessFileChange(e.FullPath);
            }
            else
            {
                _pendingScans.AddOrUpdate(e.FullPath, DateTime.Now, (key, oldValue) => DateTime.Now);
            }
        }

        // *** CORE DETECTION LOGIC (OS COMPATIBLE) ***
        private static void ProcessFileChange(string p)
        {
            if (string.IsNullOrWhiteSpace(p)) return;

            string ext = Path.GetExtension(p).ToLower();
            if (IsRansomwareActive && SuspiciousExtensions.Contains(ext))
            {
                HandleRansomwareDetection(p, ext);
                return;
            }

            string normalizedPath = Path.GetFullPath(p);
            string vaultPath = Path.GetFullPath(_vaultFolder);

            if (normalizedPath.StartsWith(vaultPath, StringComparison.OrdinalIgnoreCase)) return;
            if (WhitelistedPaths.Contains(p)) return;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (p.Contains(@"\Windows\", StringComparison.OrdinalIgnoreCase) ||
                    p.Contains(@"\AppData\", StringComparison.OrdinalIgnoreCase)) return;
            }
            else
            {
                if (p.StartsWith("/proc") || p.StartsWith("/sys") || p.StartsWith("/dev") || p.Contains("/.config/")) return;
            }

            if (p.EndsWith(".tmp") || p.EndsWith(".log")) return;

            CheckFileForVirus(p);
        }

        private static void HandleRansomwareDetection(string p, string ext)
        {
            LatestThreat = "Ransomware.Detected";
            AlertUnread = true;

            lock (AuditHistory)
            {
                AuditHistory.Insert(0, new AuditItem
                {
                    Action = "BLOCKED",
                    FileName = Path.GetFileName(p),
                    Details = "Ransomware Behavior Detected",
                    Timestamp = DateTime.Now,
                    ColorClass = "text-danger fw-bold"
                });
            }

            SaveDatabase();
            GenerateActionReport("RANSOMWARE_BLOCKED", p, $"Encrypted extension detected: {ext}");
            try { File.Delete(p); } catch { }
        }

        // ==========================================
        // SCANNER
        // ==========================================

        public static void StartScan(string mode, string customPath = "")
        {
            if (IsScanning) return;

            Initialize();
            IsScanning = true; CurrentScanType = mode.ToUpper(); FilesScanned = 0; ThreatsFoundInScan = 0;
            _scanTimer.Restart(); _scanToken = new CancellationTokenSource();

            List<string> folders = new List<string>();
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            if (mode == "quick")
            {
                string realDesktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                string realDocs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                string downloads = Path.Combine(userProfile, "Downloads");

                if (Directory.Exists(realDesktop)) folders.Add(realDesktop);
                if (Directory.Exists(realDocs)) folders.Add(realDocs);
                if (Directory.Exists(downloads)) folders.Add(downloads);
                _scanDelay = 0;
            }
            else if (mode == "custom" && Directory.Exists(customPath))
            {
                folders.Add(customPath);
                _scanDelay = 5;
            }
            else
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    foreach (var d in DriveInfo.GetDrives())
                        if (d.IsReady && d.DriveType == DriveType.Fixed) folders.Add(d.Name);
                }
                else
                {
                    folders.Add(userProfile);
                }
                _scanDelay = 2;
            }

            Task.Factory.StartNew(() =>
            {
                string status = "Completed";
                try
                {
                    foreach (var folder in folders)
                    {
                        if (_scanToken.Token.IsCancellationRequested) { status = "Aborted"; break; }
                        if (Directory.Exists(folder)) ScanDirectory(folder);
                    }
                }
                catch (Exception ex) { CurrentFile = "Error: " + ex.Message; status = "Failed"; }
                finally
                {
                    IsScanning = false;
                    string duration = _scanTimer.Elapsed.ToString(@"mm\:ss");
                    _scanTimer.Stop();
                    lock (ScanLogHistory)
                    {
                        ScanLogHistory.Insert(0, new ScanResult { ScanType = CurrentScanType, FilesChecked = FilesScanned, ThreatsFound = ThreatsFoundInScan, Duration = duration, CompletedAt = DateTime.Now, Status = status });
                    }
                    SaveDatabase(); GenerateScanReport(status, duration);
                }
            }, _scanToken.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }

        public static void StopScan() { if (_scanToken != null) _scanToken.Cancel(); }

        private static void ScanDirectory(string dir)
        {
            try
            {
                if (WhitelistedPaths.Contains(dir)) return;

                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    if (dir.Contains(@"\Windows", StringComparison.OrdinalIgnoreCase) ||
                        dir.Contains(@"\Program Files", StringComparison.OrdinalIgnoreCase)) return;
                }
                else
                {
                    if (dir.StartsWith("/proc") || dir.StartsWith("/sys")) return;
                }

                string[] files = Directory.GetFiles(dir);
                foreach (string file in files)
                {
                    if (_scanToken.Token.IsCancellationRequested) return;
                    FilesScanned++;
                    CurrentFile = Path.GetFileName(file);
                    if (_scanDelay > 0) Thread.Sleep(_scanDelay);
                    try { if (CheckFileForVirus(file)) ThreatsFoundInScan++; } catch { }
                }

                foreach (string sub in Directory.GetDirectories(dir))
                {
                    if (_scanToken.Token.IsCancellationRequested) return;
                    try
                    {
                        var info = new DirectoryInfo(sub);
                        if ((info.Attributes & FileAttributes.Hidden) != FileAttributes.Hidden)
                            ScanDirectory(sub);
                    }
                    catch { }
                }
            }
            catch { }
        }

        private static bool CheckFileForVirus(string p)
        {
            try
            {
                FileInfo fi = new FileInfo(p);
                if (!fi.Exists || fi.Length > 50 * 1024 * 1024) return false;
                if (IsFileLocked(fi)) return false;

                string hash = CalculateSha256(p);
                string fName = fi.Name.ToLowerInvariant();
                bool found = false;
                string threat = "Unknown";
                string severity = "HIGH";

                if (BlacklistedHashes.Contains(hash)) { threat = "User.Blocked.Hash"; found = true; }

                if (!found && fi.Length < 1024)
                {
                    try
                    {
                        string content = File.ReadAllText(p);
                        if (content.Contains(EICAR_STRING)) { threat = "EICAR.Test.File"; found = true; }
                    }
                    catch { }
                }

                if (!found)
                {
                    if (fName.Contains("vaultware_test_virus")) { threat = "Malware.Generic.Test"; severity = "MEDIUM"; found = true; }
                    else if (fName.EndsWith(".malz") || fName.EndsWith(".ransom")) { threat = "Ransom.Sim.Extension"; severity = "CRITICAL"; found = true; }
                    else if (fName.Contains("eicar")) { threat = "EICAR.Test.File"; severity = "LOW"; found = true; }
                }

                if (found)
                {
                    QuarantineFile(p, threat, severity, hash);
                    return true;
                }
                return false;
            }
            catch { return false; }
        }

        private static bool IsFileLocked(FileInfo file)
        {
            try
            {
                using (FileStream stream = file.Open(FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    stream.Close();
                }
            }
            catch (IOException)
            {
                return true;
            }
            return false;
        }

        // *** FIXED QUARANTINE LOGIC (Prevents Duplication/Missing Files) ***
        public static void QuarantineFile(string originalPath, string threatName, string severity, string hash = "N/A")
        {
            lock (_quarantineLock)
            {
                try
                {
                    if (!File.Exists(originalPath)) return;

                    LatestThreat = threatName;
                    AlertUnread = true;

                    string ext = Path.GetExtension(originalPath);
                    string safeFileName = $"{Guid.NewGuid()}{ext}.vir";
                    string storagePath = Path.Combine(_vaultFolder, safeFileName);

                    bool moved = false;
                    try
                    {
                        File.Move(originalPath, storagePath);
                        moved = true;
                    }
                    catch
                    {
                        try
                        {
                            File.Copy(originalPath, storagePath, true);
                            File.Delete(originalPath);
                            moved = true;
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Quarantine failed: {ex.Message}");
                        }
                    }

                    if (moved)
                    {
                        var qItem = new QuarantineItem
                        {
                            ThreatName = threatName,
                            OriginalPath = originalPath,
                            StoragePath = storagePath,
                            FileHash = hash,
                            DateCaptured = DateTime.Now,
                            Severity = severity,
                            CloudResult = "Pending..."
                        };

                        lock (QuarantineHistory) QuarantineHistory.Add(qItem);

                        lock (AuditHistory)
                        {
                            AuditHistory.Insert(0, new AuditItem
                            {
                                Action = "QUARANTINED",
                                FileName = Path.GetFileName(originalPath),
                                Details = threatName,
                                Timestamp = DateTime.Now,
                                ColorClass = "text-danger"
                            });
                        }

                        SaveDatabase();
                        GenerateActionReport("THREAT_QUARANTINED", originalPath, $"Threat: {threatName}");
                    }
                }
                catch { }
            }
        }

        private static string CalculateSha256(string p)
        {
            try
            {
                using (var s = SHA256.Create())
                using (var f = File.OpenRead(p))
                {
                    return BitConverter.ToString(s.ComputeHash(f)).Replace("-", "").ToLowerInvariant();
                }
            }
            catch { return "N/A"; }
        }

        public static void GenerateActionReport(string action, string file, string details)
        {
            try
            {
                if (!Directory.Exists(ReportsFolder)) Initialize();
                string fileName = $"Action_{action}_{DateTime.Now:yyyyMMdd_HHmmss}_{Guid.NewGuid().ToString().Substring(0, 4)}.txt";
                File.WriteAllText(Path.Combine(ReportsFolder, fileName), $"{action}\n{file}\n{details}");
            }
            catch { }
        }

        private static void GenerateScanReport(string status, string duration)
        {
            try
            {
                if (!Directory.Exists(ReportsFolder)) Initialize();
                string fileName = $"Scan_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
                File.WriteAllText(Path.Combine(ReportsFolder, fileName), $"Type: {CurrentScanType}\nStatus: {status}\nFiles: {FilesScanned}\nDuration: {duration}");
            }
            catch { }
        }

        public static async Task PerformCloudAnalysisAsync(string id)
        {
            var item = QuarantineHistory.Find(x => x.Id == id);
            if (item == null) return;
            item.Status = "Submitted to Cloud"; SaveDatabase();
            try
            {
                using (var client = new HttpClient())
                {
                    client.DefaultRequestHeaders.Add("x-apikey", VirusTotalApiKey);
                    var response = await client.GetAsync($"https://www.virustotal.com/api/v3/files/{item.FileHash}");
                    if (response.IsSuccessStatusCode)
                    {
                        string json = await response.Content.ReadAsStringAsync();
                        bool isMalicious = json.Contains("\"malicious\":") && !json.Contains("\"malicious\": 0");
                        item.CloudResult = isMalicious ? "DANGEROUS (Confirmed)" : "CLEAN (Verified)";
                        item.Severity = isMalicious ? "CRITICAL" : "LOW";
                    }
                    else { item.CloudResult = "Analysis Inconclusive"; }
                }
            }
            catch { item.CloudResult = "Network Error"; }

            lock (AuditHistory)
            {
                AuditHistory.Insert(0, new AuditItem { Action = "ANALYZED", FileName = Path.GetFileName(item.OriginalPath), Details = item.CloudResult, Timestamp = DateTime.Now, ColorClass = "text-info" });
            }
            SaveDatabase();
        }

        public static void CancelAnalysis(string id)
        {
            var item = QuarantineHistory.Find(x => x.Id == id);
            if (item != null)
            {
                item.Status = "Quarantined";
                item.CloudResult = "Analysis Cancelled";
                SaveDatabase();
            }
        }

        public static void RescanFile(string id)
        {
            var item = QuarantineHistory.Find(x => x.Id == id);
            if (item != null)
            {
                if (!File.Exists(item.StoragePath))
                {
                    item.Status = "File Missing";
                    item.CloudResult = "Error: Not Found";
                    SaveDatabase();
                    return;
                }

                string h = CalculateSha256(item.StoragePath);
                if (BlacklistedHashes.Contains(h)) { item.Status = "Blocked Forever"; item.Severity = "HIGH"; item.CloudResult = "Local: BLOCKED"; }
                else if (File.ReadAllText(item.StoragePath).Contains("EICAR")) { item.Status = "Quarantined"; item.Severity = "CRITICAL"; item.CloudResult = "Local: EICAR"; }
                else { item.Status = "Quarantined"; item.Severity = "LOW"; item.CloudResult = "Local DB: Safe"; }
                SaveDatabase();
            }
        }

        public static void CleanLogs(int hours)
        {
            lock (AuditHistory)
            {
                if (hours == 0) AuditHistory.Clear();
                else AuditHistory.RemoveAll(x => x.Timestamp < DateTime.Now.AddHours(-hours));
            }
            lock (ScanLogHistory)
            {
                if (hours == 0) ScanLogHistory.Clear();
                else ScanLogHistory.RemoveAll(x => x.CompletedAt < DateTime.Now.AddHours(-hours));
            }
            SaveDatabase();
        }

        public static void AddToWhitelist(string p) { WhitelistedPaths.Add(p); SaveDatabase(); }
        public static void RemoveFromWhitelist(string p) { WhitelistedPaths.Remove(p); SaveDatabase(); }
        public static void UnbanHash(string h) { BlacklistedHashes.Remove(h); SaveDatabase(); }
        public static void ManualBanHash(string h) { BlacklistedHashes.Add(h); SaveDatabase(); }
        public static void ManualAdd(string p) { if (File.Exists(p)) QuarantineFile(p, "Manual", "LOW", CalculateSha256(p)); }

        public static void DeleteFile(string id)
        {
            var item = QuarantineHistory.Find(x => x.Id == id);
            if (item != null)
            {
                try { File.Delete(item.StoragePath); } catch { }
                lock (QuarantineHistory) QuarantineHistory.Remove(item);
                GenerateActionReport("DELETED", item.OriginalPath, "Permanent");
                SaveDatabase();
            }
        }

        public static void RestoreFile(string id)
        {
            var item = QuarantineHistory.Find(x => x.Id == id);
            if (item != null)
            {
                try
                {
                    WhitelistedPaths.Add(item.OriginalPath);
                    File.Move(item.StoragePath, item.OriginalPath);
                    lock (QuarantineHistory) QuarantineHistory.Remove(item);
                    GenerateActionReport("RESTORED", item.OriginalPath, "Success");
                    SaveDatabase();
                }
                catch { }
            }
        }

        public static void BlockFile(string id)
        {
            var item = QuarantineHistory.Find(x => x.Id == id);
            if (item != null)
            {
                BlacklistedHashes.Add(item.FileHash);
                item.Status = "Blocked Forever";
                SaveDatabase();
            }
        }

        public static void UnblockFile(string id)
        {
            var item = QuarantineHistory.Find(x => x.Id == id);
            if (item != null)
            {
                BlacklistedHashes.Remove(item.FileHash);
                item.Status = "Quarantined";
                SaveDatabase();
            }
        }

        public static async Task SubmitForAnalysis(string id)
        {
            await PerformCloudAnalysisAsync(id);
        }

        public static void DeployTraps() { IsRansomwareActive = true; SaveDatabase(); }
        public static void RemoveTraps() { IsRansomwareActive = false; SaveDatabase(); }

        // ==========================================
        // 7. NEW ANALYSIS & HEALTH CHECK LOGIC
        // ==========================================

        public static HealthStatus GetSystemHealth()
        {
            var health = new HealthStatus { SecurityScore = 100, StatusLabel = "Secure", Recommendations = new List<string>() };

            // Logic 1: Real-Time Protection
            if (!IsActive)
            {
                health.SecurityScore -= 30;
                health.Recommendations.Add("Real-Time Protection is DISABLED. Turn it on in Protection settings.");
            }

            // Logic 2: Firewall
            if (!IsFirewallActive)
            {
                health.SecurityScore -= 20;
                health.Recommendations.Add("Firewall is OFF. Your network is vulnerable.");
            }

            // Logic 3: Ransomware
            if (!IsRansomwareActive)
            {
                health.SecurityScore -= 10;
                health.Recommendations.Add("Ransomware Traps are disabled. Enable them for extra safety.");
            }

            // Logic 4: Scan Frequency
            var lastScan = ScanLogHistory.OrderByDescending(x => x.CompletedAt).FirstOrDefault();
            if (lastScan == null || (DateTime.Now - lastScan.CompletedAt).TotalDays > 7)
            {
                health.SecurityScore -= 15;
                health.Recommendations.Add("You haven't scanned your PC in over 7 days. Run a Quick Scan.");
            }

            // Logic 5: Unresolved Threats
            var activeThreats = QuarantineHistory.Count(q => q.Status == "Quarantined");
            if (activeThreats > 0)
            {
                health.SecurityScore -= 5;
                health.Recommendations.Add($"You have {activeThreats} unresolved threats in Quarantine.");
            }

            if (health.SecurityScore < 0) health.SecurityScore = 0;

            if (health.SecurityScore < 50) health.StatusLabel = "Critical";
            else if (health.SecurityScore < 80) health.StatusLabel = "At Risk";

            if (health.Recommendations.Count == 0) health.Recommendations.Add("No issues found. Your system is healthy.");

            return health;
        }

        public static GraphData GetTrendAnalysis()
        {
            var data = new GraphData();
            // Get last 7 days
            for (int i = 6; i >= 0; i--)
            {
                var date = DateTime.Now.AddDays(-i).Date;
                data.Labels.Add(date.ToString("MMM dd"));

                // Count threats on that day
                int threats = QuarantineHistory.Count(x => x.DateCaptured.Date == date);
                data.Threats.Add(threats);

                // Count scans on that day
                int scans = ScanLogHistory.Count(x => x.CompletedAt.Date == date);
                data.Scans.Add(scans);
            }
            return data;
        }
    }
}