using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using VaultWare.Shield.Models;
using System;
using System.Diagnostics;
using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.IO;
using System.Text.Json; // Added for Graph Data Serialization

namespace VaultWare.Shield.Controllers
{
    public class OptimizationResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string StatLabel { get; set; }
        public string StatValue { get; set; }
        public List<string> Details { get; set; }
    }

    public class HomeController : Controller
    {
        public HomeController()
        {
            try { SecurityEngine.Initialize(); } catch { }
        }

        public IActionResult Index()
        {
            ViewBag.Status = SecurityEngine.IsActive ? "ACTIVE" : "OFFLINE";
            ViewBag.Alert = SecurityEngine.LastAlert;
            ViewBag.Specs = "System Ready";

            var logs = SecurityEngine.AuditHistory != null
                ? SecurityEngine.AuditHistory.Where(x => x != null).OrderByDescending(x => x.Timestamp).Take(5).ToList()
                : new List<AuditItem>();
            return View(logs);
        }

        public IActionResult Toggle()
        {
            if (SecurityEngine.IsActive) SecurityEngine.StopProtection(); else SecurityEngine.StartProtection();
            return RedirectToAction("Index");
        }

        // *** UPDATED LOGIC TO SUPPORT CROSS-PLATFORM FIREWALL ***
        public IActionResult ToggleFeature(string feature)
        {
            switch (feature)
            {
                case "RealTime":
                    SecurityEngine.ToggleSystemFeature("RealTime", !SecurityEngine.IsActive);
                    break;
                case "Ransomware":
                    SecurityEngine.ToggleSystemFeature("Ransomware", !SecurityEngine.IsRansomwareActive);
                    break;
                case "Firewall":
                    SecurityEngine.ToggleSystemFeature("Firewall", !SecurityEngine.IsFirewallActive);
                    break;
                case "Web":
                    SecurityEngine.ToggleSystemFeature("Web", !SecurityEngine.IsWebActive);
                    break;
            }
            string referer = Request.Headers["Referer"].ToString();
            if (!string.IsNullOrEmpty(referer)) return Redirect(referer);
            return RedirectToAction("Settings");
        }

        public IActionResult Speed()
        {
            var history = SecurityEngine.AuditHistory
                .Where(x => x != null && x.Action == "OPTIMIZED")
                .OrderByDescending(x => x.Timestamp)
                .Take(10)
                .ToList();
            return View(history);
        }

        public IActionResult ClearSpeedLogs()
        {
            if (SecurityEngine.AuditHistory != null) SecurityEngine.AuditHistory.RemoveAll(x => x.Action == "OPTIMIZED");
            return RedirectToAction("Speed");
        }

        [HttpPost]
        public IActionResult PerformSpeedAction([FromQuery] string action)
        {
            var result = new OptimizationResult { Success = true, Details = new List<string>() };

            try
            {
                if (string.IsNullOrEmpty(action))
                {
                    result.Success = false;
                    result.Message = "Action parameter was empty.";
                    return Json(result);
                }

                if (action == "RAM")
                {
                    long before = Process.GetCurrentProcess().WorkingSet64;
                    SecurityEngine.OptimizeRam();
                    long after = Process.GetCurrentProcess().WorkingSet64;
                    long freed = (before - after) / 1024 / 1024;
                    if (freed < 0) freed = 0;

                    result.StatLabel = "RAM FREED";
                    result.StatValue = $"{freed} MB";
                    result.Message = "Memory optimized.";
                    result.Details.Add($"Start: {before / 1024 / 1024} MB");
                    result.Details.Add($"End: {after / 1024 / 1024} MB");
                }
                else if (action == "JUNK")
                {
                    int count = SecurityEngine.CleanSystemJunk();
                    result.StatLabel = "FILES DELETED";
                    result.StatValue = $"{count} FILES";
                    result.Message = "Junk files removed.";
                    if (count > 0) result.Details.Add("System Temp Cleaned");
                    else result.Details.Add("System is already clean.");
                }
                else if (action == "CACHE")
                {
                    string msg = SecurityEngine.ClearBrowserCache();
                    result.StatLabel = "CACHE ITEMS";
                    result.StatValue = msg.Replace(" Browser Files Removed", "").Replace("Browser Files Removed", "");
                    result.Message = "Browsers cleaned.";
                    result.Details.Add("Chrome/Edge/Firefox Cache");
                }
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = ex.Message;
            }

            return Json(result);
        }

        // ==========================================
        // FIXED UNIVERSAL GENERATOR (No Crashes)
        // ==========================================
        [HttpPost]
        public IActionResult GenerateTestData()
        {
            var results = new List<string>();

            // Helper function to safely write files without crashing the app
            void SafeCreateFile(string path, string content, string label)
            {
                try
                {
                    // 1. Clean up old file if it exists (force remove read-only if needed)
                    if (System.IO.File.Exists(path))
                    {
                        try
                        {
                            System.IO.File.SetAttributes(path, FileAttributes.Normal);
                            System.IO.File.Delete(path);
                        }
                        catch { /* Ignore delete errors */ }
                    }

                    // 2. Write the new file
                    System.IO.File.WriteAllText(path, content);
                    results.Add($"✅ Created: {label}");
                }
                catch (FileNotFoundException)
                {
                    // If file vanishes immediately, it means Real-Time Protection worked!
                    results.Add($"🛡️ {label} was detected and removed immediately! (Protection Active)");
                }
                catch (Exception ex)
                {
                    // If it fails (e.g., defender blocked it), log it but DO NOT CRASH
                    results.Add($"⚠️ Intercepted/Error ({label}): {ex.Message}");
                }
            }

            try
            {
                // 1. Get Paths & FIX MISSING FOLDERS
                string desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                string docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                string temp = Path.GetTempPath();

                // Fallback for missing Desktop
                if (string.IsNullOrEmpty(desktop) || !Directory.Exists(desktop))
                {
                    string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                    desktop = Path.Combine(home, "Desktop");
                }
                if (!Directory.Exists(desktop)) Directory.CreateDirectory(desktop);

                // Fallback for missing Documents
                if (string.IsNullOrEmpty(docs) || !Directory.Exists(docs))
                {
                    string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                    docs = Path.Combine(home, "Documents");
                }
                if (!Directory.Exists(docs)) Directory.CreateDirectory(docs);

                // --- GENERATION WITH SAFETY CHECKS ---

                // 2. Create EICAR (Desktop)
                string eicarPath = Path.Combine(desktop, "eicar_test_file.com");
                SafeCreateFile(eicarPath, @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", "EICAR Test File");

                // 3. Create Virus Simulation (Documents)
                string virusPath = Path.Combine(docs, "vaultware_test_virus.txt");
                SafeCreateFile(virusPath, "This is a simulated virus payload for VaultWare.", "Malware Simulation");

                // 4. Create Junk Files (Temp Folder)
                for (int i = 1; i <= 3; i++)
                {
                    string junkPath = Path.Combine(temp, $"vw_junk_{i}.tmp");
                    SafeCreateFile(junkPath, "Junk Data " + i, $"Junk File {i}");
                }

                // 5. Create Ransomware Bait (Desktop)
                string ransomPath = Path.Combine(desktop, "important_data.locked");
                SafeCreateFile(ransomPath, "Encrypted Data Simulation", "Ransomware Sim");

                return Json(new { success = true, message = "Simulation completed.", details = results });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = "Critical Error: " + ex.Message });
            }
        }

        public IActionResult Scan()
        {
            var logs = SecurityEngine.ScanLogHistory != null
                ? SecurityEngine.ScanLogHistory.Where(x => x != null).OrderByDescending(x => x.CompletedAt).ToList()
                : new List<ScanResult>();
            return View(logs);
        }

        public IActionResult CleanScanHistory()
        {
            if (SecurityEngine.ScanLogHistory != null) SecurityEngine.ScanLogHistory.Clear();
            return RedirectToAction("Scan");
        }

        [HttpPost]
        public IActionResult StartScan(string type, string customPath)
        {
            SecurityEngine.StartScan(type, customPath);
            return Json(new { success = true });
        }

        [HttpPost]
        public IActionResult StopScan()
        {
            SecurityEngine.StopScan();
            return Json(new { success = true });
        }

        [HttpGet]
        public IActionResult GetScanProgress()
        {
            return Json(new
            {
                isScanning = SecurityEngine.IsScanning,
                scanType = SecurityEngine.CurrentScanType,
                progress = SecurityEngine.ScanProgress,
                filesScanned = SecurityEngine.FilesScanned,
                currentFile = SecurityEngine.CurrentFile,
                duration = SecurityEngine.ScanDuration,
                threats = SecurityEngine.ThreatsFoundInScan
            });
        }

        public IActionResult Settings()
        {
            ViewBag.Whitelist = SecurityEngine.WhitelistedPaths.ToList();
            ViewBag.Blacklist = SecurityEngine.BlacklistedHashes.ToList();
            ViewBag.ReportPath = SecurityEngine.ReportsFolder;
            return View();
        }

        public IActionResult ClearCache()
        {
            SecurityEngine.ClearSystemCache();
            return RedirectToAction("Settings");
        }

        [HttpPost]
        public IActionResult UpdateReportLocation(string customPath)
        {
            if (!string.IsNullOrEmpty(customPath)) SecurityEngine.SetCustomReportPath(customPath);
            return RedirectToAction("Settings");
        }

        [HttpPost]
        public IActionResult AddWhitelist(string path)
        {
            SecurityEngine.AddToWhitelist(path);
            return RedirectToAction("Settings");
        }

        public IActionResult RemoveWhitelist(string path)
        {
            SecurityEngine.RemoveFromWhitelist(path);
            return RedirectToAction("Settings");
        }

        public IActionResult RemoveBlacklist(string hash)
        {
            SecurityEngine.UnbanHash(hash);
            return RedirectToAction("Settings");
        }

        [HttpPost]
        public IActionResult AddBlacklist(string hash)
        {
            if (!string.IsNullOrEmpty(hash)) SecurityEngine.ManualBanHash(hash);
            return RedirectToAction("Settings");
        }

        public IActionResult CleanHistory(int hours)
        {
            SecurityEngine.CleanLogs(hours);
            return RedirectToAction("Index");
        }

        public IActionResult Quarantine()
        {
            ViewBag.History = SecurityEngine.AuditHistory != null
                ? SecurityEngine.AuditHistory.Where(x => x != null).OrderByDescending(x => x.Timestamp).ToList()
                : new List<AuditItem>();

            var items = SecurityEngine.QuarantineHistory != null
                ? SecurityEngine.QuarantineHistory.Where(x => x != null).OrderByDescending(x => x.DateCaptured).ToList()
                : new List<QuarantineItem>();

            return View(items);
        }

        public IActionResult Restore(string id)
        {
            SecurityEngine.RestoreFile(id);
            return RedirectToAction("Quarantine");
        }

        public IActionResult Delete(string id)
        {
            SecurityEngine.DeleteFile(id);
            return RedirectToAction("Quarantine");
        }

        public IActionResult Block(string id)
        {
            SecurityEngine.BlockFile(id);
            return RedirectToAction("Quarantine");
        }

        public IActionResult Unblock(string id)
        {
            SecurityEngine.UnblockFile(id);
            return RedirectToAction("Quarantine");
        }

        public IActionResult Rescan(string id)
        {
            SecurityEngine.RescanFile(id);
            return RedirectToAction("Quarantine");
        }

        public IActionResult CancelAnalysis(string id)
        {
            SecurityEngine.CancelAnalysis(id);
            return RedirectToAction("Quarantine");
        }

        public async Task<IActionResult> Analyze(string id)
        {
            await SecurityEngine.PerformCloudAnalysisAsync(id);
            return RedirectToAction("Quarantine");
        }

        [HttpPost]
        public IActionResult AddFile(IFormFile file)
        {
            if (file != null)
            {
                try
                {
                    string temp = Path.GetTempFileName();
                    using (var s = new FileStream(temp, FileMode.Create)) { file.CopyTo(s); }
                    string dest = Path.Combine(Path.GetDirectoryName(temp), file.FileName);
                    if (System.IO.File.Exists(dest)) System.IO.File.Delete(dest);
                    System.IO.File.Move(temp, dest);
                    SecurityEngine.ManualAdd(dest);
                }
                catch { }
            }
            return RedirectToAction("Quarantine");
        }

        public IActionResult Protection()
        {
            return View();
        }

        [HttpGet]
        public IActionResult GetStatus()
        {
            bool t = SecurityEngine.AlertUnread;
            if (t) SecurityEngine.AlertUnread = false;
            return Json(new { isThreat = t, message = t ? $"THREAT: {SecurityEngine.LatestThreat}" : SecurityEngine.LastAlert });
        }

        // ==========================================
        // 8. NEW: SECURITY ADVISOR & GRAPHS
        // ==========================================

        public IActionResult Advisor()
        {
            // 1. Get Health Data
            var health = SecurityEngine.GetSystemHealth();

            // 2. Get Graph Data
            var graph = SecurityEngine.GetTrendAnalysis();

            // Pass graph data via ViewBag for Chart.js
            ViewBag.GraphLabels = JsonSerializer.Serialize(graph.Labels);
            ViewBag.GraphThreats = JsonSerializer.Serialize(graph.Threats);
            ViewBag.GraphScans = JsonSerializer.Serialize(graph.Scans);

            return View(health);
        }

        [HttpGet]
        public IActionResult GetDashboardData()
        {
            var analysis = SecurityEngine.GetTrendAnalysis();
            var health = SecurityEngine.GetSystemHealth();
            return Json(new { analysis = analysis, health = health });
        }

        // ... (Keep all your existing code above) ...

        // ==========================================
        // 9. NEW: REPORT VIEWER
        // ==========================================

        public IActionResult Reports()
        {
            // Ensure folder exists
            if (!Directory.Exists(SecurityEngine.ReportsFolder))
            {
                Directory.CreateDirectory(SecurityEngine.ReportsFolder);
            }

            // Get all .txt files, ordered by newest first
            var dirInfo = new DirectoryInfo(SecurityEngine.ReportsFolder);
            var files = dirInfo.GetFiles("*.txt")
                               .OrderByDescending(f => f.CreationTime)
                               .ToList();

            return View(files);
        }

        public IActionResult ViewReport(string id)
        {
            if (string.IsNullOrEmpty(id)) return RedirectToAction("Reports");

            // SECURITY: Prevent path traversal (e.g., "../windows/system32")
            string cleanName = Path.GetFileName(id);
            string fullPath = Path.Combine(SecurityEngine.ReportsFolder, cleanName);

            if (!System.IO.File.Exists(fullPath))
            {
                return RedirectToAction("Reports");
            }

            string content = System.IO.File.ReadAllText(fullPath);
            ViewBag.FileName = cleanName;
            ViewBag.Content = content;

            return View();
        }

        public IActionResult DeleteReport(string id)
        {
            if (!string.IsNullOrEmpty(id))
            {
                string cleanName = Path.GetFileName(id);
                string fullPath = Path.Combine(SecurityEngine.ReportsFolder, cleanName);
                try
                {
                    if (System.IO.File.Exists(fullPath)) System.IO.File.Delete(fullPath);
                }
                catch { }
            }
            return RedirectToAction("Reports");
        }
    }
}