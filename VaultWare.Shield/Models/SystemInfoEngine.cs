using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace VaultWare.Shield.Models
{
    public class DeviceSpecs
    {
        public string HostName { get; set; }
        public string OSName { get; set; }
        public string OSArchitecture { get; set; }
        public string Processor { get; set; }
        public int CoreCount { get; set; }
        public string TotalRAM { get; set; }
        public string PrimaryDrive { get; set; }
        public string FreeSpace { get; set; }
        public string AgentVersion { get; set; } = "1.0.0 (Research Build)";
    }

    public static class SystemInfoEngine
    {
        public static DeviceSpecs GetSystemDetails()
        {
            var specs = new DeviceSpecs
            {
                HostName = Environment.MachineName,
                OSName = RuntimeInformation.OSDescription,
                OSArchitecture = RuntimeInformation.OSArchitecture.ToString(),
                CoreCount = Environment.ProcessorCount,
                Processor = "Generic / Virtual CPU" // Getting exact CPU name cross-platform is complex, this is a safe placeholder
            };

            // 1. CROSS-PLATFORM DISK INFO
            try
            {
                // Finds the drive where the OS is installed
                var systemDrive = DriveInfo.GetDrives()
                    .OrderByDescending(d => d.TotalSize)
                    .FirstOrDefault(d => d.IsReady);

                if (systemDrive != null)
                {
                    specs.PrimaryDrive = systemDrive.Name;
                    specs.FreeSpace = FormatBytes(systemDrive.AvailableFreeSpace);
                }
            }
            catch { specs.PrimaryDrive = "Unknown"; }

            // 2. RAM INFO (Safe Cross-Platform Estimation)
            // Note: Getting exact physical RAM requires OS-specific calls (WMI for Windows, /proc/meminfo for Linux)
            // This grabs the memory available to the app, which is a good proxy for "Total RAM" in a quick implementation
            long estimatedRam = Process.GetCurrentProcess().WorkingSet64;
            // For a thesis display, we can simulate the "Total" based on environment (or use a library)
            // But here is a trick to show "Usable" memory:
            specs.TotalRAM = FormatBytes(GC.GetGCMemoryInfo().TotalAvailableMemoryBytes);

            return specs;
        }

        private static string FormatBytes(long bytes)
        {
            string[] suffixes = { "B", "KB", "MB", "GB", "TB" };
            int counter = 0;
            decimal number = (decimal)bytes;
            while (Math.Round(number / 1024) >= 1)
            {
                number = number / 1024;
                counter++;
            }
            return string.Format("{0:n1} {1}", number, suffixes[counter]);
        }
    }
}