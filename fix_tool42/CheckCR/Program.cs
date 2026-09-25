using System;
using System.IO;

class Program
{
    static void Main()
    {
        var path = @"C:\Users\Jorge Ramos\Downloads\TDM-ORIGINAL-ZIP\TDM-v1.0-rc18.21.0-FIX93-CLEAN-R8-P1-P2-COMPILEFIX\src\TDM.Reporting\ReportExporter.cs";
        var bytes = File.ReadAllBytes(path);
        for (int i = 0; i < bytes.Length; i++)
        {
            if (bytes[i] == 13) // CR character
            {
                var start = Math.Max(0, i - 10);
                var end = Math.Min(bytes.Length, i + 10);
                var context = string.Join(" ", bytes.Skip(start).Take(end - start).Select(b => b.ToString("X2")));
                Console.WriteLine($"CR at {i}: {context}");
            }
        }
    }
}