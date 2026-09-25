using System;
using System.IO;
using System.Text;

class Program
{
    static void Main()
    {
        var path = @"C:\Users\Jorge Ramos\Downloads\TDM-ORIGINAL-ZIP\TDM-v1.0-rc18.21.0-FIX93-CLEAN-R8-P1-P2-COMPILEFIX\src\TDM.Reporting\ReportExporter.cs";
        var content = File.ReadAllText(path, Encoding.UTF8);

        // Read new CSS from file
        var newCss = File.ReadAllText(@"C:\Users\Jorge Ramos\Downloads\TDM-ORIGINAL-ZIP\TDM-v1.0-rc18.21.0-FIX93-CLEAN-R8-P1-P2-COMPILEFIX\new_css.txt", Encoding.UTF8);

        var oldCss = "@media print{body{background:#fff;color:#111}.card,.quick-card,.impact-item,.technical-bundle{background:#fff;border-color:#ccc;box-shadow:none}h1,h2,h3,.mono{color:#111}.muted,.report-sub,.quick-label,.support-meta,.compact-time{color:#555}th{color:#111}.technical-bundle{display:block}.technical-bundle>summary{color:#111}.technical-bundle:not([open])>:not(summary){display:none!important}}</style></head><body>";

        var content = File.ReadAllText(path, Encoding.UTF8);
        content = content.Replace(oldCss, newCss);
        File.WriteAllText(path, content, Encoding.UTF8);
        Console.WriteLine("CSS Done");
    }
}