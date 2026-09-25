using System;
using System.IO;
using System.Text;

class Program
{
    static void Main()
    {
        var path = @"C:\Users\Jorge Ramos\Downloads\TDM-ORIGINAL-ZIP\TDM-v1.0-rc18.21.0-FIX93-CLEAN-R8-P1-P2-COMPILEFIX\src\TDM.Reporting\ReportExporter.cs";
        var fileContent = File.ReadAllText(path, Encoding.UTF8);

        // Add anchor and diff styles to CSS
        var oldCss = "@media print{body{background:#fff;color:#111}.card,.quick-card,.impact-item,.technical-bundle{background:#fff;border-color:#ccc;box-shadow:none}h1,h2,h3,.mono{color:#111}.muted,.report-sub,.quick-label,.support-meta,.compact-time{color:#555}th{color:#111}.technical-bundle{display:block}.technical-bundle>summary{color:#111}.technical-bundle:not([open])>:not(summary){display:none!important}}</style></head><body>";

        var newCss = "@media print{body{background:#fff;color:#111}.card,.quick-card,.impact-item,.technical-bundle{background:#fff;border-color:#ccc;box-shadow:none}h1,h2,h3,.mono{color:#111}.muted,.report-sub,.quick-label,.support-meta,.compact-time{color:#555}th{color:#111}.technical-bundle{display:block}.technical-bundle>summary{color:#111}.technical-bundle:not([open])>:not(summary){display:none!important}}\r\n.anchor-link{position:relative}.anchor-link::after{content:'#';position:absolute;right:-18px;top:0;color:#39d0ff;opacity:0;transition:opacity .2s;font-size:12px;text-decoration:none}.anchor-link:hover::after{opacity:1}h2 .anchor-link,h3 .anchor-link{color:inherit;text-decoration:none}.anchor-target{scroll-margin-top:80px}\r\n.diff-banner{background:#173a4a;border:1px solid #243247;border-radius:8px;padding:10px;margin:8px 0;color:#e6edf5}.diff-banner h3{margin:0 0 8px;color:#67d9ff}.diff-summary{font-size:13px;margin-bottom:8px}.diff-list{display:grid;gap:6px;max-height:300px;overflow:auto}.diff-item{background:#0d141e;border:1px solid #243247;border-radius:6px;padding:8px;font-size:12px}.diff-item.added{border-left:3px solid #67e8a5}.diff-item.removed{border-left:3px solid #ff8a3d}.diff-item.changed{border-left:3px solid #ffd166}.diff-item .cat{color:#39d0ff;font-weight:700}.diff-item .key{color:#e6edf5}.diff-item .kind{font-size:10px;text-transform:uppercase;padding:2px 6px;border-radius:3px}.diff-kind-added{background:#14532e;color:#67e8a5}.diff-kind-removed{background:#5c1a1a;color:#ff8a3d}.diff-kind-changed{background:#5c4a1a;color:#ffd166}.diff-item .summary{color:#b7c8d8;margin-top:4px}.diff-toggle{cursor:pointer;color:#67d9ff;background:none;border:none;font-size:12px;text-decoration:underline}.diff-toggle:hover{color:#39d0ff}</style></head><body>";

        var fileContent = File.ReadAllText(path, Encoding.UTF8);
        fileContent = fileContent.Replace(oldCssEnd, newCssEnd);
        File.WriteAllText(path, fileContent, Encoding.UTF8);
        Console.WriteLine("CSS Done");
    }
}