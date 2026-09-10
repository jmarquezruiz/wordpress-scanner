package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"
)

func outputDir() string {
	now := time.Now()
	return filepath.Join("wpscanner-output", now.Format("20060102-150405"))
}

func EnsureOutputDir() (string, error) {
	dir := outputDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("error creating output directory: %w", err)
	}
	return dir, nil
}

// DeduplicateFindings collapses repeated reports from the same scanner, file,
// and rule while preserving how many times the evidence was observed.
func DeduplicateFindings(findings []Finding) []Finding {
	result := make([]Finding, 0, len(findings))
	indexes := make(map[string]int)
	for _, finding := range findings {
		rule := finding.Rule
		if rule == "" {
			rule = finding.Indicator + "\x00" + finding.Description
		}
		key := finding.Scanner + "\x00" + finding.File + "\x00" + rule
		if index, ok := indexes[key]; ok {
			result[index].Occurrences++
			if result[index].Evidence != finding.Evidence && finding.Evidence != "" {
				result[index].Evidence += "\n" + finding.Evidence
			}
			continue
		}
		finding.Occurrences = 1
		indexes[key] = len(result)
		result = append(result, finding)
	}
	return result
}

func GenerateJSONReport(r Report, dir string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling report: %w", err)
	}
	path := filepath.Join(dir, "wpscanner-report.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("error writing report: %w", err)
	}
	return nil
}

func GenerateHTMLReport(r Report, dir string) error {
	data, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("error marshaling HTML data: %w", err)
	}

	const page = `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WordPress Scanner Report</title>
<style>
:root { color-scheme: dark; --bg:#101419; --panel:#181f27; --line:#2b3642; --text:#edf2f7; --muted:#9eabb8; --red:#ff647c; --orange:#ffb454; --blue:#6ca8ff; --green:#58d6a0; }
* { box-sizing:border-box; } body { margin:0; background:var(--bg); color:var(--text); font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif; }
main { max-width:1400px; margin:auto; padding:32px 20px 60px; } h1,h2 { margin:0 0 8px; } h1 { font-size:clamp(25px,4vw,42px); } h2 { font-size:20px; }
.muted { color:var(--muted); } .meta { margin:0 0 26px; color:var(--muted); overflow-wrap:anywhere; }
.cards,.charts { display:grid; gap:12px; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); margin:20px 0; }
.card,.panel { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:16px; } .card strong { display:block; font-size:28px; } .critical strong { color:var(--red); } .high strong { color:var(--orange); } .medium strong { color:var(--blue); } .low strong { color:var(--green); }
.chart { min-height:170px; } .bar { display:flex; align-items:center; gap:10px; margin:10px 0; } .bar label { width:150px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; } .track { background:#27313d; border-radius:99px; flex:1; height:12px; overflow:hidden; } .fill { background:linear-gradient(90deg,#6ca8ff,#58d6a0); height:100%; }
.toolbar { display:flex; flex-wrap:wrap; gap:10px; margin:12px 0; } input,select { background:#11171d; border:1px solid var(--line); border-radius:8px; color:var(--text); padding:10px; min-width:180px; }
.table-wrap { overflow:auto; } table { width:100%; border-collapse:collapse; min-width:900px; } th,td { border-bottom:1px solid var(--line); text-align:left; padding:10px 8px; vertical-align:top; } th { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; } td { overflow-wrap:anywhere; } .severity-critical { color:var(--red); font-weight:700; } .severity-high { color:var(--orange); font-weight:700; } .severity-medium { color:var(--blue); font-weight:700; } .severity-low { color:var(--green); font-weight:700; }
@media (max-width:650px) { main { padding:22px 12px 40px; } .card strong { font-size:23px; } }
</style>
</head>
<body><main>
<h1>WordPress Scanner</h1>
<p class="meta"><b>Objetivo:</b> <span id="target"></span><br><b>Fecha:</b> <span id="date"></span> · <b>Duracion:</b> <span id="elapsed"></span>s</p>
<section class="cards" id="cards"></section>
<section class="charts"><div class="panel chart"><h2>Por scanner</h2><div id="scanner-chart"></div></div><div class="panel chart"><h2>Por tipo</h2><div id="type-chart"></div></div></section>
<section class="panel"><h2>Hallazgos de archivos</h2><div class="toolbar"><input id="search" placeholder="Filtrar archivo o descripcion"><select id="severity"><option value="">Todas las severidades</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select><select id="scanner"><option value="">Todos los scanners</option></select></div><div class="table-wrap"><table><thead><tr><th>ID</th><th>Scanner</th><th>Archivo</th><th>Severidad</th><th>Confianza</th><th>Regla</th><th>Descripcion</th></tr></thead><tbody id="findings"></tbody></table></div></section>
<section class="panel" style="margin-top:20px"><h2>Hallazgos de base de datos</h2><div class="table-wrap"><table><thead><tr><th>ID</th><th>Categoria</th><th>Check</th><th>Severidad</th><th>Filas</th><th>Muestra</th></tr></thead><tbody id="db-findings"></tbody></table></div></section>
</main>
<script>
const report = {{.ReportJSON}};
const findings = report.findings || [];
const text = value => String(value ?? '');
const esc = value => text(value).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#39;');
document.getElementById('target').textContent = esc(report.meta.target_path);
document.getElementById('date').textContent = esc(report.meta.scan_date);
document.getElementById('elapsed').textContent = esc(report.meta.elapsed_seconds);
const cards = [['critical','Criticos'],['high','Altos'],['medium','Medios'],['low','Bajos'],['unique_files','Archivos unicos'],['evidence_count','Evidencias']];
document.getElementById('cards').innerHTML = cards.map(([key,label]) => '<div class="card '+key+'"><span class="muted">'+label+'</span><strong>'+esc(report.summary[key] || 0)+'</strong></div>').join('');
function counts(key) { return findings.reduce((out,f) => { const value = f[key] || 'Sin clasificar'; out[value] = (out[value] || 0) + 1; return out; }, {}); }
function renderChart(id, values) { const root = document.getElementById(id), entries = Object.entries(values).sort((a,b)=>b[1]-a[1]), max = Math.max(1,...entries.map(x=>x[1])); root.innerHTML = entries.length ? entries.map(([label,count]) => '<div class="bar"><label title="'+esc(label)+'">'+esc(label)+'</label><div class="track"><div class="fill" style="width:'+Math.round(count/max*100)+'%"></div></div><span>'+count+'</span></div>').join('') : '<p class="muted">Sin datos</p>'; }
renderChart('scanner-chart', counts('scanner')); renderChart('type-chart', counts('type'));
const scannerSelect = document.getElementById('scanner'); [...new Set(findings.map(f=>f.scanner))].sort().forEach(s => { const option=document.createElement('option'); option.value=s; option.textContent=s; scannerSelect.appendChild(option); });
function renderFindings() { const query=document.getElementById('search').value.toLowerCase(), severity=document.getElementById('severity').value, scanner=document.getElementById('scanner').value; const rows=findings.filter(f => (!severity || f.severity===severity) && (!scanner || f.scanner===scanner) && (!query || [f.file,f.description,f.rule].some(v=>text(v).toLowerCase().includes(query)))); document.getElementById('findings').innerHTML=rows.map(f => '<tr><td>'+esc(f.id)+'</td><td>'+esc(f.scanner)+'</td><td>'+esc(f.file)+'</td><td class="severity-'+esc(f.severity)+'">'+esc(f.severity)+'</td><td>'+esc(f.confidence)+'</td><td>'+esc(f.rule)+'</td><td>'+esc(f.description)+'</td></tr>').join('') || '<tr><td colspan="7" class="muted">Sin resultados</td></tr>'; }
['search','severity','scanner'].forEach(id => document.getElementById(id).addEventListener('input',renderFindings)); renderFindings();
document.getElementById('db-findings').innerHTML=(report.db_findings||[]).map(f => '<tr><td>'+esc(f.id)+'</td><td>'+esc(f.category)+'</td><td>'+esc(f.check)+'</td><td class="severity-'+esc(f.severity)+'">'+esc(f.severity)+'</td><td>'+esc(f.rows_affected)+'</td><td>'+esc(f.sample)+'</td></tr>').join('') || '<tr><td colspan="6" class="muted">Sin hallazgos</td></tr>';
</script></body></html>`

	tpl, err := template.New("report").Parse(page)
	if err != nil {
		return fmt.Errorf("error parsing HTML template: %w", err)
	}
	var rendered bytes.Buffer
	if err := tpl.Execute(&rendered, struct{ ReportJSON template.JS }{ReportJSON: template.JS(data)}); err != nil {
		return fmt.Errorf("error rendering HTML report: %w", err)
	}
	path := filepath.Join(dir, "wpscanner-report.html")
	if err := os.WriteFile(path, rendered.Bytes(), 0644); err != nil {
		return fmt.Errorf("error writing HTML report: %w", err)
	}
	return nil
}

func GenerateMDReport(r Report, dir string) error {
	path := filepath.Join(dir, "wpscanner-report.md")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintf(f, "# WordPress Scanner Report\n\n")
	fmt.Fprintf(f, "**Tool:** %s v%s\n", r.Meta.Tool, r.Meta.Version)
	fmt.Fprintf(f, "**Scan date:** %s\n", r.Meta.ScanDate)
	fmt.Fprintf(f, "**Target:** %s\n", r.Meta.TargetPath)
	if r.Meta.TargetDomain != "" {
		fmt.Fprintf(f, "**Domain:** %s\n", r.Meta.TargetDomain)
	}
	fmt.Fprintf(f, "**Elapsed:** %ds\n\n", r.Meta.ElapsedSeconds)

	fmt.Fprintf(f, "## Summary\n\n")
	fmt.Fprintf(f, "| Severity | Count |\n")
	fmt.Fprintf(f, "|----------|-------|\n")
	fmt.Fprintf(f, "| Critical | %d |\n", r.Summary.Critical)
	fmt.Fprintf(f, "| High | %d |\n", r.Summary.High)
	fmt.Fprintf(f, "| Medium | %d |\n", r.Summary.Medium)
	fmt.Fprintf(f, "| Low | %d |\n", r.Summary.Low)
	fmt.Fprintf(f, "| Unique files | %d |\n", r.Summary.UniqueFiles)
	fmt.Fprintf(f, "| Evidence count | %d |\n", r.Summary.EvidenceCount)
	fmt.Fprintf(f, "| Duplicate evidence | %d |\n", r.Summary.DuplicateFindings)
	fmt.Fprintf(f, "| **Total findings** | **%d** |\n", r.Summary.TotalFindings+r.Summary.DBFindings)
	fmt.Fprintln(f)

	if len(r.Findings) > 0 {
		fmt.Fprintf(f, "## File Findings\n\n")
		fmt.Fprintf(f, "| ID | Scanner | File | Severity | Confidence | Rule | Type | Description |\n")
		fmt.Fprintf(f, "|----|---------|------|----------|------------|------|------|-------------|\n")
		for _, fi := range r.Findings {
			fmt.Fprintf(f, "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
				fi.ID, fi.Scanner, fi.File, fi.Severity, fi.Confidence, fi.Rule, fi.Type, fi.Description)
		}
		fmt.Fprintln(f)
	}

	if len(r.DBFindings) > 0 {
		fmt.Fprintf(f, "## Database Findings\n\n")
		fmt.Fprintf(f, "| ID | Category | Check | Severity | Rows | Sample |\n")
		fmt.Fprintf(f, "|----|----------|-------|----------|------|--------|\n")
		for _, d := range r.DBFindings {
			fmt.Fprintf(f, "| %s | %s | %s | %s | %d | %s |\n",
				d.ID, d.Category, d.Check, d.Severity, d.RowsAffected, d.Sample)
		}
		fmt.Fprintln(f)
	}

	return nil
}
