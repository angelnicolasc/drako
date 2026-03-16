import subprocess
import sys
import json
from pathlib import Path

def main():
    bench_dir = Path(__file__).parent
    results_dir = bench_dir / "results"
    results_dir.mkdir(exist_ok=True)
    
    scripts = [
        "bench_policy_engine.py",
        "bench_discovery.py",
    ]
    
    for script in scripts:
        script_path = bench_dir / script
        print(f"\n{'='*50}\nExecuting {script}\n{'='*50}")
        try:
            subprocess.run([sys.executable, str(script_path)], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error running {script}: {e}")
            
    # Read results to generate markdown metrics and SVG
    pe_file = results_dir / "policy_engine.json"
    if pe_file.exists():
        with open(pe_file) as f:
            pe_data = json.load(f)
            
        # Get P50 from single policy evaluation
        p50_ms = pe_data.get("Single Policy", {}).get("p50_ms", 0)
        
        # Generate a naive SVG badge
        color = "#4c1" if p50_ms < 10 else "#e05d44"
        badge = f'''<svg xmlns="http://www.w3.org/2000/svg" width="130" height="20">
  <linearGradient id="b" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="a"><rect width="130" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#a)"><path fill="#555" d="M0 0h65v20H0z"/><path fill="{color}" d="M65 0h65v20H65z"/><path fill="url(#b)" d="M0 0h130v20H0z"/></g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="110">
    <text x="335" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="550">Policy Eval</text>
    <text x="335" y="140" transform="scale(.1)" textLength="550">Policy Eval</text>
    <text x="965" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="550">{p50_ms:.1f}ms</text>
    <text x="965" y="140" transform="scale(.1)" textLength="550">{p50_ms:.1f}ms</text>
  </g>
</svg>'''
        with open(results_dir / "policy_badge.svg", "w") as f:
            f.write(badge)
        print("\nGenerated SVG badge at results/policy_badge.svg")

if __name__ == "__main__":
    main()
