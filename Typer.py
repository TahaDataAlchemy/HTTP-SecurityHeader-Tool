import requests
import json
import typer
from pathlib import Path

app = typer.Typer()

def scan_for_security_header(input_file: str):
    """
    Scans domains from a text file for security headers and outputs the results to JSON and text files in the same directory as the input file.
    
    Args:
        input_file (str): Path to the input .txt file containing domain names.
    """
    try:
        input_path = Path(input_file)
        if not input_path.is_file() or input_path.suffix != '.txt':
            raise ValueError(f"Input file '{input_file}' must exist and be in .txt format")
        
        output_json = input_path.parent / "SecHeaderScan.json"
        output_txt = input_path.parent / "SecHeaderScan.txt"

        results = {"data": []}
        with input_path.open("r") as file:
            for line in file:
                domain = line.strip()
                if domain:
                    domain_result = {
                        "target": domain,
                        "status": False,
                        "headers": {
                            "Content-Security-Policy": None,
                            "X-Content-Type-Options": None,
                            "X-Frame-Options": None,
                            "X-XSS-Protection": None,
                            "Strict-Transport-Security": None,
                            "Referrer-Policy": None,
                            "Permissions-Policy": None,
                            "Cross-Origin-Embedder-Policy": None,
                            "Cross-Origin-Resource-Policy": None,
                        },
                    }
                    try:
                        response = requests.get(f"http://{domain}", timeout=10)
                        if response.status_code == 200:
                            print(f"Request Successful for {domain}")
                            domain_result["status"] = True
                            domain_result["headers"] = {
                                "Content-Security-Policy": response.headers.get("Content-Security-Policy"),
                                "X-Content-Type-Options": response.headers.get("X-Content-Type-Options"),
                                "X-Frame-Options": response.headers.get("X-Frame-Options"),
                                "X-XSS-Protection": response.headers.get("X-XSS-Protection"),
                                "Strict-Transport-Security": response.headers.get("Strict-Transport-Security"),
                                "Referrer-Policy": response.headers.get("Referrer-Policy"),
                                "Permissions-Policy": response.headers.get("Permissions-Policy"),
                                "Cross-Origin-Embedder-Policy": response.headers.get("Cross-Origin-Embedder-Policy"),
                                "Cross-Origin-Resource-Policy": response.headers.get("Cross-Origin-Resource-Policy"),
                            }
                        else:
                            print(f"Not Accessible: {domain} (Status Code: {response.status_code})")
                    except requests.exceptions.RequestException as e:
                        print(f"Failed to access {domain}: {e}")
                    
                    # Add the result for this domain
                    results["data"].append(domain_result)
        
        # Save results to a JSON file
        with open(output_json, "w") as json_file:
            json.dump(results, json_file, indent=4)
        print(f"Results saved to {output_json}")

        # Save results to a TXT file (replicating JSON structure)
        with open(output_txt, "w") as text_file:
            text_file.write(json.dumps(results, indent=4))
        print(f"Results saved to {output_txt}")

    except FileNotFoundError:
        print("Error: File does not exist")
    except ValueError as ve:
        print(f"Error: {ve}")

@app.command()
def main(input_file: str = typer.Argument("/home/op/input.txt", help="Input .txt file with domain names")):
    """
    CLI entry point for scanning security headers.

    Args:
        input_file (str): Input .txt file with domain names.
    """
    scan_for_security_header(input_file)

if __name__ == "__main__":
    app()
