#!/usr/bin/env python3
import pyfiglet
import argparse
import glob
import sys
import subprocess
import os
from sigma.rule import SigmaRule
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
from sigma.pipelines.azuremonitor import azure_monitor_pipeline
from sigma.pipelines.carbonblack import CarbonBlack_pipeline, CarbonBlackResponse_pipeline
from sigma.pipelines.cortexxdr import CortexXDR_pipeline
from util import *
from superdb import superDBBackend
from concurrent.futures import ThreadPoolExecutor  # Corrected import
import shutil
import time
from tabulate import tabulate
from collections import Counter
import pandas as pd
import tempfile
import zipfile
import re


class Triage:
    def __init__(self, log_path, result_path, log_format):
        self.output_path = result_path
        self.log_path = log_path
        self.superdb = SuperDBAPI()
        self.log_format = log_format

    def clean_column_names(self, df):
        """Removes spaces from column names."""
        df.columns = df.columns.str.replace(" ", "")
        return df

    def load_and_clean_file(self):
        """Loads, cleans, and returns the temporary file path based on file type."""
        try:
            file_ext = os.path.splitext(self.log_path)[-1].lower()
            
            if file_ext == ".csv":
                df = pd.read_csv(self.log_path, low_memory=False)
            elif file_ext == ".tsv":
                df = pd.read_csv(self.log_path, sep="\t", low_memory=False)
            elif file_ext == ".json":
                df = pd.read_json(self.log_path, low_memory=False)
            else:
                print("Unsupported file format. Only CSV, TSV, and JSON are allowed.")
                return None

            df = self.clean_column_names(df)

            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=file_ext)
            if file_ext == ".json":
                df.to_json(temp_file.name, orient="records", lines=True)
            else:
                df.to_csv(temp_file.name, index=False, sep="\t" if file_ext == ".tsv" else ",")

            return temp_file.name  # Return the temp file path

        except Exception as e:
            print(f"Error in file processing: {e}")
            return None

    def update_sigma_rules(self):
        """Check for updates, download, and extract the latest Sigma rules only if needed."""
        github_releases_api = "https://api.github.com/repos/SigmaHQ/sigma/releases/latest"
        local_dir = "sigma_rules"
        zip_file = "sigma_rules_latest.zip"
        version_file = "sigma_rules_version.txt"

        # Step 1: Get the latest release version
        response = requests.get(github_releases_api, headers={"Accept": "application/vnd.github.v3+json"})
        if response.status_code != 200:
            print("❌ Error: Could not fetch release data.")
            return

        release_data = response.json()
        latest_version = release_data.get("tag_name", "unknown")

        # Step 2: Check if we already have this version
        if os.path.exists(version_file):
            with open(version_file, "r") as f:
                current_version = f.read().strip()
            if current_version == latest_version:
                print(f"Sigma Rules Already up to date! (Version {latest_version})")
                return  # Exit if already updated

        # Step 3: Find the latest ZIP file
        zip_url = None
        for asset in release_data.get("assets", []):
            if asset["name"].endswith(".zip"):
                zip_url = asset["browser_download_url"]
                print(f"New version {latest_version} found: {asset['name']}")
                break

        if not zip_url:
            print("❌ Error: No ZIP file found in latest release.")
            return

        # Step 4: Download the ZIP file
        response = requests.get(zip_url, stream=True)
        if response.status_code != 200:
            print(f"❌ Error: Failed to download {zip_url}")
            return

        with open(zip_file, "wb") as file:
            for chunk in response.iter_content(1024):
                file.write(chunk)
        print(f"Downloaded: {zip_file}")

        # Step 5: Remove old files and extract new ones
        if os.path.exists(local_dir):
            shutil.rmtree(local_dir)
            print(f"🗑️ Deleted old files in {local_dir}")

        os.makedirs(local_dir, exist_ok=True)
        with zipfile.ZipFile(zip_file, "r") as zip_ref:
            zip_ref.extractall(local_dir)
        print(f"📂 Extracted files to {local_dir}")

        # Step 6: Save the new version number
        with open(version_file, "w") as f:
            f.write(latest_version)
        print(f"💾 Updated version info: {latest_version}")

        # Step 7: Clean up ZIP file
        os.remove(zip_file)
        print("🚀 Update completed!")

    def ingest_data(self, cleaned_file_path, format="csv"):
        """Ingests the cleaned CSV data into the SuperDB lake."""
        try:
            df = pd.read_csv(cleaned_file_path, low_memory=False)
            if df.empty:
                print("Error: The CSV file is empty. No data to ingest.")
                return

            self.superdb.create_pool(name='logs', layout_order='asc', layout_keys=[['EventTime']], thresh=None)

            data = df.to_csv(index=False) if format == "csv" else df.to_json(orient="records")
            response = self.superdb.load_data_to_branch('logs', 'main', data, csv_delim=',')

            print("Data successfully ingested into SuperDB." if response else "Failed to ingest data.")
        except Exception as e:
            print(f"Error in ingest_data: {e}")

    def get_sigma_rules(self):
        """Loads and converts Sigma rules in parallel."""
        sigma_rule_files = glob.glob("./sigma_rules/rules/windows/**/*.yml", recursive=True)
        converted_rules = []
        loaded_count = 0  # Counter for successfully loaded rules
    
        def process_rule(rule_file):
            nonlocal loaded_count
            try:
                with open(rule_file, "r") as f:
                    sigma_rule_yaml = f.read()
                sigma_rule = SigmaRule.from_yaml(sigma_rule_yaml)
    
                if self.log_format == "azure":
                    pipeline = azure_monitor_pipeline()
                elif self.log_format == "defender":
                    pipeline = microsoft_xdr_pipeline()
                elif self.log_format == "cortex":
                    pipeline = CortexXDR_pipeline()
                elif self.log_format == "carbonblackresponse":
                    pipeline = CarbonBlackResponse_pipeline()
                elif self.log_format == "carbonblack":
                    pipeline = CarbonBlack_pipeline()
                else:
                    pipeline = None
    
                pipeline.apply(sigma_rule)
                converted_rule = superDBBackend().convert_rule(sigma_rule)
                
                loaded_count += 1  # Increment successful rule load counter
                return sigma_rule.title, converted_rule[0]  # Return rule title & query
    
            except Exception as e:
                # print(f"Error processing rule {rule_file}: {e}")
                return None  # Failed rules are ignored in the count
    
        with ThreadPoolExecutor() as executor:
            results = list(executor.map(process_rule, sigma_rule_files))
    
        converted_rules = [res for res in results if res]
        
        print(f"Number of rules loaded: {loaded_count}")
        return converted_rules

    def perform_detections(self):
        """Executes queries in parallel, logs hits with rule titles, saves individual results, and merges all results."""
        
        all_results = []
        rule_hit_count = Counter()  
        print(f"=== Detections ===")

        def execute_query(query, rule_title):
            fin_query = f"from logs | {query}"
            res = self.superdb.execute_query(query=fin_query)
    
            if res:
                df = pd.DataFrame(res)
                df["SigmaRule"] = rule_title  
    
                csv_output = os.path.join(self.output_path, f"{rule_title}.csv")
                df.to_csv(csv_output, index=False)
    
                all_results.append(df)  
                rule_hit_count[rule_title] = len(df)  
    
                print(f"Sigma Rule Triggered: - {rule_title}")
    
        queries = self.get_sigma_rules()
    
        with ThreadPoolExecutor() as executor:
            executor.map(lambda q: execute_query(q[1], q[0]), queries)
    
        if all_results:
            merged_df = pd.concat(all_results, ignore_index=True)
            merged_output = os.path.join(self.output_path, "sigma.csv")
            merged_df.to_csv(merged_output, index=False)
            print(f"All sigma results merged and saved to {merged_output}")

        if rule_hit_count:
            self.display_ascii_stats(rule_hit_count)

    def extract_iocs_from_text(self, text):
        """Extract unique IOCs (Indicators of Compromise) from a given text using regex."""

        # Regular expressions for different IOCs
        regex_patterns = {
            "ipv4": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
            "urls": r"https?://[^\s\"\'<>]+",
            "registry_keys": r"\bHKEY_[A-Z_]+\\(?:[A-Za-z0-9_-]+\\?)+\b",  # Windows Registry paths
            "emails": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "file_paths": r"\b[a-zA-Z]:(\\[^<>:\"/|?*]+)+\b|\b\/(?:[^<>:\"|?*]+\/)+[^<>:\"|?*]+\b",  # Windows & Linux file paths
            "hashes": r"\b[a-fA-F0-9]{32,64}\b"  # MD5, SHA1, SHA256
        }

        extracted_iocs = {}

        # Extract IOCs using regex
        for key, pattern in regex_patterns.items():
            matches = re.findall(pattern, text)
            extracted_iocs[key] = list(set(matches))  # Remove duplicates

        return extracted_iocs

    def extract_iocs(self):
        print("=== Extracted IOCs Results ===")
        query = f"from logs"
        res = self.superdb.execute_query(query=query)
        if isinstance(res, list):
            text = "\n".join(map(str, res))  # Convert list of logs to a single text string
        else:
            text = str(res)  # Ensure it's a string

        iocs = self.extract_iocs_from_text(text)
        # Convert extracted IOCs into a DataFrame
        max_length = max(len(v) for v in iocs.values())  # Find max number of IOCs in a category
        data = {key: values + [''] * (max_length - len(values)) for key, values in iocs.items()}  # Pad shorter lists
        df = pd.DataFrame(data)        
        iocs_output = os.path.join(self.output_path, "iocs.csv")
        df.to_csv(iocs_output, index=False)

        for key, values in iocs.items():
            #print(f"{key.upper()} ({len(values)}): {values[:5]}...")  # Print first 5 samples
            print(f"{key.upper()}: ({len(values)})") 

    def display_ascii_stats(self, rule_hit_count):
        """Displays hit counts as a sorted ASCII table and normalized bar chart."""
        
        print("\n=== Sigma Detection Results Summary ===")

        # Sort results by hit count (descending)
        sorted_hits = sorted(rule_hit_count.items(), key=lambda x: x[1], reverse=True)

        # Get max values for scaling
        max_label_length = max(len(k) for k, _ in sorted_hits)  
        max_count = max(v for _, v in sorted_hits)  

        # Normalize bars (avoid one rule dominating the chart)
        MAX_BAR_WIDTH = 50  # Set a max width for the longest bar

        for rule, count in sorted_hits:
            bar_length = int((count / max_count) * MAX_BAR_WIDTH)
            bar = "█" * bar_length  # Use solid blocks for a cleaner look
            print(f"{rule.ljust(max_label_length)} | {bar} ({count})")

        # Print sorted table summary
        print("\n" + tabulate(sorted_hits, headers=["SigmaRule", "Hits"], tablefmt="grid"))

    def init_lake(self):
        """Initializes the data lake using Zed commands."""
        try:
            print("Initializing the lake...")
    
            # Ensure we are in the correct directory
            script_dir = os.path.dirname(os.path.abspath(__file__))
            os.chdir(script_dir)
    
            # Remove datalake/ if it exists
            if os.path.exists("datalake"):
                print("Removing existing datalake/ directory...")
                shutil.rmtree("datalake")
    
            # Run the Zed init command
            subprocess.run(["./bin/zed", "init", "-lake", "datalake"], check=True)
    
            # Ensure no other Zed servers are running
            subprocess.run("pkill -f 'zed serve'", shell=True, stderr=subprocess.DEVNULL)
    
            # Start Zed server in the background and fully detach it
            server_process = subprocess.Popen(
                "nohup ./bin/zed serve -lake datalake > superdb.log 2>&1 &",
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL
            )
    
            # Give some time for the server to start
            time.sleep(3)
    
            print("Lake initialized and server started.")
            return server_process  # Return the process for potential management
        except subprocess.CalledProcessError as e:
            print(f"Error in init_lake: {e}")
        except Exception as e:
            print(f"Unexpected error in init_lake: {e}")

    def execute(self):
        """Executes the process step by step."""
        print("Starting the triage process...")
        #cleaned_file = self.csv_validator(self.log_path)
        cleaned_file = self.load_and_clean_file()
        if cleaned_file:
            try:
                self.update_sigma_rules()
                self.init_lake()
                self.ingest_data(cleaned_file)
                self.extract_iocs()
                self.perform_detections()
                print("Triage completed successfully.")
            finally:
                os.remove(cleaned_file)                
        else:
            print("Process halted due to errors in CSV validation.")

if __name__ == "__main__":
    invoker = Invoker()
    banner = pyfiglet.figlet_format("Musashi \n", 'slant')
    print(banner)
    parser = argparse.ArgumentParser(prog='Musashi: ', description="Musashi Sigma-Detection Logs & Rapid Triage Tool")
    parser.add_argument("-i", "--input_path", required=True, type=str, help="Set log directory")
    parser.add_argument("-o", "--output_path", type=str, required=True, help="Set output directory results")
    parser.add_argument("-lf", "--log_format", type=str, required=True, help="Set input format (e.g., azure, defender,  cortex, carbonblack)")

    args = parser.parse_args()
 
    if args.input_path is None:
        parser.print_help(sys.stderr)
        print("\nPlease specify the log files directory")
        sys.exit(1)

    if args.log_format and args.input_path is not None:
        invoker.add_command(Triage(args.input_path, args.output_path, args.log_format))

    invoker.run()
