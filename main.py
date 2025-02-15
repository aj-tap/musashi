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
from collections import defaultdict
import json
from evtx import PyEvtxParser
import yaml
from sigma.processing.pipeline import ProcessingPipeline
from openai import OpenAI

import numpy as np
from sklearn.preprocessing import MinMaxScaler
from sklearn.ensemble import IsolationForest
import tensorflow as tf
from tensorflow import keras

MITRE_CACHE_FILE = "mitre_attack_mapping.json"

def flatten_json(nested_json, prefix=""):
    """
    Recursively flattens a nested JSON dictionary.
    """
    flattened = {}
    if isinstance(nested_json, dict):
        for key, value in nested_json.items():
            new_key = f"{prefix}{key}" if prefix else key
            if isinstance(value, dict):
                flattened.update(flatten_json(value, new_key + "_"))
            elif isinstance(value, list):
                # Convert list values to a comma-separated string
                flattened[new_key] = ", ".join(map(str, value))
            else:
                flattened[new_key] = value
    else:
        flattened[prefix] = nested_json
    return flattened

class Triage:
    def __init__(self, log_path, result_path, log_format, sigma_rule_path="sigma_rules/rules/windows/", openai_api=None):
        self.output_path = result_path
        self.log_path = log_path
        self.sigma_rule_path = sigma_rule_path
        self.superdb = SuperDBAPI()
        self.log_format = log_format
        self.log_summary = ""
        self.openai_api = openai_api
        
        # If the provided sigma_rule_path is a directory, append the pattern
        if os.path.isdir(sigma_rule_path):
            self.sigma_rule_path = os.path.join(sigma_rule_path, "**", "*.yml")
        else:
            self.sigma_rule_path = sigma_rule_path  # Assume it's already a valid pattern
        # Check if the path exists
        if not os.path.exists(sigma_rule_path):
            raise ValueError(f"Provided sigma_rule_path '{sigma_rule_path}' does not exist!")
        print(f"Using Sigma rules path: {self.sigma_rule_path}")

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
                df = self.clean_column_names(df)
            elif file_ext == ".tsv":
                df = pd.read_csv(self.log_path, sep="\t", low_memory=False)
                df = self.clean_column_names(df)
            elif file_ext == ".json":
                df = pd.read_json(self.log_path, low_memory=False)
                df = self.clean_column_names(df)
            elif file_ext == ".evtx":
                records_list = []
                parser = PyEvtxParser(self.log_path)
                for record in parser.records_json():  # Get JSON format records
                    event_id = record["event_record_id"]
                    timestamp = record["timestamp"]            
                    try:
                        # Load JSON from 'data' field
                        event_data = json.loads(record["data"])["Event"]
            
                        # Flatten the nested JSON structure dynamically
                        flattened_event = flatten_json(event_data)
                        
                        # Add Event Record ID and Timestamp
                        flattened_event["Event Record ID"] = event_id
                        flattened_event["Timestamp"] = timestamp
                        
                        records_list.append(flattened_event)
            
                    except json.JSONDecodeError:
                        print(f"Error decoding JSON for Event Record ID: {event_id}")
                df = pd.DataFrame(records_list)
            else:
                print("Unsupported file format. Only Evtx, CSV, TSV, and JSON are allowed.")
                return None
            
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=file_ext)
            if file_ext == ".json":
                df.to_json(temp_file.name, orient="records", lines=True)
            else:
                df.to_csv(temp_file.name, index=False, sep="\t" if file_ext == ".tsv" else ",")

            return temp_file.name  # Return the temp file path

        except Exception as e:
            print(f"Error in file processing: {e}")
            return None

    def get_mitre_tactic_mapping(self):
        """
        Retrieves MITRE ATT&CK technique-to-tactic mappings.
        - If cached, loads from local file.
        - Otherwise, downloads and saves for future use.
        
        Returns:
            dict: { "attack.t1036": ["Defense Evasion"], "attack.t1059.001": ["Execution"], ... }
        """
        if os.path.exists(MITRE_CACHE_FILE):
            with open(MITRE_CACHE_FILE, "r") as file:
                return json.load(file)
    
        print("[+] Downloading MITRE ATT&CK data...")
    
        import requests  # Only import if downloading
        url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
        response = requests.get(url)
        data = response.json()
    
        tactic_mapping = {}
    
        for obj in data["objects"]:
            if obj["type"] == "attack-pattern" and "external_references" in obj:
                for ref in obj["external_references"]:
                    if "external_id" in ref and ref["external_id"].startswith("T"):
                        technique_id = f"attack.{ref['external_id'].lower()}"
                        tactics = [phase["phase_name"].capitalize() for phase in obj.get("kill_chain_phases", [])]
                        tactic_mapping[technique_id] = tactics if tactics else ["Other"]
    
        # Save mapping locally
        with open(MITRE_CACHE_FILE, "w") as file:
            json.dump(tactic_mapping, file, indent=4)
    
        return tactic_mapping

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
        print(f"Extracted files to {local_dir}")

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
        #sigma_rule_files = glob.glob("./sigma_rules/rules/windows/**/*.yml", recursive=True)
        sigma_rule_files = glob.glob(self.sigma_rule_path, recursive=True)        
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
                    pipeline.apply(sigma_rule)
                elif self.log_format == "defender":
                    pipeline = microsoft_xdr_pipeline()
                    pipeline.apply(sigma_rule)
                elif self.log_format == "cortex":
                    pipeline = CortexXDR_pipeline()
                    pipeline.apply(sigma_rule)
                elif self.log_format == "carbonblackresponse":
                    pipeline = CarbonBlackResponse_pipeline()
                    pipeline.apply(sigma_rule)
                elif self.log_format == "carbonblack":
                    pipeline = CarbonBlack_pipeline()
                    pipeline.apply(sigma_rule)
                elif self.log_format == "winevtx":
                    # Load YAML file properly
                    with open("pipeline/windows_mapping_superdb.yml", "r") as f:
                        yaml_content = yaml.safe_load(f)  # Parses YAML into a Python dictionary
                    # Now pass the parsed YAML content
                    pipeline = ProcessingPipeline.from_dict(yaml_content)                                        
                    pipeline.apply(sigma_rule)
                else:
                    pipeline = None
                    
                converted_rule = superDBBackend().convert_rule(sigma_rule)
                
                loaded_count += 1  # Increment successful rule load counter
                return sigma_rule.title, converted_rule[0], sigma_rule.tags  # Return rule title & query
    
            except Exception as e:
                # print(f"Error processing rule {rule_file}: {e}")
                return None  # Failed rules are ignored in the count
    
        with ThreadPoolExecutor() as executor:
            results = list(executor.map(process_rule, sigma_rule_files))
    
        converted_rules = [res for res in results if res]
        
        print(f"Number of rules loaded: {loaded_count}")
        return converted_rules

    def perform_detections(self):
        """Executes queries in parallel, logs hits with rule titles, 
           saves individual results, and builds a MITRE ATT&CK timeline.
        """
        
        all_results = []
        rule_hit_count = Counter()  
        mitre_timeline = defaultdict(list)  # Stores MITRE techniques with detected rules
        
        print(f"\n=== Detections ===")
    
        def execute_query(query, rule_title, mitre_tags):
            fin_query = f"from logs | {query}"
            res = self.superdb.execute_query(query=fin_query)
    
            if res:
                df = pd.DataFrame(res)
                df["SigmaRule"] = rule_title  
    
                csv_output = os.path.join(self.output_path, f"{rule_title}.csv")
                df.to_csv(csv_output, index=False)
    
                all_results.append(df)  
                rule_hit_count[rule_title] = len(df)  
    
                # Log MITRE ATT&CK techniques
                for mitre in mitre_tags:
                    mitre_timeline[mitre].append(rule_title)
    
                print(f"Sigma Rule Triggered: - {rule_title}")
    
        queries = self.get_sigma_rules()  # Now returns (rule_title, query, mitre_tags)
    
        with ThreadPoolExecutor() as executor:
            executor.map(lambda q: execute_query(q[1], q[0], q[2]), queries)
    
        if all_results:
            merged_df = pd.concat(all_results, ignore_index=True)
            merged_output = os.path.join(self.output_path, "all-sigma-results.csv")
            merged_df.to_csv(merged_output, index=False)
            print(f"All sigma results merged and saved to {merged_output}")
            # Ingest the all result into superdb lake
            data = merged_df.to_csv(index=False)
            self.superdb.create_pool(name='sigmaresults', layout_order='asc', thresh=None)            
            response = self.superdb.load_data_to_branch('sigmaresults', 'main', data, csv_delim=',')
    
        if rule_hit_count:
            self.display_ascii_stats(rule_hit_count, mitre_timeline)

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
        print("\n=== Extracted IOCs Results ===")
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

    def display_ascii_stats(self, rule_hit_count, mitre_timeline):
        """
        Displays Sigma rule hit counts as a sorted ASCII table.
        Also categorizes MITRE ATT&CK detections under their respective tactics.
        Stores the results in `self.stats` in a compact format.
        """
        print("\n=== Sigma Detection Results Summary ===")
    
        # Sort results by hit count (descending)
        sorted_hits = sorted(rule_hit_count.items(), key=lambda x: x[1], reverse=True)
    
        # Get max values for scaling
        max_label_length = max(len(k) for k, _ in sorted_hits)
        max_count = max(v for _, v in sorted_hits)
    
        MAX_BAR_WIDTH = 50  # Normalize bar widths
    
        sigma_summary = []
        for rule, count in sorted_hits:
            bar_length = int((count / max_count) * MAX_BAR_WIDTH)
            bar = "█" * bar_length
            print(f"{rule.ljust(max_label_length)} | {bar} ({count})")
            sigma_summary.append(f"{rule}: {count}")  # Store for compact stats
    
        print("\n=== MITRE ATT&CK Detection Timeline ===")
    
        # Load MITRE ATT&CK mappings
        tactic_mapping = self.get_mitre_tactic_mapping()
    
        # Categorize detections
        tactic_grouped = defaultdict(lambda: defaultdict(list))
    
        for technique, rules in mitre_timeline.items():
            if not isinstance(technique, str):
                technique = str(technique)  # Convert to string if needed
            
            technique = technique.lower()  # Normalize
            tactics = tactic_mapping.get(technique)
            if not tactics:
                continue  # Skip unmapped techniques
            
            for tactic in tactics:
                tactic_grouped[tactic][technique].extend(rules)
    
        # Sort tactics by total detections
        sorted_tactics = sorted(
            tactic_grouped.items(),
            key=lambda x: sum(len(v) for v in x[1].values()),
            reverse=True
        )
    
        mitre_table = []
        mitre_summary = []
    
        for tactic, techniques in sorted_tactics:
            total_detections = sum(len(rules) for rules in techniques.values())
    
            # Sort techniques by detection count
            sorted_techniques = sorted(techniques.items(), key=lambda x: len(x[1]), reverse=True)
    
            for technique, rules in sorted_techniques:
                for rule in rules:
                    mitre_table.append([tactic.capitalize(), technique, rule])
                    mitre_summary.append(f"{tactic}>{technique}>{rule}")  # Store for compact stats
    
        if mitre_table:
            print("\n" + tabulate(mitre_table, headers=["Tactic", "Technique", "Rule"], tablefmt="grid"))
        else:
            print("No mapped MITRE ATT&CK detections.")
    
        # Store optimized stats string
        self.log_summary = f"Sigma: {', '.join(sigma_summary)} | MITRE: {', '.join(mitre_summary)}"    
        #print(self.log_summary) 

    def ai_hunt(self):
        client = OpenAI(api_key=self.openai_api)        
        completion = client.chat.completions.create(
            model="gpt-4o",
            store=True,
            messages=[
                {
                    "role": "user",
                    "content": f"""
            You are a Senior Analyst specializing in advanced threat hunting using large-scale log analysis.  
            
            ### Log Summary of Sigma Scan Results:  
            {self.log_summary}  
            
            ### Task:  
            1. Analyze the Sigma scan results and identify potential missed threats.  
            2. Generate a **concise Sigma rule in YAML format** to continue the hunt.  
            3. The generated Sigma rule will be **used directly for log searches**, so ensure it is:  
               - **Minimal but effective** (no excessive conditions).  
               - **Strictly formatted in YAML** (no explanations).
               - **Only include the following fields:**
                 - `title`                 
                 - `logsource`
                 - `detection`
               - **Do NOT include any unnecessary metadata.**  
               - **Do NOT wrap the output in triple backticks (` ```yaml `). Output plain YAML.**              
            ### **Output Format:**  
            - **YAML only** (No additional text, comments, or explanations).  
            - The rule must be **actionable and directly usable** in further log analysis.  
            """
                }
            ]
        )
    
        return completion.choices[0].message.content  # Returns only the YAML rule

    def perform_anomaly_detections(self):
        fin_query = f"from logs"
        res = self.superdb.execute_query(query=fin_query)
        data = pd.DataFrame(res)
        #data = pd.read_csv(self.log_path, low_memory=False)
        numeric_features = data.select_dtypes(include=['number'])
        if numeric_features.empty:
            raise ValueError("🚨 No numeric columns found! Ensure logs contain valid numeric data.")
        # Normalize data (MinMaxScaler is better for anomaly detection)
        scaler = MinMaxScaler()
        features_scaled = scaler.fit_transform(numeric_features)
        if np.isnan(features_scaled).any():
            print("NaN detected! Replacing with 0.")
            features_scaled = np.nan_to_num(features_scaled)  # Replace NaNs with 0
        model = keras.Sequential([
            keras.layers.Dense(32, activation='relu', input_shape=(features_scaled.shape[1],)),
            keras.layers.Dense(16, activation='relu'),
            keras.layers.Dense(8, activation='relu'),  # Bottleneck layer
            keras.layers.Dense(16, activation='relu'),
            keras.layers.Dense(32, activation='relu'),
            keras.layers.Dense(features_scaled.shape[1], activation='linear')
        ])
        model.compile(optimizer='adam', loss='mse')
        model.fit(features_scaled, features_scaled, epochs=10, batch_size=64, validation_split=0.1, verbose=1)
        reconstructions = model.predict(features_scaled)
        if np.isnan(reconstructions).any():
            raise ValueError("Autoencoder produced NaN values! Check data preprocessing.")
        mse = np.mean(np.abs(reconstructions - features_scaled), axis=1)
        if np.isnan(mse).any():
            raise ValueError("MSE calculation resulted in NaNs. Check input data.")
        threshold = np.percentile(mse, 90)
        data['Anomaly_Autoencoder'] = (mse > threshold).astype(int)
        # Step 2: Isolation Forest for Anomaly Detection
        iso_forest = IsolationForest(contamination=0.05, random_state=42)
        iso_forest.fit(features_scaled)
        iso_predictions = iso_forest.predict(features_scaled)
        data['Anomaly_IsolationForest'] = (iso_predictions == -1).astype(int)
        
        # Filter and save anomalies
        anomalies_autoencoder = data[data['Anomaly_Autoencoder'] == 1]
        anomalies_isolation = data[data['Anomaly_IsolationForest'] == 1]
        
        print("=== Anomalous Data (Autoencoder) ===\n", anomalies_autoencoder)
        print("=== Anomalous Data (Isolation Forest) ===\n", anomalies_isolation)
        
        anomalies_autoencoder_output = os.path.join(self.output_path, "anomalies_autoencoder.csv")
        anomalies_isolation_output = os.path.join(self.output_path, "anomalies_isolation_forest.csv")
        
        # Save anomalies to CSV
        anomalies_autoencoder.to_csv(anomalies_autoencoder_output, index=False)
        anomalies_isolation.to_csv(anomalies_isolation_output, index=False)

        self.superdb.create_pool(name='anomalies_isolation', layout_order='asc', thresh=None)        
        self.superdb.load_data_to_branch('anomalies_isolation', 'main', anomalies_isolation.to_csv(index=False), csv_delim=',')

        self.superdb.create_pool(name='anomalies_autoencoder', layout_order='asc', thresh=None)        
        self.superdb.load_data_to_branch('anomalies_autoencoder', 'main', anomalies_autoencoder.to_csv(index=False), csv_delim=',')
        
        print("Anomaly detection complete! Results saved at pool and lake. ")
    
    def perform_additional_detections(self):
        print("\n === AI Assistance Threat hunt ===")
        #print("\n Generated Sigma detection: ")
        sigma_generated = self.ai_hunt()
        print(sigma_generated)
        sigma_rule = SigmaRule.from_yaml(sigma_generated)
        backend = superDBBackend()        

        if self.log_format == "azure":
            pipeline = azure_monitor_pipeline()
            pipeline.apply(sigma_rule)
        elif self.log_format == "defender":
            pipeline = microsoft_xdr_pipeline()
            pipeline.apply(sigma_rule)
        elif self.log_format == "cortex":
            pipeline = CortexXDR_pipeline()
            pipeline.apply(sigma_rule)
        elif self.log_format == "carbonblackresponse":
            pipeline = CarbonBlackResponse_pipeline()
            pipeline.apply(sigma_rule)
        elif self.log_format == "carbonblack":
            pipeline = CarbonBlack_pipeline()
            pipeline.apply(sigma_rule)
        elif self.log_format == "winevtx":
            # Load YAML file properly
            with open("pipeline/windows_mapping_superdb.yml", "r") as f:
                yaml_content = yaml.safe_load(f)  # Parses YAML into a Python dictionary
            # Now pass the parsed YAML content
            pipeline = ProcessingPipeline.from_dict(yaml_content)                                        
            pipeline.apply(sigma_rule)
        else:
            pipeline = None
                
        converted_rule = superDBBackend().convert_rule(sigma_rule)                                            
        fin_query = f"from logs | {converted_rule[0]}"
        print("AI generated query rule: " + fin_query)
        res = self.superdb.execute_query(query=fin_query)
        print("AI Query Result: \n")
        print(res)
        if res:
            df = pd.DataFrame(res)
            df["SigmaRule"] = rule_title  
            csv_output = os.path.join(self.output_path, f"AI - {rule_title}.csv")
            df.to_csv(csv_output, index=False)                    

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
                self.perform_anomaly_detections()                
                if self.openai_api:
                    self.perform_additional_detections()                                       
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
    parser.add_argument("-s", "--sigma_rule_path", type=str, required=False, help="Set Sigma rules directory or file path (If no specific Sigma rules directory or file path is set, the default path is sigma_rules/rules/windows/)")
    parser.add_argument("-lf", "--log_format", type=str, required=False, help="Set input format (e.g., winevtx, azure, defender,  cortex, carbonblack)")
    parser.add_argument("-a", "--openai", type=str, required=False, help="Supply openai api key to perform additional detections")

    args = parser.parse_args()
 
    if args.input_path is None:
        parser.print_help(sys.stderr)
        print("\nPlease specify the log files directory")
        sys.exit(1)

    if args.log_format and args.input_path is not None:
        invoker.add_command(Triage(args.input_path, args.output_path, args.log_format, args.sigma_rule_path, args.openai))

    invoker.run()
