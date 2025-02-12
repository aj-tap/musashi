import json
import requests

class Invoker(object):
    def __init__(self):
        self.commands = []

    def add_command(self, command):
        self.commands.append(command)

    def run(self):
        for command in self.commands:
            command.execute()

class SuperDBAPI:
    def __init__(self):
        self.base_url = "http://localhost:9867"      
        self.headers = {'Accept': 'application/json','Content-Type': 'application/json'}        

    def load_data_to_branch(self, pool_id_or_name, branch_name, data, csv_delim=',', content_type="text/csv"):
        """Loads data into a specified branch of the SuperDB pool."""
        url = f"{self.base_url}/pool/{pool_id_or_name}/branch/{branch_name}"
        headers = {
            'Content-Type': content_type,  # Set the correct Content-Type
            'Accept': 'application/json',
        }
        params = {'csv.delim': csv_delim}
    
        try:
            response = requests.post(url, headers=headers, params=params, data=data)
            response.raise_for_status()  # Raise an error for HTTP failures (4xx, 5xx)
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error loading data to branch: {e}")
            return None


    def get_branch_info(self, pool_id_or_name, branch_name):
        url = f"{self.base_url}/pool/{pool_id_or_name}/branch/{branch_name}"

        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()  # Raise an exception for 4XX or 5XX status codes
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error getting branch info: {e}")
            return None

    def delete_branch(self, pool_id_or_name, branch_name):
        url = f"{self.base_url}/pool/{pool_id_or_name}/branch/{branch_name}"

        try:
            response = requests.delete(url)
            response.raise_for_status()  # Raise an exception for 4XX or 5XX status codes
            if response.status_code == 204:
                print(f"Branch '{branch_name}' deleted successfully.")
            else:
                print(f"Unexpected response: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Error deleting branch: {e}")

    def delete_data_from_branch(self, pool_id_or_name, branch_name, object_ids=None, where=None):
        url = f"{self.base_url}/pool/{pool_id_or_name}/branch/{branch_name}/delete"
        payload = {}
        if object_ids:
            payload['object_ids'] = object_ids
        if where:
            payload['where'] = where

        try:
            response = requests.post(url, headers=self.headers, data=json.dumps(payload))
            response.raise_for_status()  # Raise an exception for 4XX or 5XX status codes
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error deleting data from branch: {e}")
            return None

    def merge_branches(self, pool_id_or_name, destination_branch, source_branch):
        url = f"{self.base_url}/pool/{pool_id_or_name}/branch/{destination_branch}/merge/{source_branch}"

        try:
            response = requests.post(url, headers=self.headers)
            response.raise_for_status()  # Raise an exception for 4XX or 5XX status codes
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error merging branches: {e}")
            return None

    def revert_commit(self, pool_id_or_name, branch_name, commit_id):
        url = f"{self.base_url}/pool/{pool_id_or_name}/branch/{branch_name}/revert/{commit_id}"

        try:
            response = requests.post(url, headers=self.headers)
            response.raise_for_status()  # Raise an exception for 4XX or 5XX status codes
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error reverting commit: {e}")
            return None

    def create_pool(self, name, layout_order='asc', layout_keys=[['ts']], thresh=None):
        url = f"{self.base_url}/pool"
        payload = {
            'name': name,
            'layout': {
                'order': layout_order,
                'keys': layout_keys
            }
        }
        if thresh is not None:
            payload['thresh'] = thresh

        try:
            response = requests.post(url, headers=self.headers, data=json.dumps(payload))
            response.raise_for_status()  # Raise an exception for 4XX or 5XX status codes
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error creating pool: {e}")
            return None

    def vacuum_pool(self, pool_id_or_name, revision, dryrun=False):
        url = f"{self.base_url}/pool/{pool_id_or_name}/revision/{revision}/vacuum"
        params = {
            'dryrun': 'T' if dryrun else 'F'
        }

        try:
            response = requests.post(url, headers=self.headers, params=params)
            response.raise_for_status()  # Raise an exception for 4XX or 5XX status codes

            if response.status_code == 200:
                data = response.json()
                if dryrun:
                    print("Objects that could be vacuumed:")
                    for obj in data.get('objects', []):
                        print(obj)
                else:
                    print("Pool vacuumed successfully.")
            else:
                print(f"Unexpected response: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Error vacuuming pool: {e}")

    def execute_query(self, query, pool=None, branch='main', ctrl='F'):
        url = f"{self.base_url}/query"
        params = {
            'ctrl': ctrl
        }
        payload = {
            'query': query
        }
        if pool:
            payload['head.pool'] = pool
        payload['head.branch'] = branch

        try:
            response = requests.post(url, headers=self.headers, params=params, data=json.dumps(payload))
            response.raise_for_status()  # Raise an exception for 4XX or 5XX status codes
            return response.json()
        except requests.exceptions.RequestException as e:
            #print(f"Error executing query: {e}")
            return None
    
