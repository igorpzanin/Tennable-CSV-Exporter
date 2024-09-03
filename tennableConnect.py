import csv
from tenable.sc import TenableSC
from datetime import datetime

# Authentication with Tenable.SC
HOST = 'YourHost'
USERNAME = 'YourUsername'
PASSWORD = 'YourPassword'

sc = TenableSC(HOST)
sc.login(USERNAME, PASSWORD)

# Function to convert timestamp to the format yyyy-mm-dd hh:mm
def formatar_data(timestamp):
    return datetime.fromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S')

# Function to retrieve filtered vulnerabilities
def obter_vulnerabilidades():
    vulnerabilidades = []

    # Severity codes
    SEVERITY_INFO = 0
    SEVERITY_LOW = 1
    SEVERITY_MEDIUM = 2
    SEVERITY_HIGH = 3
    SEVERITY_CRITICAL = 4

    query = {
        'tool': 'vulndetails',
        'filters': [
            ('pluginID', 'exists', None),
            ('severity', '!=', SEVERITY_INFO) 
        ],
        'sortField': 'severity',
        'sortDirection': 'desc'
    }

    try:
        response = sc.analysis.vulns(**query)
    except Exception as e:
        print(f"Erro ao obter vulnerabilidades: {e}")
        sc.logout()
        exit()


    # Add vulnerabilities to the result
    for vuln in response:
        plugin_id = vuln.get('pluginID')
        name = vuln.get('pluginName')
        severity = vuln.get('severity')
        vpr = vuln.get('vprScore') if vuln.get('vprScore') else 'N/A'
        discovered = formatar_data(vuln.get('firstSeen'))
        last_observed = formatar_data(vuln.get('lastSeen'))
        mitigated = vuln.get('hasBeenMitigated') if vuln.get('hasBeenMitigated') else 'N/A'
        dns_name = vuln.get('dnsName')  if vuln.get('dnsName') else 'N/A'
        ip_address = vuln.get('ip') if vuln.get('ip') else 'N/A'
        repository = vuln.get('repository') if vuln.get('repository') else 'N/A'

        vulnerabilidade = {
            'plugin_id': plugin_id,
            'name': name,
            'severity': severity,
            'vpr': vpr,
            'discovered': discovered,
            'last_observed': last_observed,
            'mitigated': mitigated,
            'dns_name': dns_name,
            'ip_address': ip_address,
            'repository': repository,
            
        }
        vulnerabilidades.append(vulnerabilidade)
    return vulnerabilidades

# Function to export to CSV
def exportar_para_csv(vulnerabilidades, arquivo_csv):
    with open(arquivo_csv, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=['plugin_id', 'name', 'severity', 'vpr', 'discovered', 'last_observed', 'mitigated', 'dns_name', 'ip_address', 'repository'])
        writer.writeheader()
        for vulnerabilidade in vulnerabilidades:
            writer.writerow(vulnerabilidade)

# Retrieving vulnerabilities and exporting to CSV
vulnerabilidades = obter_vulnerabilidades()
exportar_para_csv(vulnerabilidades, 'vulnerabilidades.csv')

print(f"Vulnerabilidades exportadas para 'vulnerabilidades.csv'")

# Logout Tenable.SC
sc.logout()