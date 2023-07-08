# Automatyzacja rozpoznawania podatności poprzez API

import requests
import os
import datetime
import PyPDF2
import re
from termcolor import colored


# Wyszukiwanie CVE IDs w plikach pdf (pliki z wynikami skanowania)
def find_cve_ids_in_pdf(file_path):
    cve_ids = []
    
    # Otwórz plik PDF
    with open(file_path, 'rb') as file:
        pdf_reader = PyPDF2.PdfReader(file)
        
        # Przejdź przez wszystkie strony pliku PDF
        for page_num in range(len(pdf_reader.pages)):
            page = pdf_reader.pages[page_num]
            page_text = page.extract_text()
            
            # Wyszukaj identyfikatory CVE za pomocą wyrażeń regularnych
            matches = re.findall(r'CVE-\d{4}-\d{4,7}', page_text)
            
            # Dodaj znalezione identyfikatory CVE do listy
            cve_ids.extend(matches)

    # Usuń duplikaty z listy identyfikatorów CVE
    cve_ids = list(set(cve_ids)) 
    
    return cve_ids


# Formatowanie daty
def format_date(date_string):
    parsed_date = datetime.datetime.strptime(date_string, "%Y-%m-%dT%H:%M:%S.%f")
    formatted_date = parsed_date.strftime("%d-%m-%Y")
    return formatted_date


# Pobieranie szczegółów podatności na podstawie identyfikatora CVE
def get_vulnerability_details(cve_id):
    base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    url = f'{base_url}?cveId={cve_id}'
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        cve_items = data['vulnerabilities']

        for cve_item in cve_items:
            cve_data = cve_item['cve']
            impact = cve_data['metrics']

            return cve_data, impact
        
    else:
        print('Failed to retrieve vulnerability information.')


# Wyświetlanie szczegółów podatności
def print_cve_details(cve_data, impact):
    cvss_v2 = None
    cvss_v30 = None
    cvss_v31 = None
    
    print((colored('CVE ID:\n', 'green')), cve_data['id'])
    print((colored('Source Identifier:\n', 'green')), cve_data['sourceIdentifier'])

    published_date = cve_data['published']
    formatted_published_date = format_date(published_date)
    print((colored('Published Date:\n', 'green')), formatted_published_date)
    modified_date = cve_data['lastModified']
    formatted_modified_date = format_date(modified_date)
    print((colored('Last Modified:\n', 'green')), formatted_modified_date)

    print((colored('Vulnerability Status:\n', 'green')), cve_data['vulnStatus'])
    print((colored('Description:\n', 'green')), cve_data['descriptions'][0]['value'])

    if 'weaknesses' in cve_data:
        print((colored('Weakness enumeration:\n', 'green')), cve_data['weaknesses'][0]['description'][0]['value'])

    # Sprawdź jakie wersje i jaki wynik CVSS posiada podatność
    if 'cvssMetricV2' in impact:
        cvss_v2 = impact['cvssMetricV2'][0]['cvssData']
        print((colored('CVSS v2 Score:\n', 'green')), cvss_v2['baseScore'])
    if 'cvssMetricV30' in impact:
        cvss_v30 = impact['cvssMetricV30'][0]['cvssData']
        print((colored('CVSS v3.0 Score:\n', 'green')), cvss_v30['baseScore'], cvss_v30['baseSeverity'])
    if 'cvssMetricV31' in impact:
        cvss_v31 = impact['cvssMetricV31'][0]['cvssData']
        print((colored('CVSS v3.1 Score:\n', 'green')), cvss_v31['baseScore'], cvss_v31['baseSeverity'])

    print('-' * 100)


# Skanowanie kilku podatności na podstawie identyfikatorów CVE
def scan_vulnerabilities(cve_ids):
    vulnerability_details = []

    for cve_id in cve_ids:
        details = get_vulnerability_details(cve_id)
        vulnerability_details.append(details)

    return vulnerability_details


# Zapisywanie informacji o podatnościach do pliku txt
def save_to_file(cve_data):
    file_name = input('Podaj nazwę pliku: ')
    file_path = f'{file_name}.txt'

    with open(file_path, 'w') as file:
        for cve, impact in cve_data:
            file.write('CVE ID: ' + cve['id'] + '\n')
            file.write('Source Identifier: ' + cve['sourceIdentifier'] + '\n')
            file.write('Published Date: ' + format_date(cve['published']) + '\n')
            file.write('Last Modified: ' + format_date(cve['lastModified']) + '\n')
            file.write('Vulnerability Status: ' + cve['vulnStatus'] + '\n')
            file.write('Description:\n' + cve['descriptions'][0]['value'] + '\n')

            if 'weaknesses' in cve:
                file.write('Weakness enumeration: ' + cve['weaknesses'][0]['description'][0]['value'] + '\n')

            if 'cvssMetricV2' in impact:
                cvss_v2 = impact['cvssMetricV2'][0]['cvssData']
                file.write('CVSS v2 Score: ' + str(cvss_v2['baseScore']) + '\n')

            if 'cvssMetricV30' in impact:
                cvss_v30 = impact['cvssMetricV30'][0]['cvssData']
                file.write('CVSS v3.0 Score: ' + str(cvss_v30['baseScore']) + ' ' + str(cvss_v30['baseSeverity']) + '\n')

            if 'cvssMetricV31' in impact:
                cvss_v31 = impact['cvssMetricV31'][0]['cvssData']
                file.write('CVSS v3.1 Score: ' + str(cvss_v31['baseScore']) + ' ' + str(cvss_v31['baseSeverity']) + '\n')

            file.write('\n')
            file.write('-' * 100)
            file.write('n')

    print(f'Information about vulnerabilities has been saved to a file: {file_path}')


# Funkcja menu
def menu():
    while True:
        print(colored('\n========== MENU ==========', 'yellow'))
        print('1. Find CVE IDs in PDF file')
        print('2. View information about a specific vulnerability')
        print('3. Exit')

        choice = input('Choose an option: ')

        # Wyszukiwanie identyfikatorów CVE w pliku PDF
        if choice == '1':
            os.system('cls' if os.name == 'nt' else 'clear')  # Czyszczenie ekranu
            pdf_file_path = input('Enter the path to the PDF file: ')
            try:
                cve_ids = find_cve_ids_in_pdf(pdf_file_path)
                print('CVE IDs found:', ', '.join(cve_ids))

                save_choice = input('Do you want to display information about vulnerabilities (V) or save to a file (S)? ')

                if save_choice.upper() == 'V':
                    cve_data = scan_vulnerabilities(cve_ids)
                    for details in cve_data:
                        print_cve_details(*details)
                elif save_choice.upper() == 'S':
                    cve_data = scan_vulnerabilities(cve_ids)
                    save_to_file(cve_data)
                else:
                    print('Invalid choice.')
            except FileNotFoundError:
                print('The specified path to the file is invalid.')
            except OSError as e:
                print('An error occurred while opening the file: ', str(e))

        # Wyswietlanie informacji o konkretnej podatności
        elif choice == '2':
            os.system('cls' if os.name == 'nt' else 'clear')
            cve_id = input('Enter the CVE ID: ')
            cve_data, impact = get_vulnerability_details(cve_id)
            print_cve_details(cve_data, impact)

        # Zakończenie programu
        elif choice == '3':
            break
        else:
            print('Invalid choice.')


menu()
