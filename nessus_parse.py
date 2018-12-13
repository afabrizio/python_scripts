# Author: A. Fabrizio
# Purpose: This script takes a Nessus scan CSV file as an input and outputs...
#   - summary.csv
#   - critical.csv
#   - high.csv
#   - medium.csv
#   - mappings.json
# ...files. Content size is reduced by throwing out risk="None" and risk="Info" rows and mapping duplicate values to a hash table stored in <mappings.json>.
# Usage: $ python <path_to_file>
import csv
import json
import sys

file_path = sys.argv[1]
output = {
    0: 'Done.',
    1: 'Error opening file.',
    2: 'Error parsing the CSV file.',
    3: 'Error transforming input CSV file.'
}
# attempts to open the file at the provided path:
def main(file_path):
    try:
        scan_file = open(file_path, 'r') # open input file in read mode, line-buffered
        scan_reader = csv.reader(scan_file)
        medium_file = open('./sandbox/medium.csv', 'w', 1)
        medium_writer = csv.writer(medium_file)
        high_file = open('./sandbox/high.csv', 'w', 1)
        high_writer = csv.writer(high_file)
        critical_file = open('./sandbox/critical.csv', 'w', 1)
        critical_writer = csv.writer(critical_file)
        summary_file = open('./sandbox/summary.csv', 'w', 1)
        summary_writer = csv.writer(summary_file)
        mappings_file = open('./sandbox/mappings.json', 'w', 1)
    except IOError as e:
        print e
        return 1
    except NameError as e:
        print e
        return 3
    except:
        print sys.exc_info()[0]
    else:
        #row_count = sum(1 for row in csv_reader)
        #transformed_row_count = 0
        columns = None
        column_indicies = {
            'Plugin ID': None,
            'Plugin Output': None,
            'Risk': None,
            'Host': None,
            'Name': None,
            'Synopsis': None,
            'Description': None,
            'Solution': None,
        }
        compressed_column_indicies = []
        summary = {
            'Medium': {
                'count': 0,
                'hosts': {}
            },
            'High': {
                'count': 0,
                'hosts': {}
            },
            'Critical': {
                'count': 0,
                'hosts': {}
            }
        }
        mappings = {}
        for row in scan_reader:
            # extracts scan file headers and records each column index:
            if scan_reader.line_num == 1:
                columns = row
                compressed_column_indicies = [ row.index(header) for header in columns if header not in [ 'Risk', 'Name', 'Synopsis', 'Description', 'Solution' ] ]
                compressed_columns = [ columns[i] for i in compressed_column_indicies ]
                critical_writer.writerow(compressed_columns)
                high_writer.writerow(compressed_columns)
                medium_writer.writerow(compressed_columns)
                for key in column_indicies:
                    column_indicies[key] = columns.index(key)
            # for each CSV dataset row:
            else:
                # stores mapping for each "Plugin ID":
                if row[column_indicies['Risk']] in [ 'Critical', 'High', 'Medium' ]:
                    if row[column_indicies['Plugin ID']] not in mappings:
                       mappings[row[column_indicies['Plugin ID']]] = {
                           'Name': row[column_indicies['Name']],
                           'Synopsis': row[column_indicies['Synopsis']],
                           'Description': row[column_indicies['Description']],
                           'Plugin Output': row[column_indicies['Plugin Output']]
                        }
                # separates rows into separate files by risk level
                # AND records host summary counts:
                if row[column_indicies['Risk']] == 'Medium':
                    summary['Medium']['count'] += 1
                    if row[column_indicies['Host']] in summary['Medium']['hosts']:
                        summary['Medium']['hosts'][row[column_indicies['Host']]] += 1
                    else:
                        summary['Medium']['hosts'][row[column_indicies['Host']]] = 1
                    medium_writer.writerow([ row[i] for i in compressed_column_indicies ])
                elif row[column_indicies['Risk']] == 'High':
                    summary['High']['count'] += 1
                    if row[column_indicies['Host']] in summary['High']['hosts']:
                        summary['High']['hosts'][row[column_indicies['Host']]] += 1
                    else:
                        summary['High']['hosts'][row[column_indicies['Host']]] = 1
                    high_writer.writerow([ row[i] for i in compressed_column_indicies ])
                elif row[column_indicies['Risk']] == 'Critical':
                    summary['Critical']['count'] += 1
                    if row[column_indicies['Host']] in summary['Critical']['hosts']:
                        summary['Critical']['hosts'][row[column_indicies['Host']]] += 1
                    else:
                        summary['Critical']['hosts'][row[column_indicies['Host']]] = 1
                    critical_writer.writerow([ row[i] for i in compressed_column_indicies ])
                else:
                    pass
        # transforms summary hosts into a count and writes to summary.csv file:
        summary_writer.writerow([ 'count', 'risk', 'hosts' ])
        for key in summary:
            summary[key]['hosts'] = len(summary[key]['hosts'])
            summary_writer.writerow([ summary[key]['count'], key, summary[key]['hosts'] ])
        # converts mapping dict to JSON and writes to mappings.json file:
        mappings_file.write(json.dumps(mappings).replace('\\n', '\\\\n'))
        # cleans up:
        scan_file.close()
        medium_file.close()
        high_file.close()
        critical_file.close()
        summary_file.close()
        mappings_file.close()
        return 0


code = main(file_path)
print output[code]
sys.exit(code)
