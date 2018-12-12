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
import sys

file_path = sys.argv[1]
output = {
    0: 'Success',
    1: 'Error opening file.',
    2: 'Error parsing the CSV file.',
    3: 'Error transforming input CSV file.'
}
# attempts to open the file at the provided path:
def main(file_path):
    try:
        scan_file = open(file_path, 'r') # open input file in read mode, line-buffered
        scan_reader = csv.reader(scan_file)
        # medium_file = open('./sandbox/medium.csv', 'w', 1)
        # high_file = open('./sandbox/high.csv', 'w', 1)
        critical_file = open('./sandbox/critical.csv', 'w', 1)
        critical_writer = csv.writer(critical_file)
        # mappings_json = open('./sandbox/mappings.json', 'w', 1)
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
        riskColumnIndex = 0
        for row in scan_reader:
            if scan_reader.line_num == 1:
                columns = row 
                critical_writer.writerow(row)
                riskColumnIndex = columns.index('Risk')
            else:
                if row[riskColumnIndex] == 'Critical':
                    critical_writer.writerow(row)
        scan_file.close()
        critical_file.close()
        return 0


code = main(file_path)
print output[code]
sys.exit(code)
