import yaml
import json
import argparse

# This script transforms the NetHSM API specification by adding the path parameters to each of the methods.
# This is to fix an issue with openapijsonschematools/openapi-json-schema-generator-cli that doesn't support
# common path parameters.



# read cli arguments
parser = argparse.ArgumentParser()
parser.add_argument("input_file", help="input file")
parser.add_argument("output_file", help="output file")
args = parser.parse_args()
input_file = args.input_file
output_file = args.output_file

data = None

# Read the YAML file
with open(input_file, 'r') as stream:
    try:
        data = yaml.safe_load(stream)
    except yaml.YAMLError as exc:
        print(exc)
        exit(1)

for path in data['paths']:
    path_data = data['paths'][path]

    if 'parameters' in path_data:
        parameters = path_data['parameters']

        for method in path_data:
            if method == 'parameters':
                continue
            method_data = path_data[method]

            # Add the parameters to the method
            if 'parameters' in method_data:
                method_data['parameters'] += parameters
            else:
                method_data['parameters'] = parameters

# Write the JSON file
with open(output_file, 'w') as stream:
    try:
        json.dump(data, stream, indent=2)
    except yaml.YAMLError as exc:
        print(exc)
        exit(1)
