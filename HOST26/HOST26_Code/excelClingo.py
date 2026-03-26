import itertools
import glob
import clingo
import logging
import re
from datetime import datetime
import os
import openpyxl
from openpyxl import Workbook

# Function to set up logging to output to a uniquely named file
def setup_logging():
    # Determine the next available log file number
    existing_files = glob.glob("optimization_results_*.txt")
    numbers = [
        int(re.search(r'optimization_results_(\d+).txt', f).group(1))
        for f in existing_files if re.search(r'optimization_results_(\d+).txt', f)
    ]
    next_number = max(numbers, default=0) + 1
    log_filename = f'optimization_results_{next_number}.txt'
    # Configure logging
    logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(message)s')
    return log_filename

# List of optimization programs to run together
optimization_programs = [
    "Clingo/init_enc.lp",
    "Clingo/opt_latency_enc.lp",
    "Clingo/opt_power_enc.lp",
    "Clingo/opt_resource_enc.lp",
    "Clingo/opt_security_enc.lp",
    "Clingo/security_features_inst.lp",
    "Clingo/tgt_system_inst1.lp",
    "Clingo/usr_constraints_inst.lp",
]

# Attributes to record
attributes = [
    "total_asset_bram", "total_asset_bufg", "total_asset_dsps", "total_asset_lutram",
    "total_base_bufg", "total_bufg_used", "total_component_bram", "total_component_bufg",
    "total_component_dsps", "total_component_lutram", "bram_used_by_component",
    "bufg_used_by_component", "dsps_used_by_component", "lutram_used_by_component",
    "selected_logging", "selected_security", "register_risk_fact", "asset_latency",
    "total_base_power", "component_power", "total_component_power", "total_asset_power",
    "total_power_used", "total_base_bram", "total_bram_used", "total_base_lutram",
    "total_lutram_used", "total_base_dsps", "total_dsps_used", "total_base_ffs",
    "ffs_used_by_component", "total_component_ffs", "total_asset_ffs", "total_ffs_used",
    "total_base_luts", "luts_used_by_component", "total_component_luts",
    "total_asset_luts", "total_luts_used", "component_write_risk", "component_read_risk",
    "Optimization"
]

# Extract assets from symbols
assets = []  # Define your assets here (dynamic discovery)

# Function to run ASP
def run_combined_asp(base_program, file_path):
    # Read and combine all optimization program contents
    optimization_content = ''
    for opt_program in optimization_programs:
        try:
            with open(opt_program, 'r') as opt_file:
                optimization_content += "\n" + opt_file.read()
        except FileNotFoundError:
            logging.info(f"Optimization program {opt_program} not found.")
    full_program = base_program + optimization_content
    # Initialize Clingo control object for the combined program
    ctl = clingo.Control(["--models=0"])  # Ensure Clingo looks for all possible models
    ctl.add("base", [], full_program)
    ctl.ground([("base", [])])
    # Log the running command
    logging.info(f"Running ASP for file {file_path}")
    # Solve the combined ASP program and collect statistics
    results = []
    with ctl.solve(yield_=True) as handle:
        for model in handle:
            # Filter the necessary parts of the output
            filtered_symbols = [
                symbol for symbol in model.symbols(shown=True)
                if any(str(symbol).startswith(prefix) for prefix in attributes)
            ]
            print(filtered_symbols)
            # Using model.number for answer number and model.cost for optimized value
            optimized_risk = sum(model.cost)  # Assuming the sum of cost elements represents the risk metric
            result = f"Answer #{model.number}\nOptimization({optimized_risk})\n" + " ".join(map(str, filtered_symbols))
            results.append((model.number, filtered_symbols))
    # Retrieve elapsed time from clingo statistics
    elapsed_time = ctl.statistics['summary']['times']['total']
    logging.info(f"Time taken: {elapsed_time:.6f} seconds")
    return results, elapsed_time

# Function to parse the base program
def parse_program(file_content):
    base_program_lines = [line for line in file_content.strip().split("\n")]
    base_program = "\n".join(base_program_lines)
    return base_program

# Function to extract assets from symbols
def extract_assets(symbols):
    for symbol in symbols:
        symbol_str = str(symbol)
        if "register_risk_fact" in symbol_str:
            components = symbol_str.strip("register_risk_fact()").split(",")
            asset = components[0]
            if asset not in assets:
                assets.append(asset)

# Function to write results to an Excel file
def write_to_excel(results, filename="asp_results.xlsx"):
    wb = Workbook()
    ws = wb.active

    # Set the header
    header = ["Answer #", "Optimization"] + attributes + [f"register_risk_read_{asset}" for asset in assets] + [f"register_risk_write_{asset}" for asset in assets]
    ws.append(header)

    # Write data rows
    for answer_num, symbols in results:
        row = [answer_num]

        # Extract optimization value
        optimization_value = [
            int(re.search(r'Optimization\((\d+)\)', symbol).group(1))
            for symbol in symbols if str(symbol).startswith("Optimization")
        ]
        if optimization_value:
            row.append(optimization_value[0])
        else:
            row.append("")

        # Initialize attribute values with empty strings
        attribute_values = {attr: "" for attr in attributes + [f"register_risk_read_{asset}" for asset in assets] + [f"register_risk_write_{asset}" for asset in assets]}

        # Fill in the extracted symbol values
        for symbol in symbols:
            symbol_str = str(symbol)
            for attr in attributes:
                if attr in symbol_str:
                    # Extract and store the value
                    attr_value = symbol_str.split('(')[1].split(')')[0]
                    attribute_values[attr] = attr_value
            if "register_risk_fact" in symbol_str:
                components = symbol_str.strip("register_risk_fact()").split(",")
                asset = components[0]
                operation = components[1]
                value = components[2]
                if operation == "read":
                    attribute_values[f"register_risk_read_{asset}"] = value
                elif operation == "write":
                    attribute_values[f"register_risk_write_{asset}"] = value

        row.extend([attribute_values[attr] for attr in attributes + [f"register_risk_read_{asset}" for asset in assets] + [f"register_risk_write_{asset}" for asset in assets]])
        ws.append(row)

    # Save the workbook
    wb.save(filename)

# Main script
def main():
    # Set up logging within the main function to ensure a new log file each run
    log_filename = setup_logging()
    # Get all test case files with the pattern testCase*_inst.lp
    test_files = glob.glob("testCases/testCase3_inst.lp")
    # Process each test case file
    all_results = []
    for file_path in test_files:
        logging.info(f"\nProcessing file: {file_path}")
        # Read the content of the file
        with open(file_path, 'r') as file:
            file_content = file.read()
        # Parse the base program
        base_program = parse_program(file_content)
        results, elapsed_time = run_combined_asp(base_program, file_path)
        all_results.extend(results)
        # Extract assets dynamically from results
        #print(results[0])
        for answer_num, symbols in results:
            extract_assets(symbols)
        for answer_num, result in results:
            logging.info(f"Answer #{answer_num}\n{result}")
        # Add a separator line
        logging.info("-" * 80)
    # Write results to an Excel file
    write_to_excel(all_results)
    # Close all logging file handlers
    for handler in logging.getLogger().handlers:
        handler.close()

if __name__ == "__main__":
    main()