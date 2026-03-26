import subprocess
import os

# testCase5_inst.lp is also good
optimization_programs = [
    "Clingo/opt_redundancy_enc.lp",
    #"Clingo/test_redundancy.lp",
    "testCases/testCase9_inst.lp",
    #"Clingo/opt_security_enc.lp",
    "Clingo/security_features_inst.lp",
    #"Clingo/opt_power_enc.lp",
    "Clingo/opt_resource_enc.lp",
    "Clingo/tgt_system_inst1.lp",
    "Clingo/init_enc.lp"
]


def main():
    # Find the clingo binary in the conda env
    clingo_bin = r"C:\Users\butkaa\Anaconda3\envs\clingo\Library\bin\clingo.exe"

    cmd = [clingo_bin] + optimization_programs

    result = subprocess.run(cmd, capture_output=True, text=True)

    print(result.stdout)
    if result.stderr:
        print("ERRORS:", result.stderr)


if __name__ == "__main__":
    main()