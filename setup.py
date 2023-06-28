import os

import nltk

from modules.rAIversing.pathing import *


def setup_test_binaries_p2im():
    # clone repository and pull latest changes
    if not os.path.exists(f"{TESTING_ROOT}/p2im-real_firmware"):
        os.system(f"git clone https://github.com/RiS3-Lab/p2im-real_firmware.git {TESTING_ROOT}/p2im-real_firmware")
    else:
        os.system(f"cd {TESTING_ROOT}/p2im-real_firmware && git pull")

    # copy usable binaries from p2im-real_firmware/binary to testing/samples/binaries/p2im
    if not os.path.exists(f"{BINARIES_ROOT}/p2im"):
        os.makedirs(f"{BINARIES_ROOT}/p2im")
        os.makedirs(f"{BINARIES_ROOT}/p2im/stripped")
        os.makedirs(f"{BINARIES_ROOT}/p2im/original")
        os.makedirs(f"{BINARIES_ROOT}/p2im/no_propagation")
        os.system(f"cp {TESTING_ROOT}/p2im-real_firmware/binary/* {BINARIES_ROOT}/p2im/stripped")
        os.system(f"cp {TESTING_ROOT}/p2im-real_firmware/binary/* {BINARIES_ROOT}/p2im/original")
        os.system(f"cp {TESTING_ROOT}/p2im-real_firmware/binary/* {BINARIES_ROOT}/p2im/no_propagation")

        # strip binaries
        for binary in os.listdir(f"{BINARIES_ROOT}/p2im/stripped"):
            binary_path = f"{BINARIES_ROOT}/p2im/stripped/{binary}"
            os.system(f"arm-none-eabi-strip --strip-all {binary_path}")

        for binary in os.listdir(f"{BINARIES_ROOT}/p2im/no_propagation"):
            binary_path = f"{BINARIES_ROOT}/p2im/no_propagation/{binary}"
            os.system(f"arm-none-eabi-strip --strip-all {binary_path}")
            # rename to binary_no_propagation
            os.system(f"mv {binary_path} {binary_path}_no_propagation")

        for binary in os.listdir(f"{BINARIES_ROOT}/p2im/original"):
            binary_path = f"{BINARIES_ROOT}/p2im/original/{binary}"
            # rename to binary_original
            os.system(f"mv {binary_path} {binary_path}_original")


def setup_xfl():
    if not os.path.exists(f"{MODULES_ROOT}/xfl"):
        os.system(f"git clone https://github.com/kenohassler/xfl.git {MODULES_ROOT}/xfl")
    else:
        os.system(f"cd {MODULES_ROOT}/xfl && git pull")

def setup_eval_repo():
    if not os.path.exists(f"{EVALUATION_ROOT}"):
        os.system(f"git clone https://github.com/MrMatch246/rAIversingEvaluation.git {EVALUATION_ROOT}")
    else:
        os.system(f"cd {EVALUATION_ROOT} && git pull")


def main():
    nltk.download('wordnet')
    nltk.download('words')
    nltk.download('stopwords')
    setup_xfl()
    setup_test_binaries_p2im()
    setup_eval_repo()


if __name__ == "__main__":
    main()
